"""Tests for formatscout.directory_detect."""

from pathlib import Path

from formatscout.tests import smart_media_fixtures as fx


# ---------------------------------------------------------------------------
# _detect_from_pe(), confirmed untouched by the consolidation fix: still has
# its own Subsystem gate, still a distinct function from exe_detect.detect_exe()
# even though both now compute the same PE-header classification independently.
# ---------------------------------------------------------------------------

class TestDetectFromPe:
    def _call(self, exe_path: Path):
        from formatscout.directory_detect import _detect_from_pe
        return _detect_from_pe(exe_path)

    def test_is_a_distinct_function_from_exe_detect_detect_exe(self):
        from formatscout.directory_detect import _detect_from_pe
        from formatscout.exe_detect import detect_exe
        assert _detect_from_pe is not detect_exe

    def test_win98_era_from_major_os_version_4(self, tmp_path: Path):
        exe_path = tmp_path / "SETUP.EXE"
        exe_path.write_bytes(fx.build_pe_header(major_os_version=4, subsystem=2))
        result = self._call(exe_path)
        assert result.era == "win98"

    def test_winxp_era_from_major_os_version_5(self, tmp_path: Path):
        exe_path = tmp_path / "SETUP.EXE"
        exe_path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        result = self._call(exe_path)
        assert result.era == "winxp"

    def test_subsystem_gate_rejects_non_gui_console_subsystems(self, tmp_path: Path):
        """Subsystem values other than 2 (GUI) or 3 (console) are gated out,
        confirms the Subsystem gate is still present and unmodified."""
        exe_path = tmp_path / "SETUP.EXE"
        exe_path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=1))
        result = self._call(exe_path)
        assert result.era is None

    def test_mz_only_header_is_dos(self, tmp_path: Path):
        exe_path = tmp_path / "SETUP.EXE"
        exe_path.write_bytes(fx.build_pe_header(pe_offset=None, total_len=0x20))
        result = self._call(exe_path)
        assert result.era == "dos"

    def test_no_mz_header_returns_null(self, tmp_path: Path):
        exe_path = tmp_path / "NOTANEXE.EXE"
        exe_path.write_bytes(b"not an executable at all")
        result = self._call(exe_path)
        assert result.era is None

    def test_agrees_with_exe_detect_detect_exe_for_the_same_header(self, tmp_path: Path):
        """directory_detect._detect_from_pe() and exe_detect.detect_exe() now
        compute the same PE-subsystem/version classification via independent,
        duplicated code paths, not delegation, confirm they still agree
        rather than having silently diverged.
        """
        from formatscout.exe_detect import detect_exe

        pe_path = tmp_path / "GAME.EXE"
        pe_path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))

        pe_result = self._call(pe_path)
        exe_result = detect_exe(pe_path)

        assert pe_result.era == exe_result.era == "winxp"
        assert pe_result.confidence == exe_result.confidence


# ---------------------------------------------------------------------------
# _parse_autorun_exe(), read cap fix from the perf pass (commit 98ce932):
# _POINTER_FILE_READ_CAP_BYTES (imported from iso_detect.py) must actually
# cap the read, not just exist as an unused constant.
# ---------------------------------------------------------------------------

class TestParseAutorunExe:
    def _call(self, autorun_path: Path):
        from formatscout.directory_detect import _parse_autorun_exe
        return _parse_autorun_exe(autorun_path)

    def test_parses_open_directive(self, tmp_path: Path):
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_text("[autorun]\nOPEN=SETUP.EXE\n")
        assert self._call(autorun) == "SETUP.EXE"

    def test_parses_run_directive(self, tmp_path: Path):
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_text("[autorun]\nRUN=INSTALL.EXE\n")
        assert self._call(autorun) == "INSTALL.EXE"

    def test_strips_quotes(self, tmp_path: Path):
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_text('[autorun]\nOPEN="SETUP.EXE"\n')
        assert self._call(autorun) == "SETUP.EXE"

    def test_non_exe_value_is_ignored(self, tmp_path: Path):
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_text("[autorun]\nOPEN=readme.txt\n")
        assert self._call(autorun) is None

    def test_nonexistent_file_returns_none(self, tmp_path: Path):
        assert self._call(tmp_path / "ghost.inf") is None

    def test_directive_beyond_read_cap_is_never_seen(self, tmp_path: Path):
        """Regression for the perf-pass read cap: _POINTER_FILE_READ_CAP_BYTES
        must actually cap the read at that many bytes. A real OPEN= directive
        placed after that boundary must not be found, proof the file is
        genuinely truncated/capped on read, not fully read regardless of size.
        """
        from formatscout.directory_detect import (
            _POINTER_FILE_READ_CAP_BYTES,
        )

        padding = b";" + b"x" * (_POINTER_FILE_READ_CAP_BYTES + 100) + b"\n"
        content = padding + b"OPEN=SETUP.EXE\n"
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) is None

    def test_directive_within_read_cap_is_still_found(self, tmp_path: Path):
        """Sanity control for the cap test above: a directive comfortably
        inside the cap, on an otherwise large file, is still found, the cap
        truncates the read, it doesn't break normal parsing.
        """
        from formatscout.directory_detect import (
            _POINTER_FILE_READ_CAP_BYTES,
        )

        padding = b";" + b"x" * 1000 + b"\n"
        trailer = b";" * _POINTER_FILE_READ_CAP_BYTES
        content = padding + b"OPEN=SETUP.EXE\n" + trailer
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) == "SETUP.EXE"
