"""Tests for formatscout.directory_detect."""

from pathlib import Path

from formatscout.tests import smart_media_fixtures as fx


# ---------------------------------------------------------------------------
# _detect_from_pe(): still a distinct function from exe_detect.detect_exe(),
# still applies its own AUTORUN.INF-specific reason text and Subsystem gate,
# but the consolidation fix moved the actual PE-header classification (MZ/PE
# checks, offset math, Subsystem gate, MajorOperatingSystemVersion split)
# into a single shared exe_detect._classify_pe_header() helper both functions
# call, no longer two independently-duplicated implementations.
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
        share the same underlying exe_detect._classify_pe_header() call, so
        era/confidence agreement is guaranteed by construction rather than
        needing to be independently maintained; this pins that it holds.
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
# POINTER_FILE_READ_CAP_BYTES (now in formatscout.constants, previously
# imported from iso_detect.py) must actually cap the read, not just exist as
# an unused constant.
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
        """Regression for the perf-pass read cap: POINTER_FILE_READ_CAP_BYTES
        must actually cap the read at that many bytes. A real OPEN= directive
        placed after that boundary must not be found, proof the file is
        genuinely truncated/capped on read, not fully read regardless of size.
        """
        from formatscout.constants import POINTER_FILE_READ_CAP_BYTES

        padding = b";" + b"x" * (POINTER_FILE_READ_CAP_BYTES + 100) + b"\n"
        content = padding + b"OPEN=SETUP.EXE\n"
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) is None

    def test_directive_within_read_cap_is_still_found(self, tmp_path: Path):
        """Sanity control for the cap test above: a directive comfortably
        inside the cap, on an otherwise large file, is still found, the cap
        truncates the read, it doesn't break normal parsing.
        """
        from formatscout.constants import POINTER_FILE_READ_CAP_BYTES

        padding = b";" + b"x" * 1000 + b"\n"
        trailer = b";" * POINTER_FILE_READ_CAP_BYTES
        content = padding + b"OPEN=SETUP.EXE\n" + trailer
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) == "SETUP.EXE"


# ---------------------------------------------------------------------------
# detect_directory(): dispatch between the AUTORUN.INF tier and the
# marker-file/depth-2 heuristic tier. Previously untested per README's Known
# Gaps section.
# ---------------------------------------------------------------------------

class TestDetectDirectory:
    def _call(self, root: Path):
        from formatscout.directory_detect import detect_directory
        return detect_directory(root)

    def test_autorun_inf_reaches_pe_detection_end_to_end(self, tmp_path: Path):
        """detect_directory() -> _detect_from_autorun() -> _parse_autorun_exe()
        -> _detect_from_pe() chained together with real files throughout,
        nothing mocked.
        """
        exe_path = tmp_path / "SETUP.EXE"
        exe_path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_text("[autorun]\nOPEN=SETUP.EXE\n")

        result = self._call(tmp_path)

        assert result.era == "winxp"
        assert result.confidence == 0.75

    def test_autorun_present_but_no_signal_falls_through_to_directory_heuristics(self, tmp_path: Path):
        """AUTORUN.INF exists but its OPEN= target is not a recognisable PE
        (not even a .exe extension), so _detect_from_autorun() returns a null
        result. detect_directory() must fall through to
        _detect_from_directory() rather than stopping there.
        """
        (tmp_path / "AUTORUN.INF").write_text("[autorun]\nOPEN=readme.txt\n")
        (tmp_path / "PS3_DISC.SFB").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era == "ps3"

    def test_no_signal_anywhere_returns_null(self, tmp_path: Path):
        # A lone .txt file is not a no-signal fixture here: .txt is one of
        # the extensions _detect_from_directory()'s "DOS-only root
        # extensions" branch treats as DOS-era on its own. .png isn't in
        # that set and matches nothing else either.
        (tmp_path / "image.png").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era is None
        assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# _detect_from_directory(): root marker-file heuristics and the depth-2
# fallback scan, reached only after detect_directory() finds no AUTORUN.INF
# signal. Previously untested per README's Known Gaps section.
# ---------------------------------------------------------------------------

class TestDetectFromDirectory:
    def _call(self, root: Path):
        from formatscout.directory_detect import _detect_from_directory
        return _detect_from_directory(root)

    def test_ps3_disc_sfb_marker(self, tmp_path: Path):
        """Newest marker-file branch added to this function, and the least
        covered before this test existed.
        """
        (tmp_path / "PS3_DISC.SFB").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era == "ps3"
        assert result.confidence == 0.9
        assert "PS3_DISC.SFB" in result.reason

    def test_ps3_marker_wins_even_alongside_other_root_files(self, tmp_path: Path):
        (tmp_path / "PS3_DISC.SFB").write_bytes(b"\x00")
        (tmp_path / "readme.txt").write_text("unrelated")

        result = self._call(tmp_path)

        assert result.era == "ps3"

    def test_xpsp_marker_is_winxp(self, tmp_path: Path):
        (tmp_path / "XPSP").mkdir()

        result = self._call(tmp_path)

        assert result.era == "winxp"
        assert result.confidence == 0.6

    def test_install_bat_marker_is_dos(self, tmp_path: Path):
        (tmp_path / "INSTALL.BAT").write_bytes(b"@echo off\n")

        result = self._call(tmp_path)

        assert result.era == "dos"
        assert result.confidence == 0.55

    def test_depth2_dos_tool_fallback(self, tmp_path: Path):
        """DEICE.EXE one level below root, not at the root itself, only
        found by the depth-2 scan, not any root-level marker check above it.
        """
        subdir = tmp_path / "DATA"
        subdir.mkdir()
        (subdir / "DEICE.EXE").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era == "dos"
        assert result.confidence == 0.6
        assert "DEICE.EXE" in result.reason

    def test_depth2_wad_file_fallback(self, tmp_path: Path):
        subdir = tmp_path / "DATA"
        subdir.mkdir()
        (subdir / "DOOM.WAD").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era == "dos"
        assert "WAD" in result.reason

    def test_root_marker_checked_before_depth2_scan(self, tmp_path: Path):
        """A root-level marker (PS3_DISC.SFB) must win even when a depth-2
        DOS-tool file is also present, confirming the marker checks run
        first and short-circuit before the depth-2 scan is ever reached.
        """
        (tmp_path / "PS3_DISC.SFB").write_bytes(b"\x00")
        subdir = tmp_path / "DATA"
        subdir.mkdir()
        (subdir / "DEICE.EXE").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era == "ps3"

    def test_no_signal_returns_null(self, tmp_path: Path):
        # See TestDetectDirectory.test_no_signal_anywhere_returns_null: a
        # lone .txt file is not no-signal here, it hits the DOS-only root
        # extensions branch. .png matches nothing.
        (tmp_path / "image.png").write_bytes(b"\x00")

        result = self._call(tmp_path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "no signal found"

    def test_unreadable_directory_returns_null_with_reason(self, tmp_path: Path, monkeypatch):
        def _boom(self):
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "iterdir", _boom)

        result = self._call(tmp_path)

        assert result.era is None
        assert result.reason == "cannot list directory"
