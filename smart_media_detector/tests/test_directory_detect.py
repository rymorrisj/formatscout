"""Tests for backend.service.utils.smart_media_detector.directory_detect.

Priority: regression-pin the PS3/XEX consolidation fix (see the module's own
resolve_ps3_target()/resolve_xex_target() docstrings and dev_docs/SCOPE.md's
PX-2 architecture-refactor entries). Before that fix, the disc-format branch
in _detect_from_directory() trusted PS3_DISC.SFB alone and never checked for
a resolvable EBOOT.BIN, and a raw extracted XEX folder produced
confidence=0.0 instead of era=xbox360.
"""

from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


# ---------------------------------------------------------------------------
# is_disc_format_folder()
# ---------------------------------------------------------------------------

class TestIsDiscFormatFolder:
    def test_true_when_sfb_file_present(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import is_disc_format_folder
        folder = fx.build_ps3_disc_folder(tmp_path)
        assert is_disc_format_folder(folder) is True

    def test_false_when_absent(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import is_disc_format_folder
        folder = fx.build_ps3_installed_folder(tmp_path)
        assert is_disc_format_folder(folder) is False

    def test_false_when_marker_is_a_directory_not_a_file(self, tmp_path: Path):
        """PS3_DISC.SFB as a directory, not a file, must not count — the
        check is explicitly is_file()."""
        from backend.service.utils.smart_media_detector.directory_detect import is_disc_format_folder
        folder = tmp_path / "weird"
        (folder / "PS3_DISC.SFB").mkdir(parents=True)
        assert is_disc_format_folder(folder) is False


# ---------------------------------------------------------------------------
# find_eboot()
# ---------------------------------------------------------------------------

class TestFindEboot:
    def test_installed_layout(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import find_eboot
        folder = fx.build_ps3_installed_folder(tmp_path)
        assert find_eboot(folder) == folder / "USRDIR" / "EBOOT.BIN"

    def test_disc_layout(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import find_eboot
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=True)
        assert find_eboot(folder) == folder / "PS3_GAME" / "USRDIR" / "EBOOT.BIN"

    def test_no_eboot_anywhere(self, tmp_path: Path):
        """The exact bug-reproduction shape: PS3_DISC.SFB present, no
        EBOOT.BIN under either known layout."""
        from backend.service.utils.smart_media_detector.directory_detect import find_eboot
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=False)
        assert find_eboot(folder) is None


# ---------------------------------------------------------------------------
# find_default_xex()
# ---------------------------------------------------------------------------

class TestFindDefaultXex:
    def test_exact_default_xex_case_insensitive(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import find_default_xex
        folder = fx.build_xex_folder(tmp_path, xex_names=["Default.XEX"])
        assert find_default_xex(folder) == folder / "Default.XEX"

    def test_tie_break_chooses_alphabetically_first_and_logs_warning(self, tmp_path: Path, monkeypatch):
        """No default.xex, three other .xex files present: must deterministically
        pick the alphabetically-first by filename (not filesystem iteration
        order) and log a warning, since this is a tie-break, not a confirmed match.
        """
        from backend.service.utils.smart_media_detector import directory_detect

        folder = fx.build_xex_folder(tmp_path, xex_names=["Cherry.xex", "apple.xex", "Banana.xex"])
        warnings_logged = []
        monkeypatch.setattr(directory_detect.log, "warning", lambda *a, **kw: warnings_logged.append((a, kw)))

        result = directory_detect.find_default_xex(folder)

        assert result is not None
        assert result.name == "apple.xex"
        assert len(warnings_logged) == 1

    def test_no_xex_files_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import find_default_xex
        folder = fx.build_non_ps3_folder(tmp_path)
        assert find_default_xex(folder) is None

    def test_nonexistent_folder_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import find_default_xex
        assert find_default_xex(tmp_path / "ghost_folder") is None


# ---------------------------------------------------------------------------
# resolve_ps3_target() — the single resolver for both PS3 folder shapes
# ---------------------------------------------------------------------------

class TestResolvePs3Target:
    def test_disc_shape_with_eboot(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_ps3_target
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=True)

        target = resolve_ps3_target(folder)

        assert target is not None
        assert target.kind == "disc_folder"
        assert target.detect_path == folder / "PS3_GAME" / "USRDIR" / "EBOOT.BIN"
        assert target.launch_path == folder
        assert target.era == "ps3"
        assert target.requires_install is False

    def test_installed_shape(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_ps3_target
        folder = fx.build_ps3_installed_folder(tmp_path)

        target = resolve_ps3_target(folder)

        assert target is not None
        assert target.kind == "installed_dir"
        assert target.detect_path == folder / "USRDIR" / "EBOOT.BIN"
        assert target.launch_path == folder
        assert target.era == "ps3"

    def test_disc_marker_without_eboot_returns_none(self, tmp_path: Path):
        """The original bug's exact case, at the resolver level: PS3_DISC.SFB
        present but no findable EBOOT.BIN is not a valid target — must return
        None rather than trusting the SFB marker alone.
        """
        from backend.service.utils.smart_media_detector.directory_detect import resolve_ps3_target
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=False)
        assert resolve_ps3_target(folder) is None

    def test_neither_marker_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_ps3_target
        folder = fx.build_non_ps3_folder(tmp_path)
        assert resolve_ps3_target(folder) is None

    def test_not_a_directory_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_ps3_target
        a_file = tmp_path / "not_a_dir.txt"
        a_file.write_bytes(b"x")
        assert resolve_ps3_target(a_file) is None


# ---------------------------------------------------------------------------
# resolve_xex_target() — the single resolver for the XEX folder shape
# ---------------------------------------------------------------------------

class TestResolveXexTarget:
    def test_default_xex_present(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_xex_target
        folder = fx.build_xex_folder(tmp_path)

        target = resolve_xex_target(folder)

        assert target is not None
        assert target.kind == "xex_folder"
        assert target.detect_path == folder / "default.xex"
        assert target.launch_path == folder / "default.xex"
        assert target.era == "xbox360"
        assert target.requires_install is False

    def test_no_xex_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_xex_target
        folder = fx.build_non_ps3_folder(tmp_path)
        assert resolve_xex_target(folder) is None

    def test_not_a_directory_returns_none(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import resolve_xex_target
        a_file = tmp_path / "not_a_dir.txt"
        a_file.write_bytes(b"x")
        assert resolve_xex_target(a_file) is None


# ---------------------------------------------------------------------------
# _detect_from_directory() delegates to resolve_ps3_target()/resolve_xex_target()
# rather than re-deriving the SFB/EBOOT/XEX checks inline (the consolidation
# fix itself, not just its outcome) — pinned via monkeypatched resolvers so a
# future regression back to inline duplicated logic would break this test
# even if the inline logic happened to produce the same result.
# ---------------------------------------------------------------------------

class TestDetectFromDirectoryDelegatesToResolvers:
    def test_delegates_to_resolve_ps3_target(self, tmp_path: Path, monkeypatch):
        from backend.service.utils.smart_media_detector import directory_detect
        from backend.service.utils.smart_media_detector.result import MediaTarget

        folder = tmp_path / "anything"
        folder.mkdir()
        sentinel = MediaTarget(
            kind="installed_dir", detect_path=folder / "EBOOT.BIN", launch_path=folder,
            era="ps3", requires_install=False,
        )
        called = {}

        def _fake_resolve(f):
            called["folder"] = f
            return sentinel

        monkeypatch.setattr(directory_detect, "resolve_ps3_target", _fake_resolve)

        result = directory_detect._detect_from_directory(folder)

        assert called["folder"] == folder
        assert result.era == "ps3"
        assert result.confidence == 0.85

    def test_delegates_to_resolve_xex_target(self, tmp_path: Path, monkeypatch):
        from backend.service.utils.smart_media_detector import directory_detect
        from backend.service.utils.smart_media_detector.result import MediaTarget

        folder = tmp_path / "anything"
        folder.mkdir()
        sentinel = MediaTarget(
            kind="xex_folder", detect_path=folder / "default.xex", launch_path=folder / "default.xex",
            era="xbox360", requires_install=False,
        )
        monkeypatch.setattr(directory_detect, "resolve_ps3_target", lambda f: None)
        called = {}

        def _fake_resolve_xex(f):
            called["folder"] = f
            return sentinel

        monkeypatch.setattr(directory_detect, "resolve_xex_target", _fake_resolve_xex)

        result = directory_detect._detect_from_directory(folder)

        assert called["folder"] == folder
        assert result.era == "xbox360"


# ---------------------------------------------------------------------------
# _detect_from_directory() — the PS3/XEX regression pin, unpatched end-to-end.
# Case 3 (SFB, no EBOOT) is the exact original bug reproduction.
# ---------------------------------------------------------------------------

class TestDetectFromDirectoryPs3XexRegression:
    def test_disc_sfb_with_eboot_classifies_as_ps3(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_directory
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=True)

        result = _detect_from_directory(folder)

        assert result.era == "ps3"
        assert result.confidence == 0.9
        assert "PS3_DISC.SFB" in result.reason

    def test_installed_dir_classifies_as_ps3(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_directory
        folder = fx.build_ps3_installed_folder(tmp_path)

        result = _detect_from_directory(folder)

        assert result.era == "ps3"
        assert result.confidence == 0.85
        assert "EBOOT.BIN" in result.reason

    def test_disc_sfb_without_eboot_does_not_classify_as_ps3(self, tmp_path: Path):
        """THE regression test for the original bug: a folder with
        PS3_DISC.SFB but no findable EBOOT.BIN anywhere must not be
        confidently classified as era=ps3. Before the fix, this branch
        trusted the SFB marker alone and returned era=ps3, confidence=0.9
        even with no bootable file — an unbootable folder would have reached
        RPCS3 before failing there instead of failing here.
        """
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_directory
        folder = fx.build_ps3_disc_folder(tmp_path, with_eboot=False)

        result = _detect_from_directory(folder)

        assert result.era != "ps3"
        assert result.era is None
        assert result.confidence == 0.0

    def test_neither_marker_present_returns_no_signal(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_directory
        folder = fx.build_non_ps3_folder(tmp_path)

        result = _detect_from_directory(folder)

        assert result.era is None


# ---------------------------------------------------------------------------
# Second half of the original bug: a raw extracted XEX folder must resolve
# to era=xbox360, not confidence=0.0 — through both detect_directory() and
# the full public detect() entry point.
# ---------------------------------------------------------------------------

class TestXexFolderEndToEnd:
    def test_detect_directory_returns_xbox360_for_raw_xex_folder(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import detect_directory
        folder = fx.build_xex_folder(tmp_path)

        result = detect_directory(folder)

        assert result.era == "xbox360"
        assert result.confidence == 0.85

    def test_detect_returns_xbox360_for_raw_xex_folder(self, tmp_path: Path, monkeypatch):
        """Through the full public detect() entry point (detector.py), not
        just detect_directory() directly. detector._INDEX_PATH is pointed at
        a nonexistent path so detect()'s Tier-1 hash lookup fails closed
        (FileNotFoundError, caught and logged) and falls through to
        detect_directory() without loading the real ~88MB hash_index.json.
        """
        from backend.service.utils.smart_media_detector import detector

        fx.patch_detector_index(monkeypatch, tmp_path / "unused_index.json")
        xex_root = tmp_path / "xex_root"
        xex_root.mkdir()
        folder = fx.build_xex_folder(xex_root)

        result = detector.detect(folder)

        assert result.era == "xbox360"
        assert result.confidence == 0.85


# ---------------------------------------------------------------------------
# _detect_from_pe() — confirmed untouched by the consolidation fix: still has
# its own Subsystem gate, still a distinct function from exe_detect.detect_exe()
# even though both now compute the same PE-header classification independently.
# ---------------------------------------------------------------------------

class TestDetectFromPe:
    def _call(self, exe_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_pe
        return _detect_from_pe(exe_path)

    def test_is_a_distinct_function_from_exe_detect_detect_exe(self):
        from backend.service.utils.smart_media_detector.directory_detect import _detect_from_pe
        from backend.service.utils.smart_media_detector.exe_detect import detect_exe
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
        """Subsystem values other than 2 (GUI) or 3 (console) are gated out —
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
        duplicated code paths, not delegation — confirm they still agree
        rather than having silently diverged.
        """
        from backend.service.utils.smart_media_detector.exe_detect import detect_exe

        pe_path = tmp_path / "GAME.EXE"
        pe_path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))

        pe_result = self._call(pe_path)
        exe_result = detect_exe(pe_path)

        assert pe_result.era == exe_result.era == "winxp"
        assert pe_result.confidence == exe_result.confidence


# ---------------------------------------------------------------------------
# _parse_autorun_exe() — read cap fix from the perf pass (commit 98ce932):
# _POINTER_FILE_READ_CAP_BYTES (imported from iso_detect.py) must actually
# cap the read, not just exist as an unused constant.
# ---------------------------------------------------------------------------

class TestParseAutorunExe:
    def _call(self, autorun_path: Path):
        from backend.service.utils.smart_media_detector.directory_detect import _parse_autorun_exe
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
        placed after that boundary must not be found — proof the file is
        genuinely truncated/capped on read, not fully read regardless of size.
        """
        from backend.service.utils.smart_media_detector.directory_detect import (
            _POINTER_FILE_READ_CAP_BYTES,
        )

        padding = b";" + b"x" * (_POINTER_FILE_READ_CAP_BYTES + 100) + b"\n"
        content = padding + b"OPEN=SETUP.EXE\n"
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) is None

    def test_directive_within_read_cap_is_still_found(self, tmp_path: Path):
        """Sanity control for the cap test above: a directive comfortably
        inside the cap, on an otherwise large file, is still found — the cap
        truncates the read, it doesn't break normal parsing.
        """
        from backend.service.utils.smart_media_detector.directory_detect import (
            _POINTER_FILE_READ_CAP_BYTES,
        )

        padding = b";" + b"x" * 1000 + b"\n"
        trailer = b";" * _POINTER_FILE_READ_CAP_BYTES
        content = padding + b"OPEN=SETUP.EXE\n" + trailer
        autorun = tmp_path / "AUTORUN.INF"
        autorun.write_bytes(content)

        assert self._call(autorun) == "SETUP.EXE"
