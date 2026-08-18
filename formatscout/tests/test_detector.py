"""Tests for formatscout.detector, the package's public detect() entry point.

Three things are covered here, none of which had any coverage before:

  1. The suffix dispatch table in _detect_file(), every branch of it. Branches
     that resolve inline (extension-only eras, .gdi/.cdi, .img) are driven with
     real files; branches that delegate to another module (.iso, .cue, .chd,
     .exe, and the directory path) are driven with a monkeypatched delegate,
     since each of those has its own dedicated test file already and what is
     unproven here is the routing, not the delegate's own logic.
  2. detect()'s fail-soft contract: it must never raise, any unexpected error
     becomes a zero-confidence ScanResult carrying the message as a warning.
  3. _compute_requires_install(), including the directory case that depends on
     utils.blocklist.

Every test points detector._INDEX_PATH at a nonexistent tmp_path file via
fx.patch_detector_index(), so the real ~88MB hash_index.json is never read.
hash_lookup.load_index() raises FileNotFoundError for a missing path, which
_detect() already catches and falls through on, which is exactly the Tier-1
miss these tests want. The two tests that do want a Tier-1 hit build a
synthetic index instead.
"""

import os
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx


def _detect(path: Path, dir_cache=None):
    from formatscout.detector import detect
    return detect(path, dir_cache)


def _no_index(monkeypatch, tmp_path: Path) -> None:
    fx.patch_detector_index(monkeypatch, tmp_path / "no_such_index.json")


def _scan(era=None, confidence=0.0, reason="sentinel"):
    from formatscout.result import ScanResult
    return ScanResult(title=None, platform=None, era=era, confidence=confidence, reason=reason)


# ---------------------------------------------------------------------------
# Path preconditions, before any dispatch happens
# ---------------------------------------------------------------------------

class TestPathPreconditions:
    def test_nonexistent_path(self, tmp_path: Path, monkeypatch):
        _no_index(monkeypatch, tmp_path)

        result = _detect(tmp_path / "ghost.iso")

        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "path does not exist"

    def test_path_that_is_neither_a_file_nor_a_directory(self, tmp_path: Path, monkeypatch):
        """A device node, socket or FIFO reaches _detect() as an existing path
        that is neither. Reproduced by overriding is_file()/is_dir() for this
        one path only, rather than with a real FIFO, so the test runs the same
        way on Windows.
        """
        _no_index(monkeypatch, tmp_path)
        target = tmp_path / "weird"
        target.write_bytes(b"")

        real_is_file, real_is_dir = Path.is_file, Path.is_dir
        monkeypatch.setattr(Path, "is_file", lambda self: False if self == target else real_is_file(self))
        monkeypatch.setattr(Path, "is_dir", lambda self: False if self == target else real_is_dir(self))

        result = _detect(target)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "path is neither a file nor a directory"


# ---------------------------------------------------------------------------
# _detect_file(), extension-only branches (Tier 5)
# ---------------------------------------------------------------------------

class TestExtensionOnlyDispatch:
    @pytest.mark.parametrize(
        "filename,expected_era",
        [
            ("game.xiso", "xbox"),
            ("game.xex", "xbox360"),
            ("game.z64", "n64"),
            ("game.n64", "n64"),
            ("game.v64", "n64"),
            ("game.sfc", "snes"),
            ("game.smc", "snes"),
            ("game.fig", "snes"),
            ("game.swc", "snes"),
            ("game.nes", "nes"),
            ("game.pkg", "ps3"),
        ],
    )
    def test_extension_resolves_era_at_confidence_0_7(
        self, tmp_path: Path, monkeypatch, filename: str, expected_era: str,
    ):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / filename
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era == expected_era
        assert result.confidence == 0.7
        assert result.requires_install is False

    @pytest.mark.parametrize("suffix", [".SFC", ".Nes", ".XISO"])
    def test_suffix_match_is_case_insensitive(self, tmp_path: Path, monkeypatch, suffix: str):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / f"game{suffix}"
        path.write_bytes(b"\x00" * 64)

        assert _detect(path).era is not None

    def test_nds_is_explicitly_unsupported(self, tmp_path: Path, monkeypatch):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "game.nds"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert "not supported" in result.reason
        assert result.warnings

    def test_unrecognised_suffix_returns_no_signal(self, tmp_path: Path, monkeypatch):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "notes.txt"
        path.write_bytes(b"hello")

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "no signal found"


# ---------------------------------------------------------------------------
# _detect_file(), branches that resolve inline against real file content
# ---------------------------------------------------------------------------

class TestGdiCdiDispatch:
    @pytest.mark.parametrize("suffix", [".gdi", ".cdi"])
    def test_magic_match_wins_at_0_9(self, tmp_path: Path, monkeypatch, suffix: str):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / f"game{suffix}"
        path.write_bytes(fx.DREAMCAST_IP_BIN_BLOB)

        result = _detect(path)

        assert result.era == "dreamcast"
        assert result.confidence == 0.9

    @pytest.mark.parametrize("suffix", [".gdi", ".cdi"])
    def test_no_magic_falls_back_to_extension_at_0_5_with_warning(
        self, tmp_path: Path, monkeypatch, suffix: str,
    ):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / f"game{suffix}"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era == "dreamcast"
        assert result.confidence == 0.5
        assert result.warnings


class TestImgDispatch:
    def test_small_img_is_dos_and_flags_requires_install(self, tmp_path: Path, monkeypatch):
        """Under 800 MB resolves era=dos, and _compute_requires_install()'s
        .img rule (under 2 MB) then fires on top of it, a floppy image.
        """
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "disk1.img"
        path.write_bytes(b"\x00" * 1024)

        result = _detect(path)

        assert result.era == "dos"
        assert result.confidence == 0.35
        assert result.warnings
        assert result.requires_install is True

    def test_img_over_2mb_is_still_dos_but_not_an_install(self, tmp_path: Path, monkeypatch):
        """Same era=dos branch, but past the 2 MB floppy cutoff, so this is
        treated as playable media rather than installer media.
        """
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "big.img"
        path.touch()
        os.truncate(path, 8 * 1024 * 1024)

        result = _detect(path)

        assert result.era == "dos"
        assert result.requires_install is False

    def test_img_at_or_over_800mb_returns_no_signal(self, tmp_path: Path, monkeypatch):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "huge.img"
        path.touch()
        os.truncate(path, 800 * 1024 * 1024)

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.requires_install is False


class TestBinDispatch:
    def test_bin_with_no_magic_no_pvd_and_no_cue_reaches_bin_validator(
        self, tmp_path: Path, monkeypatch,
    ):
        """Routing check for the .bin branch's third and last step. An
        all-zero .bin with no sibling cue is resolve_bin_cue()'s
        no-sibling-cue outcome, which only that function produces.
        """
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "game.bin"
        path.write_bytes(b"\x00" * 4096)

        result = _detect(path)

        assert result.confidence == 0.3
        assert "no sibling .cue sheet" in result.reason

    def test_bin_magic_match_short_circuits(self, tmp_path: Path, monkeypatch):
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "game.bin"
        path.write_bytes(fx.N64_BIG_ENDIAN_BLOB)

        result = _detect(path)

        assert result.era == "n64"
        assert result.confidence == 0.9


# ---------------------------------------------------------------------------
# _detect_file(), branches that delegate to another module
# ---------------------------------------------------------------------------

class TestDelegatingDispatch:
    @pytest.mark.parametrize(
        "filename,delegate",
        [
            ("game.iso", "detect_iso"),
            ("game.chd", "detect_chd"),
            ("game.exe", "detect_exe"),
        ],
    )
    def test_suffix_routes_to_its_delegate_and_returns_its_result(
        self, tmp_path: Path, monkeypatch, filename: str, delegate: str,
    ):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        sentinel = _scan(era="dreamcast", confidence=1.0)
        captured: dict = {}

        def _fake(path, *args):
            captured["path"] = path
            return sentinel

        monkeypatch.setattr(detector, delegate, _fake)
        path = tmp_path / filename
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result is sentinel
        assert captured["path"] == path

    def test_directory_routes_to_detect_directory(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        sentinel = _scan(era="winxp", confidence=0.6)
        captured: dict = {}

        def _fake(path):
            captured["path"] = path
            return sentinel

        monkeypatch.setattr(detector, "detect_directory", _fake)
        target = tmp_path / "game_dir"
        target.mkdir()

        result = _detect(target)

        assert result is sentinel
        assert captured["path"] == target

    def test_cue_receives_the_dir_cache_detect_was_given(self, tmp_path: Path, monkeypatch):
        """dir_cache is threaded detect() -> _detect_file() -> detect_cue().
        Nothing else in detector.py reads it, so passing it through intact is
        the whole contract.
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        captured: dict = {}

        def _fake_cue(path, dir_cache=None):
            captured["dir_cache"] = dir_cache
            return _scan(era="ps1", confidence=0.5)

        monkeypatch.setattr(detector, "detect_cue", _fake_cue)
        path = tmp_path / "game.cue"
        path.write_text("TRACK 01 MODE2/2352\n")
        dir_cache: dict = {tmp_path: []}

        _detect(path, dir_cache)

        assert captured["dir_cache"] is dir_cache

    def test_dir_cache_defaults_to_none(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        captured: dict = {}

        def _fake_cue(path, dir_cache=None):
            captured["dir_cache"] = dir_cache
            return _scan(era="ps1", confidence=0.5)

        monkeypatch.setattr(detector, "detect_cue", _fake_cue)
        path = tmp_path / "game.cue"
        path.write_text("TRACK 01 MODE2/2352\n")

        _detect(path)

        assert captured["dir_cache"] is None


# ---------------------------------------------------------------------------
# Tier 1 hash lookup, which precedes the whole suffix table
# ---------------------------------------------------------------------------

class TestHashTier:
    def test_hash_hit_short_circuits_the_suffix_dispatch_entirely(self, tmp_path: Path, monkeypatch):
        """The file is named .nes, which the suffix table would resolve to
        era=nes at 0.7. Its bytes are an indexed ps1 entry, so a Tier-1 hit
        must win and return before _detect_file() is ever reached.
        """
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_detector_index(monkeypatch, index_path)

        path = tmp_path / "game.nes"
        path.write_bytes(fx.VERIFIED_CONTENT)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.confidence == 1.0
        assert "sha1 match" in result.reason

    def test_missing_index_falls_through_to_signal_detection(self, tmp_path: Path, monkeypatch):
        """A missing hash_index.json raises FileNotFoundError out of
        load_index(); detect() must swallow it and keep going rather than
        surfacing it as a detection failure.
        """
        _no_index(monkeypatch, tmp_path)
        path = tmp_path / "game.nes"
        path.write_bytes(fx.VERIFIED_CONTENT)

        result = _detect(path)

        assert result.era == "nes"
        assert result.confidence == 0.7

    def test_requires_install_is_stamped_on_the_hash_tier_result_too(self, tmp_path: Path, monkeypatch):
        """The Tier-1 early return has its own _compute_requires_install()
        call, separate from the one at the end of _detect(). A dos-era hash
        hit on a .iso must still come back flagged.
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(
            detector._hash_lookup, "lookup",
            lambda path, index_path: _scan(era="dos", confidence=1.0, reason="sha1 match: fake"),
        )
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era == "dos"
        assert result.confidence == 1.0
        assert result.requires_install is True

    def test_hash_lookup_error_on_a_directory_is_swallowed(self, tmp_path: Path, monkeypatch):
        """Handing detect() a directory makes the Tier-1 hash read fail by
        construction. That is logged and stepped over, not surfaced.
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="win98", confidence=0.6))
        target = tmp_path / "game_dir"
        target.mkdir()

        assert _detect(target).era == "win98"


# ---------------------------------------------------------------------------
# Fail-soft contract: detect() never raises
# ---------------------------------------------------------------------------

class TestFailSoftContract:
    def test_unexpected_error_becomes_a_zero_confidence_result(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)

        def _boom(path):
            raise RuntimeError("delegate exploded")

        monkeypatch.setattr(detector, "detect_iso", _boom)
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "unexpected detection error"
        assert result.warnings == ["delegate exploded"]

    def test_error_from_a_non_oserror_type_is_also_caught(self, tmp_path: Path, monkeypatch):
        """The guard is `except Exception`, not `except OSError`, so a bug in
        a delegate (a TypeError, say) fails soft the same way an IO problem
        does. This is the contract README states for detect().
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)

        def _boom(path):
            raise TypeError("bad argument somewhere downstream")

        monkeypatch.setattr(detector, "detect_exe", _boom)
        path = tmp_path / "game.exe"
        path.write_bytes(b"MZ")

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.reason == "unexpected detection error"


# ---------------------------------------------------------------------------
# _compute_requires_install()
# ---------------------------------------------------------------------------

class TestComputeRequiresInstall:
    @pytest.mark.parametrize("filename", ["game.iso", "game.cue"])
    def test_dos_era_iso_and_cue_require_install(self, tmp_path: Path, monkeypatch, filename: str):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_iso", lambda path: _scan(era="dos", confidence=0.7))
        monkeypatch.setattr(detector, "detect_cue", lambda path, dir_cache=None: _scan(era="dos", confidence=0.7))
        path = tmp_path / filename
        path.write_bytes(b"\x00" * 64)

        assert _detect(path).requires_install is True

    @pytest.mark.parametrize("era", ["ps1", "winxp", "xbox", None])
    def test_non_dos_era_never_requires_install(self, tmp_path: Path, monkeypatch, era):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_iso", lambda path: _scan(era=era, confidence=0.7))
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 64)

        assert _detect(path).requires_install is False

    def test_dos_era_file_of_an_unrelated_suffix_does_not_require_install(
        self, tmp_path: Path, monkeypatch,
    ):
        """Only .iso/.cue/.img are install media. A dos-era .exe is the game."""
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_exe", lambda path: _scan(era="dos", confidence=0.65))
        path = tmp_path / "game.exe"
        path.write_bytes(b"MZ")

        assert _detect(path).requires_install is False

    def test_directory_of_only_blocklisted_executables_requires_install(
        self, tmp_path: Path, monkeypatch,
    ):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="dos", confidence=0.55))
        target = tmp_path / "disc"
        target.mkdir()
        (target / "INSTALL.EXE").write_bytes(b"MZ")
        (target / "PKUNZIP.EXE").write_bytes(b"MZ")
        (target / "README.TXT").write_text("not an executable, ignored")

        assert _detect(target).requires_install is True

    def test_directory_containing_a_real_game_executable_does_not(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="dos", confidence=0.55))
        target = tmp_path / "disc"
        target.mkdir()
        (target / "INSTALL.EXE").write_bytes(b"MZ")
        (target / "DOOM.EXE").write_bytes(b"MZ")

        assert _detect(target).requires_install is False

    @pytest.mark.parametrize("game_exe", ["INSANITY.EXE", "SETTINGS.EXE", "INSTINCT.EXE"])
    def test_short_prefix_blocklist_false_positives_no_longer_force_requires_install(
        self, tmp_path: Path, monkeypatch, game_exe: str,
    ):
        """Regression tying utils.blocklist's tightened prefixes to their real
        consumer. Under the old "ins"/"set" prefixes each of these names was
        blocked, so a directory holding the installer plus the actual game
        looked installer-only and was wrongly flagged.
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="dos", confidence=0.55))
        target = tmp_path / "disc"
        target.mkdir()
        (target / "INSTALL.EXE").write_bytes(b"MZ")
        (target / game_exe).write_bytes(b"MZ")

        assert _detect(target).requires_install is False

    def test_directory_with_no_executables_at_all_does_not_require_install(
        self, tmp_path: Path, monkeypatch,
    ):
        """The `if exes and ...` guard: an empty executable list must not
        vacuously satisfy all().
        """
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="dos", confidence=0.55))
        target = tmp_path / "disc"
        target.mkdir()
        (target / "GAME.DAT").write_bytes(b"\x00")

        assert _detect(target).requires_install is False

    def test_com_and_bat_count_as_executables_too(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_directory", lambda path: _scan(era="dos", confidence=0.55))
        target = tmp_path / "disc"
        target.mkdir()
        (target / "INSTALL.BAT").write_bytes(b"@echo off")
        (target / "PKUNZIP.COM").write_bytes(b"\x00")

        assert _detect(target).requires_install is True
