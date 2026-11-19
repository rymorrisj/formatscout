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
from formatscout.tests.builders.cue import build_cue


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
# md5/crc32 hits corroborate the suffix dispatch instead of short-circuiting it
# ---------------------------------------------------------------------------

_PS1_CNF = "BOOT = cdrom:\\SLUS_000.01;1\r\nTCB = 4\r\nEVENT = 10\r\nSTACK = 801FFF00\r\n"


def _ps1_raw_bin() -> bytes:
    """Raw Mode 2 image with a PS1 SYSTEM.CNF: the .bin dispatch reads it as
    ps1 via SYSTEM.CNF (corpus row ps1_raw_bin_boot)."""
    from formatscout.tests.builders.iso9660 import build_iso
    return build_iso({}, system_cnf=_PS1_CNF, system_id="PLAYSTATION", volume_id="FSPS", framing="mode2_form1")


def _weak_hash_index(tmp_path: Path, content: bytes, era: str, kind: str = "md5") -> Path:
    """Index whose only entry matches *content* by md5 (or crc32) alone: its
    sha1 key is unrelated, so lookup() reports an md5/crc32 hit."""
    from formatscout.tests.builders import index as index_builder
    hashes = fx.hashes_for(content)
    entry = index_builder.IndexEntry("f" * 40, "Weak Hash Game (USA)", era, "Synthetic Platform", **{kind: hashes[kind]})
    index_dir = tmp_path / "idx"
    index_dir.mkdir()
    return index_builder.write_index_v1(index_dir / "index.json", [entry])


def _codes(result) -> list[str]:
    return [issue.code for issue in result.issues]


class TestWeakHashCorroboration:
    @pytest.mark.parametrize("kind, confidence", [("md5", 0.45), ("crc32", 0.35)])
    def test_hit_without_structural_evidence_is_a_weak_guess(self, tmp_path: Path, monkeypatch, kind, confidence):
        from formatscout.result import IssueCode, Method, Status

        content = fx.CAUTION_MD5_CONTENT if kind == "md5" else fx.CAUTION_CRC32_CONTENT
        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        path = tmp_path / "game.bin"
        path.write_bytes(content)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.method == Method(f"hash_{kind}")
        assert (result.status, result.authoritative) == (Status.GUESS, False)
        assert result.confidence == confidence
        assert IssueCode.HASH_WEAK in _codes(result)
        assert IssueCode.CONFLICTING_EVIDENCE not in _codes(result)
        assert f"{kind}_index_match" in result.evidence

    def test_agreeing_structure_is_kept_and_records_corroboration(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Method

        content = _ps1_raw_bin()
        fx.patch_detector_index(monkeypatch, _weak_hash_index(tmp_path, content, "ps1"))
        path = tmp_path / "game.bin"
        path.write_bytes(content)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.method == Method.SYSTEM_CNF
        assert result.authoritative is False
        assert "md5_index_match" in result.evidence
        assert result.title == "Weak Hash Game (USA)"
        assert result.confidence >= 0.85
        assert "corroborated by md5 match" in result.reason
        assert result.issues == ()

    def test_disagreeing_structure_wins_with_conflicting_evidence(self, tmp_path: Path, monkeypatch):
        from formatscout.result import IssueCode, Method

        content = _ps1_raw_bin()
        fx.patch_detector_index(monkeypatch, _weak_hash_index(tmp_path, content, "dreamcast"))
        path = tmp_path / "game.bin"
        path.write_bytes(content)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.method == Method.SYSTEM_CNF
        assert _codes(result) == [IssueCode.CONFLICTING_EVIDENCE]
        assert result.issues[0].message in result.warnings
        assert result.title is None

    def test_hit_inside_structural_candidates_picks_one(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Method, Status

        content = b"\x00" * 64
        fx.patch_detector_index(monkeypatch, _weak_hash_index(tmp_path, content, "ps2"))
        path = tmp_path / "g.bin"
        path.write_bytes(content)
        (tmp_path / "g.cue").write_text(build_cue([("g.bin", [(1, "MODE2/2352")])]), encoding="ascii")

        result = _detect(path)

        assert result.era == "ps2"
        assert (result.method, result.status, result.authoritative) == (Method.HASH_MD5, Status.GUESS, False)
        assert result.container == "bin_cue"
        assert result.confidence == 0.85

    def test_hit_outside_structural_candidates_keeps_them(self, tmp_path: Path, monkeypatch):
        from formatscout.result import IssueCode, Status

        content = b"\x00" * 64
        fx.patch_detector_index(monkeypatch, _weak_hash_index(tmp_path, content, "xbox"))
        path = tmp_path / "g.bin"
        path.write_bytes(content)
        (tmp_path / "g.cue").write_text(build_cue([("g.bin", [(1, "MODE2/2352")])]), encoding="ascii")

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert IssueCode.CONFLICTING_EVIDENCE in _codes(result)

    def test_extension_guess_does_not_overrule_the_hit(self, tmp_path: Path, monkeypatch):
        """An extension-only era is not structural evidence: the hit stays the
        answer (weakly), and the disagreement is reported."""
        from formatscout.result import IssueCode, Method

        content = fx.CAUTION_MD5_CONTENT
        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        path = tmp_path / "game.nes"
        path.write_bytes(content)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.method == Method.HASH_MD5
        assert {IssueCode.HASH_WEAK, IssueCode.CONFLICTING_EVIDENCE} <= set(_codes(result))

    def test_sha1_hit_still_short_circuits(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import Method

        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        def _never(*args, **kwargs):
            raise AssertionError("suffix dispatch must not run after a sha1 hit")

        monkeypatch.setattr(detector, "_detect_file", _never)
        path = tmp_path / "game.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        result = _detect(path)

        assert (result.era, result.method, result.authoritative) == ("ps1", Method.HASH_SHA1, True)

    def test_requires_install_follows_the_weak_hit_era(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import Method, ScanResult

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(
            detector._hash_lookup, "lookup",
            lambda path, index_path: ScanResult(
                title="DOS Thing", platform=None, era="dos", confidence=0.85, reason="md5 match: fake",
                method=Method.HASH_MD5,
            ),
        )
        monkeypatch.setattr(detector, "detect_iso", lambda path: _scan())
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era == "dos"
        assert result.requires_install is True

    def test_dispatch_error_after_a_weak_hit_keeps_the_hit(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import IssueCode, Method, ScanResult

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(
            detector._hash_lookup, "lookup",
            lambda path, index_path: ScanResult(
                title="Thing", platform=None, era="ps2", confidence=0.75, reason="crc32 match: fake",
                method=Method.HASH_CRC32,
            ),
        )

        def _boom(path):
            raise RuntimeError("delegate exploded")

        monkeypatch.setattr(detector, "detect_iso", _boom)
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 64)

        result = _detect(path)

        assert result.era == "ps2"
        assert result.reason != "unexpected detection error"
        assert IssueCode.HASH_WEAK in _codes(result)


# ---------------------------------------------------------------------------
# CHD candidate resolution by filename title (container_only + candidates)
# ---------------------------------------------------------------------------

def _chd_container_only(eras=("ps1", "ps2"), container="chd_cd"):
    """What detect_chd() returns for a CD/DVD-tagged CHD per the lane
    interface: era None, container_only, candidate eras."""
    from formatscout.result import Candidate, Method, ScanResult, Status, Tier
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0, reason="CHD CD track metadata, platform unknown",
        status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container=container,
        candidates=tuple(Candidate(era, Tier.WEAK) for era in eras),
    )


def _title_index(tmp_path: Path, titles) -> Path:
    from formatscout.tests.builders import index as index_builder
    entries = [
        index_builder.IndexEntry(f"{n:040x}", title, era, platform)
        for n, (title, era, platform) in enumerate(titles, start=1)
    ]
    index_dir = tmp_path / "idx"
    index_dir.mkdir()
    return index_builder.write_index_v1(index_dir / "index.json", entries)


def _chd_file(tmp_path: Path, name: str) -> Path:
    # Header with an all-zero rawsha1: lookup() loads the index, finds no
    # embedded hash and returns None.
    path = tmp_path / name
    path.write_bytes(bytes(fx.build_chd_header()))
    return path


class TestChdTitleResolution:
    def test_single_candidate_era_match_resolves_as_title_match(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import Method, Status

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [("Ico (USA)", "ps2", "Sony - PlayStation 2")]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert result.era == "ps2"
        assert (result.method, result.status, result.authoritative) == (Method.TITLE_MATCH, Status.GUESS, False)
        assert result.reason == "title match in Sony - PlayStation 2 index (hash lookup unavailable for CHD)"
        assert result.title == "Ico (USA)"
        assert result.container == "chd_cd"
        assert result.issues == ()

    def test_disc_suffix_in_the_filename_is_ignored(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [("Ico (USA)", "ps2", "Sony - PlayStation 2")]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        assert _detect(_chd_file(tmp_path, "Ico - Disc 1.chd")).era == "ps2"

    def test_several_matching_eras_stay_ambiguous(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import IssueCode, Status

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [
            ("Ico (USA)", "ps2", "Sony - PlayStation 2"), ("Ico (Japan)", "ps1", "Sony - PlayStation"),
        ]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert [issue.code for issue in result.issues] == [IssueCode.AMBIGUOUS_CONTAINER]

    def test_match_outside_the_candidates_is_ignored(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import Status

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [("Ico (USA)", "xbox", "Microsoft - Xbox")]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert (result.era, result.status, result.issues) == (None, Status.CONTAINER_ONLY, ())

    def test_no_match_leaves_the_result_unchanged(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import Method

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [("Ico (USA)", "ps2", None)]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Something Else.chd"))

        assert (result.era, result.method, result.issues) == (None, Method.STRUCTURAL, ())

    def test_unavailable_index_adds_only_the_existing_issue(self, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.tests.builders import index as index_builder

        fx.patch_detector_index(monkeypatch, index_builder.write_corrupt_index(tmp_path / "index.json", "invalid_json"))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert result.era is None
        assert [issue.code for issue in result.issues] == ["INDEX_UNAVAILABLE"]
        assert len(result.warnings) == 1

    def test_missing_index_skips_silently(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        _no_index(monkeypatch, tmp_path)
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert (result.era, result.issues) == (None, ())

    def test_title_match_error_never_escapes_detect(self, tmp_path: Path, monkeypatch):
        from formatscout import detector

        fx.patch_detector_index(monkeypatch, _title_index(tmp_path, [("Ico (USA)", "ps2", None)]))
        monkeypatch.setattr(detector, "detect_chd", lambda path: _chd_container_only())

        def _boom(*args, **kwargs):
            raise RuntimeError("title table exploded")

        monkeypatch.setattr(detector._title_match, "exact_title_matches", _boom)

        result = _detect(_chd_file(tmp_path, "Ico (USA).chd"))

        assert result.era is None
        assert result.reason != "unexpected detection error"


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
