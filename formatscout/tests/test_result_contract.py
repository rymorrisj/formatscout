"""Result contract: ScanResult/ClassifyResult keyword-only fields, the
Status/Method/Tier vocabularies, the confidence -> Tier mapping, and the
method/status/authoritative tags every rule site attaches.

One test (or parametrized row) per rule site that builds a ScanResult. All
offline: conftest.py supplies the fake home, the network block and a
nonexistent index path; a test that needs an index writes a synthetic one.
"""

import importlib
import math
import os
import struct
from pathlib import Path

import pytest

import formatscout
from formatscout import detector, directory_detect, exe_detect, iso_detect
from formatscout.hashing import hash_lookup
from formatscout.magic import magic_detect
from formatscout.result import (
    Candidate,
    ClassifyResult,
    Issue,
    Method,
    ScanResult,
    Status,
    Tier,
    null_scan_result,
    tier_for_confidence,
)
from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.builders import index as index_builder
from formatscout.tests.builders import pe, xdvdfs
from formatscout.tests.builders.cue import HOSTILE_PARENT_POSIX, build_cue
from formatscout.tests.builders.iso9660 import build_iso
from formatscout.tests.builders.sparse import write_sparse
from formatscout.validators import bin_validator, chd_validator

PS2_BOOT_LINE = "BOOT2 = cdrom0:\\SLUS_200.62;1"


def _tags(result: ScanResult, method: Method, status: Status, authoritative: bool) -> None:
    assert (result.method, result.status, result.authoritative) == (method, status, authoritative), result.reason


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Bare construction and defaults
# ---------------------------------------------------------------------------

class TestScanResultDefaults:
    def test_era_less_result_defaults_to_no_signal(self):
        result = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
        assert result.status == Status.NO_SIGNAL
        assert result.method == Method.NONE
        assert result.authoritative is False
        assert result.container is None
        assert result.candidates == ()
        assert result.evidence == ()
        assert result.issues == ()
        assert result.platform_hint is None

    def test_era_result_defaults_to_guess(self):
        result = ScanResult(title=None, platform=None, era="ps1", confidence=0.5, reason="")
        assert result.status == Status.GUESS
        assert result.authoritative is False

    def test_authoritative_era_result_derives_identified(self):
        result = ScanResult(title=None, platform=None, era="ps1", confidence=1.0, reason="", authoritative=True)
        assert result.status == Status.IDENTIFIED

    def test_null_scan_result_is_no_signal(self):
        result = null_scan_result()
        assert (result.status, result.method, result.authoritative) == (Status.NO_SIGNAL, Method.NONE, False)

    def test_positional_construction_still_works(self):
        result = ScanResult(None, "plat", "dos", 0.35, "why", True, True, ["w"])
        assert (result.platform, result.era, result.requires_install, result.requires_extraction) == ("plat", "dos", True, True)
        assert result.warnings == ["w"]
        assert result.status == Status.GUESS

    def test_new_fields_are_keyword_only(self):
        with pytest.raises(TypeError):
            ScanResult(None, None, None, 0.0, "", False, False, [], Status.ERROR)  # type: ignore[misc]

    def test_plain_strings_are_coerced_to_enums(self):
        result = ScanResult(
            title=None, platform=None, era=None, confidence=0.0, reason="", status="error", method="magic",
        )
        assert result.status is Status.ERROR
        assert result.method is Method.MAGIC

    def test_plain_tuples_are_coerced_to_named_tuples(self):
        result = ScanResult(
            title=None, platform=None, era=None, confidence=0.2, reason="", status="ambiguous",
            candidates=[("ps1", "weak", ["x"])], issues=[("code", "message")], evidence=["e"],
        )
        assert result.candidates == (Candidate("ps1", Tier.WEAK, ("x",)),)
        assert result.candidates[0].tier is Tier.WEAK
        assert result.issues == (Issue("code", "message"),)
        assert result.evidence == ("e",)

    def test_unknown_status_or_method_is_rejected(self):
        with pytest.raises(ValueError):
            ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="", status="bogus")
        with pytest.raises(ValueError):
            ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="", method="bogus")

    @pytest.mark.parametrize(
        "era, status, authoritative",
        [
            (None, None, True),                  # authoritative needs an era
            (None, Status.IDENTIFIED, False),    # identified needs an era
            (None, Status.GUESS, False),         # guess needs an era
            ("ps1", Status.AMBIGUOUS, False),    # an era result is identified or guess
            ("ps1", Status.NO_SIGNAL, False),
            ("ps1", Status.IDENTIFIED, False),   # identified needs authoritative
            ("ps1", Status.GUESS, True),         # guess cannot be authoritative
        ],
    )
    def test_contradictory_combinations_are_rejected(self, era, status, authoritative):
        kwargs = {"authoritative": authoritative}
        if status is not None:
            kwargs["status"] = status
        with pytest.raises(ValueError):
            ScanResult(title=None, platform=None, era=era, confidence=0.5, reason="", **kwargs)


class TestClassifyResultDefaults:
    def test_bare_construction_defaults(self):
        result = ClassifyResult(status="not_in_index", computed_sha1="ab", matched_title=None, similarity=None, reason="r")
        assert result.matched_era is None
        assert result.hash_kind is None
        assert result.issues == ()

    def test_positional_construction_still_works(self):
        result = ClassifyResult("mismatch", "ab", "Title", 0.9, "r")
        assert (result.status, result.matched_title, result.similarity) == ("mismatch", "Title", 0.9)

    def test_new_fields_are_keyword_only(self):
        with pytest.raises(TypeError):
            ClassifyResult("verified", "ab", None, None, "r", "ps1")  # type: ignore[misc]

    def test_issues_are_coerced(self):
        result = ClassifyResult("unchecked", None, None, None, "r", issues=[("HASH_FAILED", "m")])
        assert result.issues == (Issue("HASH_FAILED", "m"),)


# ---------------------------------------------------------------------------
# Vocabularies, str equality, tier mapping, exports
# ---------------------------------------------------------------------------

class TestVocabulary:
    def test_status_values(self):
        assert {s.value for s in Status} == {
            "identified", "guess", "ambiguous", "container_only", "unsupported", "no_signal", "error",
        }

    def test_method_values(self):
        assert {m.value for m in Method} == {
            "hash_sha1", "hash_md5", "hash_crc32", "chd_header_claim", "magic", "structural", "system_cnf",
            "directory_marker", "pe_header", "extension", "size_heuristic", "title_match", "none",
        }

    def test_tier_values(self):
        assert [t.value for t in Tier] == ["certain", "strong", "moderate", "weak", "none"]

    @pytest.mark.parametrize("member", [*Status, *Method, *Tier])
    def test_members_equal_their_plain_string(self, member):
        assert isinstance(member, str)
        assert member == member.value
        assert str(member) == member.value
        assert f"{member}" == member.value

    def test_result_fields_compare_equal_to_plain_strings(self):
        result = ScanResult(title=None, platform=None, era="ps1", confidence=0.9, reason="", method=Method.MAGIC)
        assert result.status == "guess"
        assert result.method == "magic"
        assert result.status in {"guess", "identified"}

    def test_new_names_are_exported(self):
        for name in ("Status", "Method", "Tier", "Candidate", "Issue", "HashKind", "tier_for_confidence"):
            assert name in formatscout.__all__
            assert hasattr(formatscout, name)
        assert formatscout.Status is Status
        assert formatscout.tier_for_confidence is tier_for_confidence


class TestTierForConfidence:
    @pytest.mark.parametrize(
        "confidence, tier",
        [
            (1.0, Tier.CERTAIN), (1.5, Tier.CERTAIN), (math.inf, Tier.CERTAIN),
            (0.99, Tier.STRONG), (0.9, Tier.STRONG), (0.85, Tier.STRONG),
            (0.84, Tier.MODERATE), (0.75, Tier.MODERATE), (0.5, Tier.MODERATE),
            (0.49, Tier.WEAK), (0.35, Tier.WEAK), (0.2, Tier.WEAK), (1e-9, Tier.WEAK),
            (0.0, Tier.NONE), (-0.5, Tier.NONE), (math.nan, Tier.NONE),
        ],
    )
    def test_mapping(self, confidence, tier):
        assert tier_for_confidence(confidence) is tier

    @pytest.mark.parametrize(
        "confidence, tier",
        [
            (1.0, Tier.CERTAIN),    # sha1 hit
            (0.85, Tier.STRONG),    # md5 hit, CHD CHGD
            (0.9, Tier.STRONG),     # magic
            (0.75, Tier.MODERATE),  # crc32 hit, PVD label
            (0.7, Tier.MODERATE),   # extension only
            (0.35, Tier.WEAK),      # .img size guess
            (0.3, Tier.WEAK),       # weak guess
        ],
    )
    def test_documented_pipeline_values(self, confidence, tier):
        assert tier_for_confidence(confidence) is tier


class TestMagicTags:
    def test_system_cnf_reasons(self):
        assert magic_detect.magic_tags(magic_detect._SYSTEM_CNF_PS2_REASON) == (Method.SYSTEM_CNF, False)
        assert magic_detect.magic_tags(magic_detect._SYSTEM_CNF_PS1_REASON) == (Method.SYSTEM_CNF, False)

    def test_platform_signature_reason(self, tmp_path: Path):
        era, reason = magic_detect.detect_from_magic(_write(tmp_path / "g.bin", fx.NES_HEADER_BLOB), "bin")
        assert era == "nes"
        assert magic_detect.magic_tags(reason) == (Method.MAGIC, True)


# ---------------------------------------------------------------------------
# detector.py sites
# ---------------------------------------------------------------------------

class TestDetectorSites:
    def test_catch_all_is_error(self, monkeypatch, tmp_path: Path):
        def _boom(path, *args, **kwargs):
            raise RuntimeError("kaboom\nsecond line")

        monkeypatch.setattr(detector, "_detect", _boom)
        result = detector.detect(tmp_path / "anything.iso")
        _tags(result, Method.NONE, Status.ERROR, False)
        assert result.reason == "unexpected detection error"
        assert result.warnings == ["kaboom\nsecond line"]
        assert result.issues == (Issue("UNEXPECTED_ERROR", "RuntimeError: kaboom second line"),)

    def test_missing_path_is_error(self, tmp_path: Path):
        _tags(detector.detect(tmp_path / "missing.iso"), Method.NONE, Status.ERROR, False)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
    def test_neither_file_nor_directory_is_unsupported(self, tmp_path: Path):
        fifo = tmp_path / "pipe.iso"
        os.mkfifo(fifo)
        _tags(detector.detect(fifo), Method.NONE, Status.UNSUPPORTED, False)

    def test_nds_is_unsupported_with_platform_hint(self, tmp_path: Path):
        result = detector.detect(_write(tmp_path / "game.nds", b"x"))
        _tags(result, Method.EXTENSION, Status.UNSUPPORTED, False)
        assert result.platform_hint == "Nintendo DS"

    @pytest.mark.parametrize(
        "name", ["g.xiso", "g.xex", "g.z64", "g.n64", "g.v64", "g.sfc", "g.smc", "g.fig", "g.swc", "g.nes", "g.pkg"],
    )
    def test_extension_shortcuts_are_guesses(self, tmp_path: Path, name: str):
        result = detector.detect(_write(tmp_path / name, b"x"))
        assert result.era is not None
        _tags(result, Method.EXTENSION, Status.GUESS, False)

    @pytest.mark.parametrize("suffix", [".gdi", ".cdi"])
    def test_gdi_cdi_magic_hit_is_identified(self, tmp_path: Path, suffix: str):
        result = detector.detect(_write(tmp_path / f"g{suffix}", fx.DREAMCAST_IP_BIN_BLOB))
        assert result.era == "dreamcast"
        _tags(result, Method.MAGIC, Status.IDENTIFIED, True)

    @pytest.mark.parametrize("suffix", [".gdi", ".cdi"])
    def test_gdi_cdi_extension_fallback_is_guess(self, tmp_path: Path, suffix: str):
        result = detector.detect(_write(tmp_path / f"g{suffix}", b"not a gd-rom"))
        assert result.era == "dreamcast"
        _tags(result, Method.EXTENSION, Status.GUESS, False)

    def test_bin_platform_magic_is_identified(self, tmp_path: Path):
        result = detector.detect(_write(tmp_path / "g.bin", fx.NES_HEADER_BLOB))
        assert result.era == "nes"
        _tags(result, Method.MAGIC, Status.IDENTIFIED, True)

    def test_bin_system_cnf_magic_is_guess(self, tmp_path: Path):
        raw = build_iso({}, system_cnf=PS2_BOOT_LINE, system_id="PLAYSTATION", framing="mode2_form1")
        result = detector.detect(_write(tmp_path / "g.bin", raw))
        assert result.era == "ps2"
        _tags(result, Method.SYSTEM_CNF, Status.GUESS, False)

    def test_small_img_is_size_guess(self, tmp_path: Path):
        result = detector.detect(_write(tmp_path / "floppy.img", b"\x00" * 512))
        assert result.era == "dos"
        _tags(result, Method.SIZE_HEURISTIC, Status.GUESS, False)

    def test_large_img_is_no_signal(self, tmp_path: Path):
        result = detector.detect(write_sparse(tmp_path / "big.img", b"\x00", 900_000_000))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)

    def test_unhandled_extension_is_no_signal(self, tmp_path: Path):
        _tags(detector.detect(_write(tmp_path / "notes.txt", b"hello")), Method.NONE, Status.NO_SIGNAL, False)

    def test_index_unavailable_adds_one_issue_and_keeps_heuristic_tags(self, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, index_builder.write_corrupt_index(tmp_path / "index.json", "invalid_json"))
        result = detector.detect(_write(tmp_path / "g.bin", fx.NES_HEADER_BLOB))
        _tags(result, Method.MAGIC, Status.IDENTIFIED, True)
        codes = [issue.code for issue in result.issues]
        assert codes == ["INDEX_UNAVAILABLE"]
        assert result.issues[0].message in result.warnings

    def test_hash_hit_through_detect_is_identified(self, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        result = detector.detect(_write(tmp_path / "g.bin", fx.VERIFIED_CONTENT))
        _tags(result, Method.HASH_SHA1, Status.IDENTIFIED, True)
        assert result.issues == ()


# ---------------------------------------------------------------------------
# hashing/hash_lookup.lookup() sites
# ---------------------------------------------------------------------------

class TestHashLookupSites:
    @pytest.mark.parametrize(
        "content, method, status, authoritative",
        [
            (fx.VERIFIED_CONTENT, Method.HASH_SHA1, Status.IDENTIFIED, True),
            (fx.CAUTION_MD5_CONTENT, Method.HASH_MD5, Status.GUESS, False),
            (fx.CAUTION_CRC32_CONTENT, Method.HASH_CRC32, Status.GUESS, False),
        ],
    )
    def test_file_hash_tiers(self, tmp_path: Path, content, method, status, authoritative):
        result = hash_lookup.lookup(_write(tmp_path / "g.bin", content), fx.write_synthetic_index(tmp_path))
        assert result is not None and result.era == "ps1"
        _tags(result, method, status, authoritative)

    def test_chd_embedded_rawsha1_is_header_claim(self, tmp_path: Path):
        chd = _write(tmp_path / "g.chd", fx.build_synthetic_chd(fx.CHD_EMBEDDED_SHA1))
        result = hash_lookup.lookup(chd, fx.write_synthetic_index(tmp_path))
        assert result is not None and result.era == "dreamcast"
        # A header hash is a forgeable claim, never proof: guess, not authoritative.
        _tags(result, Method.CHD_HEADER_CLAIM, Status.GUESS, False)
        assert result.container == "chd"
        assert result.confidence == 1.0

    def test_entry_without_era_is_unsupported(self, tmp_path: Path):
        content = b"eraless synthetic content"
        index_path = index_builder.write_index_v1(
            tmp_path / "index.json", [index_builder.entry_for(content, title="PC Thing", era=None)],
        )
        result = hash_lookup.lookup(_write(tmp_path / "g.bin", content), index_path)
        assert result is not None and result.era is None
        _tags(result, Method.HASH_SHA1, Status.UNSUPPORTED, False)


# ---------------------------------------------------------------------------
# iso_detect.py sites
# ---------------------------------------------------------------------------

class TestIsoSites:
    def test_detect_iso_magic_hit(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: ("ps2", "fake magic"))
        result = iso_detect.detect_iso(_write(tmp_path / "g.iso", b"\x00" * 100))
        _tags(result, Method.MAGIC, Status.IDENTIFIED, True)

    def test_detect_iso_magic_hit_via_system_cnf(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(
            iso_detect, "detect_from_magic", lambda path, extension: ("ps2", magic_detect._SYSTEM_CNF_PS2_REASON),
        )
        result = iso_detect.detect_iso(_write(tmp_path / "g.iso", b"\x00" * 100))
        _tags(result, Method.SYSTEM_CNF, Status.GUESS, False)

    @pytest.mark.parametrize("executable, era", [("DEFAULT.XBE", "xbox"), ("DEFAULT.XEX", "xbox360")])
    def test_xdvdfs_is_magic_guess(self, tmp_path: Path, executable: str, era: str):
        result = iso_detect.detect_iso(_write(tmp_path / "g.iso", xdvdfs.build_xdvdfs(executable).data))
        assert result.era == era
        _tags(result, Method.MAGIC, Status.GUESS, False)
        assert result.container == "xdvdfs"
        assert not result.requires_extraction

    def test_xdvdfs_without_default_executable_is_container_only(self, tmp_path: Path):
        result = iso_detect.detect_iso(_write(tmp_path / "g.iso", xdvdfs.build_xdvdfs("GAME.XBE").data))
        _tags(result, Method.MAGIC, Status.CONTAINER_ONLY, False)
        assert result.container == "xdvdfs"
        assert [c.era for c in result.candidates] == ["xbox", "xbox360"]

    def test_iso9660_over_4gib_is_not_an_xbox_rip(self, tmp_path: Path):
        path = write_sparse(tmp_path / "g.iso", build_iso({"README.TXT": b"x"}, volume_id="FSDVD"), 4_400_000_000)
        result = iso_detect.detect_iso(path)
        assert result.era is None and not result.requires_extraction
        _tags(result, Method.SIZE_HEURISTIC, Status.AMBIGUOUS, False)
        assert result.container == "iso9660"

    def test_cue_without_bin_is_no_signal(self, tmp_path: Path):
        cue = tmp_path / "g.cue"
        cue.write_text(build_cue([("absent.bin", [(1, "MODE2/2352")])]), encoding="ascii")
        _tags(iso_detect.detect_cue(cue), Method.NONE, Status.NO_SIGNAL, False)

    def test_cue_magic_hit(self, tmp_path: Path):
        _write(tmp_path / "g.bin", fx.NES_HEADER_BLOB)
        cue = tmp_path / "g.cue"
        cue.write_text(build_cue([("g.bin", [(1, "MODE1/2352")])]), encoding="ascii")
        _tags(iso_detect.detect_cue(cue), Method.MAGIC, Status.IDENTIFIED, True)

    def test_cue_rejected_pointer_becomes_issue(self, tmp_path: Path):
        cue = tmp_path / "g.cue"
        cue.write_text(build_cue([(HOSTILE_PARENT_POSIX, [(1, "MODE2/2352")])]), encoding="ascii")
        result = iso_detect.detect_cue(cue)
        assert [issue.code for issue in result.issues] == ["POINTER_REJECTED"]
        assert result.issues[0].message in result.warnings

    @pytest.mark.parametrize(
        "kwargs, era, evidence",
        [
            ({"root_entries": ["PS3_DISC.SFB"]}, "ps3", "pvd_root_ps3_disc_sfb"),
            ({"root_entries": ["DEFAULT.XBE"]}, "xbox", "pvd_root_xbe"),
            ({"volume_id": "WIN98SE"}, "win98", "pvd_volume_label_keyword"),
            ({"publisher": "ID SOFTWARE"}, "dos", "pvd_publisher_dos_publisher"),
            ({"preparer": "APOGEE"}, "dos", "pvd_preparer_dos_publisher"),
        ],
    )
    def test_pvd_structural_sites(self, tmp_path: Path, kwargs, era, evidence):
        result = iso_detect.detect_from_pvd(fx.write_pvd_iso(tmp_path / "g.iso", **kwargs))
        assert result.era == era
        _tags(result, Method.STRUCTURAL, Status.GUESS, False)
        assert evidence in result.evidence

    @pytest.mark.parametrize("cnf, era", [("BOOT = cdrom:\\SLUS_000.01;1", "ps1"), (PS2_BOOT_LINE, "ps2")])
    def test_pvd_system_cnf_is_identified(self, tmp_path: Path, cnf: str, era: str):
        path = _write(tmp_path / "g.iso", build_iso({}, system_cnf=cnf, volume_id="FSTITLE"))
        result = iso_detect.detect_from_pvd(path)
        assert result.era == era
        _tags(result, Method.SYSTEM_CNF, Status.IDENTIFIED, True)
        assert result.container == "iso9660"

    @pytest.mark.parametrize(
        "kwargs, evidence",
        [
            ({"volume_id": "SLUS_000.01"}, "pvd_ps_serial_label"),
            ({"system_id": "CD-ROM", "publisher": "SONY COMPUTER"}, "pvd_sony_cdrom"),
        ],
    )
    def test_pvd_playstation_hint_without_system_cnf_is_ambiguous(self, tmp_path: Path, kwargs, evidence):
        result = iso_detect.detect_from_pvd(fx.write_pvd_iso(tmp_path / "g.iso", **kwargs))
        assert result.era is None
        _tags(result, Method.STRUCTURAL, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]
        assert evidence in result.evidence

    def test_pvd_ps_label_dvd_size_only_orders_candidates(self, tmp_path: Path):
        path = write_sparse(tmp_path / "g.iso", fx.build_pvd_iso(volume_id="SLUS_200.62"), 4_800_000_000)
        result = iso_detect.detect_from_pvd(path)
        assert result.era is None
        _tags(result, Method.SIZE_HEURISTIC, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps2", "ps1"]

    def test_pvd_no_signal(self, tmp_path: Path):
        result = iso_detect.detect_from_pvd(fx.write_pvd_iso(tmp_path / "g.iso", volume_id="FSDATA"))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)

    def test_pvd_read_error(self, tmp_path: Path):
        _tags(iso_detect.detect_from_pvd(tmp_path / "missing.iso"), Method.NONE, Status.ERROR, False)

    def test_size_fallback_stat_error(self, tmp_path: Path):
        _tags(iso_detect._iso_size_fallback(tmp_path / "missing.iso"), Method.NONE, Status.NO_SIGNAL, False)

    def test_size_fallback_over_4gib_is_ambiguous(self, tmp_path: Path):
        result = iso_detect._iso_size_fallback(write_sparse(tmp_path / "g.iso", b"\x00", 4_400_000_000))
        _tags(result, Method.SIZE_HEURISTIC, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps2", "xbox"]
        assert all(c.tier is Tier.WEAK for c in result.candidates)

    @pytest.mark.parametrize("size", [2048, 1_000_000_000])
    def test_size_fallback_confirmed_iso9660_is_container_only(self, tmp_path: Path, size: int):
        path = write_sparse(tmp_path / "g.iso", b"\x00", size)
        result = iso_detect._iso_size_fallback(path, iso9660_confirmed=True)
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "iso9660"

    @pytest.mark.parametrize("size", [2048, 1_000_000_000])
    def test_size_fallback_unconfirmed_is_no_signal(self, tmp_path: Path, size: int):
        result = iso_detect._iso_size_fallback(write_sparse(tmp_path / "g.iso", b"\x00", size))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)
        assert result.container is None


# ---------------------------------------------------------------------------
# exe_detect.py and directory_detect.py sites
# ---------------------------------------------------------------------------

PE_CASES = [
    (pe.build_mz_stub(), "dos"),
    (pe.build_mz_dos(), "dos"),
    (pe.build_pe32(major_os_version=5), "winxp"),
    (pe.build_pe32(major_os_version=4), "win98"),
]


class TestExeSites:
    @pytest.mark.parametrize("data, era", PE_CASES)
    def test_pe_branches_are_guesses(self, tmp_path: Path, data: bytes, era: str):
        result = exe_detect.detect_exe(_write(tmp_path / "g.exe", data))
        assert result.era == era
        _tags(result, Method.PE_HEADER, Status.GUESS, False)

    def test_unclassified_pe_is_no_signal(self, tmp_path: Path):
        result = exe_detect.detect_exe(_write(tmp_path / "g.exe", pe.build_pe32(major_os_version=3)))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)

    def test_read_error(self, tmp_path: Path):
        _tags(exe_detect.detect_exe(tmp_path / "missing.exe"), Method.NONE, Status.ERROR, False)


def _dir(root: Path, files: dict[str, bytes], dirs: tuple[str, ...] = ()) -> Path:
    root.mkdir()
    for name, data in files.items():
        (root / name).write_bytes(data)
    for name in dirs:
        (root / name).mkdir()
    return root


class TestDirectorySites:
    @pytest.mark.parametrize("data, era", PE_CASES)
    def test_autorun_pe_branches_are_guesses(self, tmp_path: Path, data: bytes, era: str):
        root = _dir(tmp_path / "disc", {"AUTORUN.INF": b"[autorun]\r\nOPEN=SETUP.EXE\r\n", "SETUP.EXE": data})
        result = directory_detect.detect_directory(root)
        assert result.era == era
        _tags(result, Method.PE_HEADER, Status.GUESS, False)
        assert "autorun_exe" in result.evidence

    def test_autorun_unclassified_pe_is_no_signal(self, tmp_path: Path):
        exe = _write(tmp_path / "SETUP.EXE", pe.build_pe32(major_os_version=3))
        _tags(directory_detect._detect_from_pe(exe), Method.NONE, Status.NO_SIGNAL, False)

    def test_autorun_pe_parse_error(self, tmp_path: Path):
        _tags(directory_detect._detect_from_pe(tmp_path / "missing.exe"), Method.NONE, Status.ERROR, False)

    def test_autorun_detection_error(self, tmp_path: Path, monkeypatch):
        def _boom(autorun):
            raise RuntimeError("boom")

        monkeypatch.setattr(directory_detect, "_parse_autorun_exe", _boom)
        root = _dir(tmp_path / "disc", {"AUTORUN.INF": b"[autorun]\r\nOPEN=SETUP.EXE\r\n"})
        _tags(directory_detect._detect_from_autorun(root), Method.NONE, Status.ERROR, False)

    def test_autorun_rejected_pointer_issue_reaches_fallback_result(self, tmp_path: Path):
        root = _dir(tmp_path / "disc", {"AUTORUN.INF": b"[autorun]\r\nOPEN=..\\EVIL.EXE\r\n"})
        result = directory_detect.detect_directory(root)
        assert [issue.code for issue in result.issues] == ["POINTER_REJECTED"]
        assert result.issues[0].message in result.warnings

    def test_unlistable_directory_is_error(self, tmp_path: Path):
        _tags(directory_detect._detect_from_directory(tmp_path / "missing"), Method.NONE, Status.ERROR, False)

    @pytest.mark.parametrize(
        "files, dirs, era, evidence",
        [
            ({"PS3_DISC.SFB": b".SFB"}, (), "ps3", "dir_ps3_disc_sfb"),
            ({}, ("I386",), "winxp", "dir_winxp_installer"),
            ({}, ("WIN98",), "win98", "dir_win98_markers"),
            ({}, ("WIN95",), "win95", "dir_win95_markers"),
            ({"INSTALL.BAT": b"@echo off"}, (), "dos", "dir_dos_install_script"),
            ({"DOOM.WAD": b"IWAD"}, (), "dos", "dir_wad_file"),
            ({"GAME.1": b"", "GAME.DAT": b""}, (), "dos", "dir_split_archive"),
            ({"RUN.BAT": b"", "DATA.XYZ": b""}, (), "dos", "dir_root_bat"),
            ({"GAME.EXE": b"MZ", "README.TXT": b""}, (), "dos", "dir_dos_only_extensions"),
        ],
    )
    def test_marker_sites_are_guesses(self, tmp_path: Path, files, dirs, era, evidence):
        result = directory_detect.detect_directory(_dir(tmp_path / "d", files, dirs))
        assert result.era == era
        _tags(result, Method.DIRECTORY_MARKER, Status.GUESS, False)
        assert evidence in result.evidence

    def test_depth2_dos_tool_is_guess(self, tmp_path: Path):
        root = _dir(tmp_path / "d", {}, ("TOOLS",))
        (root / "TOOLS" / "PKUNZIP.EXE").write_bytes(b"MZ")
        result = directory_detect.detect_directory(root)
        assert result.era == "dos"
        _tags(result, Method.DIRECTORY_MARKER, Status.GUESS, False)
        assert "dir_dos_tool" in result.evidence

    def test_system_cnf_is_guess(self, tmp_path: Path):
        root = _dir(tmp_path / "d", {"SYSTEM.CNF": PS2_BOOT_LINE.encode("ascii")})
        result = directory_detect.detect_directory(root)
        assert result.era == "ps2"
        _tags(result, Method.SYSTEM_CNF, Status.GUESS, False)

    def test_system_cnf_unreadable_is_ambiguous(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(magic_detect, "resolve_ps_generation_from_file", lambda path: "unknown")
        result = directory_detect.detect_directory(_dir(tmp_path / "d", {"SYSTEM.CNF": b"x"}))
        _tags(result, Method.SYSTEM_CNF, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_system_cnf_without_boot_key_is_ambiguous(self, tmp_path: Path):
        result = directory_detect.detect_directory(_dir(tmp_path / "d", {"SYSTEM.CNF": b"garbage, no key"}))
        assert result.era is None
        _tags(result, Method.SYSTEM_CNF, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_system_cnf_not_a_file_is_ambiguous(self, tmp_path: Path):
        result = directory_detect.detect_directory(_dir(tmp_path / "d", {}, ("SYSTEM.CNF",)))
        _tags(result, Method.SYSTEM_CNF, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_empty_directory_is_no_signal(self, tmp_path: Path):
        _tags(directory_detect.detect_directory(_dir(tmp_path / "d", {})), Method.NONE, Status.NO_SIGNAL, False)


# ---------------------------------------------------------------------------
# validators: chd_validator and bin_validator sites
# ---------------------------------------------------------------------------

def _chd_with_tag(tag: bytes, *, logical_bytes: int = 0) -> bytes:
    meta_at = fx.CHD_HEADER_SIZE
    buf = fx.build_chd_header(logical_bytes=logical_bytes, meta_offset=meta_at, size=meta_at + fx.CHD_META_ENTRY_LEN)
    fx.place_chd_metadata_entry(buf, meta_at, tag, 0)
    return bytes(buf)


class TestChdSites:
    def test_bad_magic_is_no_signal(self, tmp_path: Path):
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", b"not a chd"))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)

    def test_truncated_header_is_container_only_with_issue(self, tmp_path: Path):
        data = b"MComprHD" + struct.pack(">II", 124, 5) + b"\x00" * 32  # v5 prefix, ends before the metadata offset
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", data))
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "chd"
        assert [issue.code for issue in result.issues] == ["CHD_HEADER_TRUNCATED"]

    def test_unsupported_version_is_container_only_with_issue(self, tmp_path: Path):
        data = b"MComprHD" + struct.pack(">II", 108, 4) + b"\x00" * 100
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", data))
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "chd"
        assert [issue.code for issue in result.issues] == ["CHD_VERSION_UNSUPPORTED"]

    def test_chgd_is_structural_guess(self, tmp_path: Path):
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", _chd_with_tag(b"CHGD")))
        assert result.era == "dreamcast"
        _tags(result, Method.STRUCTURAL, Status.GUESS, False)
        assert result.container == "chd_gd"

    @pytest.mark.parametrize("tag", [b"CHTR", b"CHT2"])
    def test_chtr_cht2_is_container_only_with_candidates(self, tmp_path: Path, tag: bytes):
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", _chd_with_tag(tag, logical_bytes=1000)))
        assert result.era is None
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "chd_cd"
        assert [candidate.era for candidate in result.candidates] == ["ps1", "ps2"]

    def test_no_platform_tag_is_container_only(self, tmp_path: Path):
        result = chd_validator.detect_chd_platform(_write(tmp_path / "g.chd", _chd_with_tag(b"ABCD")))
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "chd"

    def test_read_error(self, tmp_path: Path):
        _tags(chd_validator.detect_chd_platform(tmp_path / "missing.chd"), Method.NONE, Status.ERROR, False)


class TestBinCueSites:
    def _pair(self, tmp_path: Path, bin_data: bytes, cue_text: str | None) -> Path:
        bin_path = _write(tmp_path / "g.bin", bin_data)
        if cue_text is not None:
            (tmp_path / "g.cue").write_text(cue_text, encoding="ascii")
        return bin_path

    def test_no_cue_is_no_signal(self, tmp_path: Path):
        result = bin_validator.resolve_bin_cue(self._pair(tmp_path, b"\x00" * 64, None))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)

    def test_magic_confirmed_by_cue(self, tmp_path: Path):
        cue = build_cue([("g.bin", [(1, "MODE1/2352")])])
        result = bin_validator.resolve_bin_cue(self._pair(tmp_path, fx.NES_HEADER_BLOB, cue))
        _tags(result, Method.MAGIC, Status.IDENTIFIED, True)
        assert result.container == "bin_cue"

    def test_mode2_is_ambiguous(self, tmp_path: Path):
        cue = build_cue([("g.bin", [(1, "MODE2/2352")])])
        result = bin_validator.resolve_bin_cue(self._pair(tmp_path, b"\x00" * 64, cue))
        _tags(result, Method.STRUCTURAL, Status.AMBIGUOUS, False)
        assert [c.era for c in result.candidates] == ["ps1", "ps2", "dreamcast"]

    @pytest.mark.parametrize("mode", ["MODE1/2352", "AUDIO", "MODE1/2048"])
    def test_other_track_types_are_container_only(self, tmp_path: Path, mode: str):
        cue = build_cue([("g.bin", [(1, mode)])])
        result = bin_validator.resolve_bin_cue(self._pair(tmp_path, b"\x00" * 64, cue))
        _tags(result, Method.STRUCTURAL, Status.CONTAINER_ONLY, False)
        assert result.container == "bin_cue"

    def test_cue_without_track_is_no_signal(self, tmp_path: Path):
        result = bin_validator.resolve_bin_cue(self._pair(tmp_path, b"\x00" * 64, 'FILE "g.bin" BINARY\n'))
        _tags(result, Method.NONE, Status.NO_SIGNAL, False)


# ---------------------------------------------------------------------------
# classify(): new ClassifyResult fields (statuses unchanged)
# ---------------------------------------------------------------------------

def _classify(path: Path, title: str, era: str | None):
    return formatscout.classify(path, title, era)


class TestClassifyFields:
    @pytest.mark.parametrize(
        "content, status, hash_kind",
        [
            (fx.VERIFIED_CONTENT, "verified", "sha1"),
            (fx.CAUTION_MD5_CONTENT, "caution", "md5"),
            (fx.CAUTION_CRC32_CONTENT, "caution", "crc32"),
        ],
    )
    def test_hash_hits(self, tmp_path: Path, monkeypatch, content, status, hash_kind):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        result = _classify(_write(tmp_path / "g.bin", content), "no title match", "ps1")
        assert (result.status, result.hash_kind, result.matched_era) == (status, hash_kind, "ps1")
        assert result.matched_title is None
        assert result.issues == ()

    def test_chd_rawsha1_hit(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        chd = _write(tmp_path / "g.chd", fx.build_synthetic_chd(fx.CHD_EMBEDDED_SHA1))
        result = _classify(chd, "x", "dreamcast")
        assert (result.status, result.hash_kind, result.matched_era) == ("caution", "chd_rawsha1", "dreamcast")
        assert [issue.code for issue in result.issues] == ["CLAIM_UNVERIFIED"]

    def test_chd_without_rawsha1_records_issue(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        result = _classify(_write(tmp_path / "g.chd", bytes(fx.build_chd_header())), "x", "ps1")
        assert result.status == "not_in_index"
        assert [issue.code for issue in result.issues] == ["CHD_RAWSHA1_MISSING"]

    def test_mismatch_carries_searched_era(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        result = _classify(_write(tmp_path / "g.bin", fx.UNINDEXED_CONTENT), fx.TITLE_QUERY_ABOVE_THRESHOLD, "ps1")
        assert (result.status, result.matched_era, result.hash_kind) == ("mismatch", "ps1", None)

    def test_not_in_index(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        result = _classify(_write(tmp_path / "g.bin", fx.UNINDEXED_CONTENT), "nothing like it", "ps1")
        assert (result.status, result.matched_era, result.hash_kind, result.issues) == ("not_in_index", None, None, ())

    def test_missing_custom_index_records_issue(self, tmp_path: Path):
        # conftest points classify at a nonexistent custom index path.
        result = _classify(_write(tmp_path / "g.bin", fx.UNINDEXED_CONTENT), "x", "ps1")
        assert result.status == "not_in_index"
        assert [issue.code for issue in result.issues] == ["INDEX_MISSING"]

    def test_unchecked_records_issue(self, tmp_path: Path):
        result = _classify(tmp_path / "missing.bin", "x", "ps1")
        assert result.status == "unchecked"
        assert [issue.code for issue in result.issues] == ["HASH_FAILED"]

    def test_classify_module_index_hook_still_patchable(self, tmp_path: Path, monkeypatch):
        classify_module = importlib.import_module("formatscout.classify")
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)
        assert classify_module._INDEX_PATH == index_path
