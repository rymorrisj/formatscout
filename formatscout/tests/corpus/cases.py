"""Detection corpus: a table of synthetic samples and the era a correct detector returns.

Each Case builds one tiny sample (a file, a file plus siblings, or a
directory) inside a scratch directory and says what detect() SHOULD return
for it. expect_era is the correct answer, not the current behavior. Where the
current behavior differs, the case is flagged known_wrong with the finding
IDs below; test_corpus.py applies pytest.mark.xfail(strict=True) to those, so
fixing the library makes the test XPASS (a failure) until the flag is removed.

Finding legend (the single place these IDs are defined; every ID used by a
known-wrong case must appear here, and every ID here must be used):
"""

import ast
import inspect
import textwrap
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from formatscout import detector
from formatscout.magic import magic_detect
from formatscout.result import Era, Method
from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.builders import chd, index, pe, roms, sectors, xdvdfs
from formatscout.tests.builders.cue import build_cue
from formatscout.tests.builders.iso9660 import build_iso
from formatscout.tests.builders.sparse import write_sparse

FINDINGS: dict[str, str] = {
    "F-IMG-SIZE-ONLY": (
        "Any .img under 800 MiB is called dos from extension and size alone, including a raw "
        "CloneCD-style PS1 image and a zero-byte file."
    ),
    "F-PKG-EXT-ONLY": "Every .pkg is called ps3 from its extension, including a PS4 package.",
    "F-EXT-ONLY-EMPTY": (
        "Extension-only shortcuts (.xiso .xex .z64 .n64 .v64 .sfc family .nes .pkg .gdi .cdi) assign "
        "an era to a zero-byte file."
    ),
}
__doc__ += "\n".join(f"    {key}: {text}" for key, text in FINDINGS.items()) + "\n"


class _NotAsserted:
    """Sentinel: the case only checks that detect() returns a result."""

    def __repr__(self) -> str:
        return "NOT_ASSERTED"


NOT_ASSERTED = _NotAsserted()

# Builder: (scratch directory, Case.filename) -> path to hand to detect().
Builder = Callable[[Path, str], Path]
# IndexBuilder: (scratch directory) -> path of an index file for detector._INDEX_PATH.
IndexBuilder = Callable[[Path], Path]


@dataclass(frozen=True)
class Case:
    """One corpus sample. Add new columns as keyword fields with defaults.

    build(workdir, filename) creates the sample in an empty *workdir* and
    returns the path passed to detect(): the file called *filename*, or, for a
    directory sample, the directory called *filename*.
    expect_era is what a correct detector returns (None means "no era");
    NOT_ASSERTED means only "returns a result without failing".
    known_wrong marks a case whose current behavior differs from expect_era;
    it needs finding_ids (keys of FINDINGS) and an asserted era.
    index, when set, writes a hash index and points detect() at it.
    expect_method/expect_authoritative, when set, are the ScanResult.method
    and ScanResult.authoritative the current detector returns (observed, not
    aspirational). Only for cases with an asserted era that are not
    known_wrong: a known-wrong row must keep failing for its era alone.
    """

    id: str
    build: Builder
    filename: str
    expect_era: Era | None | _NotAsserted
    finding_ids: tuple[str, ...] = ()
    known_wrong: bool = False
    index: IndexBuilder | None = None
    expect_method: Method | None = None
    expect_authoritative: bool | None = None

    @property
    def has_tag_expectations(self) -> bool:
        return self.expect_method is not None or self.expect_authoritative is not None

    def __post_init__(self) -> None:
        if self.has_tag_expectations and (self.known_wrong or self.expect_era is NOT_ASSERTED):
            raise ValueError(f"{self.id}: tag expectations need an asserted era and no known_wrong")
        if self.known_wrong and not self.finding_ids:
            raise ValueError(f"{self.id}: known_wrong needs finding_ids")
        if self.known_wrong and self.expect_era is NOT_ASSERTED:
            raise ValueError(f"{self.id}: known_wrong needs an asserted era")
        unknown = [f for f in self.finding_ids if f not in FINDINGS]
        if unknown:
            raise ValueError(f"{self.id}: unknown finding ids {unknown}")


# ---------------------------------------------------------------------------
# Builders (how a sample is laid out on disk)
# ---------------------------------------------------------------------------

def file_of(data: bytes) -> Builder:
    def build(workdir: Path, filename: str) -> Path:
        path = workdir / filename
        path.write_bytes(data)
        return path
    return build


def sparse_of(head: bytes, size: int) -> Builder:
    def build(workdir: Path, filename: str) -> Path:
        return write_sparse(workdir / filename, head, size)
    return build


def dir_of(files: dict[str, bytes]) -> Builder:
    def build(workdir: Path, filename: str) -> Path:
        root = workdir / filename
        root.mkdir()
        for name, data in files.items():
            (root / name).write_bytes(data)
        return root
    return build


def cue_with_bin(bin_data: bytes, *, bin_name: str = "game.bin", mode: str = "MODE2/2352") -> Builder:
    def build(workdir: Path, filename: str) -> Path:
        (workdir / bin_name).write_bytes(bin_data)
        cue = workdir / filename
        cue.write_text(build_cue([(bin_name, [(1, mode)])]), encoding="ascii")
        return cue
    return build


def clonecd_img(img_data: bytes) -> Builder:
    """A raw .img with its .ccd control file beside it (the .sub is omitted)."""
    ccd = "[CloneCD]\nVersion=3\n[Disc]\nTocEntries=3\nSessions=1\nDataTracksScrambled=0\n"

    def build(workdir: Path, filename: str) -> Path:
        img = workdir / filename
        img.write_bytes(img_data)
        img.with_suffix(".ccd").write_text(ccd, encoding="ascii")
        return img
    return build


# ---------------------------------------------------------------------------
# Sample bytes
# ---------------------------------------------------------------------------

PS1_CNF = "BOOT = cdrom:\\SLUS_000.01;1\r\nTCB = 4\r\nEVENT = 10\r\nSTACK = 801FFF00\r\n"
PS2_CNF = "BOOT2 = cdrom0:\\SLUS_200.62;1\r\nVER = 1.00\r\nVMODE = NTSC\r\n"
RAW = "mode2_form1"


@cache
def ps_raw(cnf: str, framing: str = RAW) -> bytes:
    return build_iso({}, system_cnf=cnf, system_id="PLAYSTATION", volume_id="FSPS", framing=framing)


@cache
def ps_cooked(cnf: str, volume_id: str) -> bytes:
    return build_iso({}, system_cnf=cnf, system_id="PLAYSTATION", volume_id=volume_id)


@cache
def plain_iso(**kwargs: str) -> bytes:
    return build_iso({"README.TXT": b"hello"}, **kwargs)


@cache
def ps3_iso() -> bytes:
    return build_iso({"PS3_DISC.SFB": b".SFB\x00\x01\x00\x01"}, volume_id="PS3VOLUME")


@cache
def xdvdfs_image(executable: str) -> xdvdfs.XdvdfsImage:
    return xdvdfs.build_xdvdfs(executable)


@cache
def dreamcast_raw_bin() -> bytes:
    ip = b"SEGA SEGAKATANA SEGA ENTERPRISES".ljust(2048, b" ")
    return sectors.frame_sectors([ip, bytes(2048)], "mode1")


def chd_image(version: int, *entries: chd.MetaEntry, logical_bytes: int | None = None) -> chd.ChdImage:
    return chd.build_chd(version=version, metadata=tuple(entries), logical_bytes=logical_bytes)


ICO_LOGICAL_BYTES = 664_710_336  # CD-sized logical length of a PS2 CD-ROM title
DVD_LOGICAL_BYTES = 4_400_000_000


# ---------------------------------------------------------------------------
# Case table, hand written part
# ---------------------------------------------------------------------------

def _hand_written() -> list[Case]:
    ps1_bin = ps_raw(PS1_CNF)
    ps2_bin = ps_raw(PS2_CNF)
    ps1_hash_bin = fx.VERIFIED_CONTENT
    cases: list[Case] = [
        # -- PS1 / PS2 raw and cooked ---------------------------------------
        Case(
            "ps1_raw_bin_boot", file_of(ps1_bin), "game.bin", "ps1",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case(
            "ps1_raw_bin_boot_via_cue", cue_with_bin(ps1_bin), "game.cue", "ps1",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case(
            "ps2_raw_bin_boot2", file_of(ps2_bin), "game.bin", "ps2",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case(
            "pc_raw_bin_mode1_no_system_cnf", file_of(build_iso({"SETUP.EXE": b"MZ"}, framing="mode1")), "pc.bin", None,
            expect_method=Method.NONE, expect_authoritative=False,
        ),
        Case(
            "ps1_cooked_iso_boot_serial_label", file_of(ps_cooked(PS1_CNF, "SLUS_000.01")), "ps1.iso", "ps1",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=True,
        ),
        Case(
            "ps1_cooked_iso_boot_titled_label", file_of(ps_cooked(PS1_CNF, "FSTITLE")), "ps1.iso", "ps1",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=True,
        ),
        Case(
            "ps2_cooked_iso_boot2_serial_label", file_of(ps_cooked(PS2_CNF, "SLUS_200.62")), "ps2.iso", "ps2",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=True,
        ),
        Case(
            "ps2_cooked_iso_boot2_titled_label", file_of(ps_cooked(PS2_CNF, "FSTITLE")), "ps2.iso", "ps2",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=True,
        ),
        Case(
            "ps2_dvd_sized_iso_boot2_serial_label",
            sparse_of(ps_cooked(PS2_CNF, "SLUS_200.62"), 4_800_000_000), "ps2_dvd.iso", "ps2",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=True,
        ),
        # A PlayStation-looking disc with no readable BOOT/BOOT2 key names no era.
        Case(
            "iso_system_cnf_without_boot_key_no_era", file_of(ps_cooked("VER = 1.00\r\n", "FSTITLE")), "nokey.iso", None,
        ),
        Case(
            "iso_serial_label_without_system_cnf_no_era", file_of(plain_iso(volume_id="SLUS_000.01")), "serial.iso", None,
        ),
        Case("clonecd_img_ps1_raw", clonecd_img(ps1_bin), "game.img", "ps1", ("F-IMG-SIZE-ONLY",), True),
        # -- PS3 ---------------------------------------------------------------
        Case(
            "ps3_iso_sfb", file_of(ps3_iso()), "ps3.iso", "ps3",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "ps3_directory_sfb", dir_of({"PS3_DISC.SFB": b".SFB"}), "ps3_dir", "ps3",
            expect_method=Method.DIRECTORY_MARKER, expect_authoritative=False,
        ),
        Case(
            "ps3_pkg_magic", file_of(roms.build_ps3_pkg()), "game.pkg", "ps3",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case("ps4_pkg_magic", file_of(roms.build_ps4_pkg()), "game.pkg", None, ("F-PKG-EXT-ONLY",), True),
        # -- Xbox / Xbox 360 ----------------------------------------------------
        Case(
            "xdvdfs_xbe_iso", file_of(xdvdfs_image("DEFAULT.XBE").data), "xbox.iso", "xbox",
            expect_method=Method.MAGIC, expect_authoritative=False,
        ),
        Case(
            "xdvdfs_xex_iso", file_of(xdvdfs_image("DEFAULT.XEX").data), "x360.iso", "xbox360",
            expect_method=Method.MAGIC, expect_authoritative=False,
        ),
        Case(
            "xex2_file_ext", file_of(roms.build_xex2()), "default.xex", "xbox360",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "xdvdfs_xbe_xiso_ext", file_of(xdvdfs_image("DEFAULT.XBE").data), "xbox.xiso", "xbox",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        # -- Generic ISO 9660 ---------------------------------------------------
        Case(
            "pc_dvd_iso9660_over_4gib", sparse_of(plain_iso(volume_id="FSPCDVD"), 4_400_000_000), "pc_dvd.iso", None,
        ),
        Case(
            "pc_cd_iso9660_no_signal", file_of(plain_iso(volume_id="FSDATA")), "data.iso", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "iso_publisher_dos_keyword", file_of(plain_iso(volume_id="FSGAME", publisher="ID SOFTWARE")),
            "doom.iso", "dos",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "iso_volume_label_winxp", file_of(plain_iso(volume_id="WINDOWS XP SP2")), "xp.iso", "winxp",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "iso_volume_label_win98", file_of(plain_iso(volume_id="WIN98SE")), "w98.iso", "win98",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        # -- Dreamcast ------------------------------------------------------------
        Case(
            "dreamcast_raw_bin_ip", file_of(dreamcast_raw_bin()), "dc.bin", "dreamcast",
            expect_method=Method.MAGIC, expect_authoritative=True,
        ),
        # -- CHD ----------------------------------------------------------------
        Case(
            "chd_v5_chgd_dreamcast", file_of(chd_image(5, chd.track_entry(chd.TAG_CHGD, track_type="MODE1_RAW")).data), "dc.chd", "dreamcast",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_chgt_dreamcast", file_of(chd_image(5, chd.track_entry(chd.TAG_CHGT, track_type="MODE1_RAW")).data), "dc.chd",
            "dreamcast",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_chain_unknown_tag_then_chgd",
            file_of(chd_image(5, chd.MetaEntry(b"ABCD", b"x\x00"), chd.track_entry(chd.TAG_CHGD)).data), "dc.chd", "dreamcast",
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_cht2_ico_cd_sized_ps2",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHT2), logical_bytes=ICO_LOGICAL_BYTES).data), "Ico (USA).chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_chtr_dvd_sized",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHTR), logical_bytes=DVD_LOGICAL_BYTES).data), "disc.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_cht2_logical_size_zero",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHT2), logical_bytes=0).data), "disc.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_dvd_tag", file_of(chd_image(5, chd.dvd_entry(), logical_bytes=DVD_LOGICAL_BYTES).data), "dvd.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_no_metadata", file_of(chd_image(5).data), "bare.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v4_chgd_dreamcast", file_of(chd_image(4, chd.track_entry(chd.TAG_CHGD, track_type="MODE1_RAW")).data), "dc_v4.chd",
            None, expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v4_cht2", file_of(chd_image(4, chd.track_entry(chd.TAG_CHT2), logical_bytes=ICO_LOGICAL_BYTES).data), "disc_v4.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v4_dvd_tag", file_of(chd_image(4, chd.dvd_entry(), logical_bytes=DVD_LOGICAL_BYTES).data), "dvd_v4.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_chcd_tag", file_of(chd_image(5, chd.MetaEntry(chd.TAG_CHCD, b"\x00")).data), "chcd.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_chtr_plain_cd", file_of(chd_image(5, chd.track_entry(chd.TAG_CHTR)).data), "cd.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_v5_unknown_tag_then_cht2",
            file_of(chd_image(5, chd.MetaEntry(b"ABCD", b"x\x00"), chd.track_entry(chd.TAG_CHT2)).data), "disc.chd", None,
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        # CD/DVD CHDs are resolved by an exact filename-title match in the candidate eras only.
        Case(
            "chd_cht2_title_match_single_era_ps2",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHT2), logical_bytes=ICO_LOGICAL_BYTES).data), "Ico (USA).chd", "ps2",
            index=lambda d: index.write_index_v1(
                d / "index.json",
                [index.entry_for(b"ico-ps2", title="Ico (USA)", era="ps2", platform="Sony - PlayStation 2")],
            ),
            expect_method=Method.TITLE_MATCH, expect_authoritative=False,
        ),
        Case(
            "chd_cht2_title_match_two_eras_stays_ambiguous",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHT2)).data), "Twin (USA).chd", None,
            index=lambda d: index.write_index_v1(
                d / "index.json",
                [
                    index.entry_for(b"twin-ps1", title="Twin (USA)", era="ps1", platform="Sony - PlayStation"),
                    index.entry_for(b"twin-ps2", title="Twin (USA)", era="ps2", platform="Sony - PlayStation 2"),
                ],
            ),
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        Case(
            "chd_cht2_title_match_outside_candidates_ignored",
            file_of(chd_image(5, chd.track_entry(chd.TAG_CHT2)).data), "Halo (USA).chd", None,
            index=lambda d: index.write_index_v1(
                d / "index.json", [index.entry_for(b"halo-xbox", title="Halo (USA)", era="xbox", platform="Microsoft - Xbox")],
            ),
            expect_method=Method.STRUCTURAL, expect_authoritative=False,
        ),
        # -- Executables ---------------------------------------------------------
        Case(
            "exe_mz_dos", file_of(pe.build_mz_dos()), "game.exe", "dos",
            expect_method=Method.PE_HEADER, expect_authoritative=False,
        ),
        Case(
            "exe_mz_stub", file_of(pe.build_mz_stub()), "tiny.exe", "dos",
            expect_method=Method.PE_HEADER, expect_authoritative=False,
        ),
        Case(
            "exe_ne_windows_16bit", file_of(pe.build_ne()), "win3.exe", "dos",
            expect_method=Method.PE_HEADER, expect_authoritative=False,
        ),
        Case(
            "exe_pe32_os5_winxp", file_of(pe.build_pe32(major_os_version=5)), "xp.exe", "winxp",
            expect_method=Method.PE_HEADER, expect_authoritative=False,
        ),
        Case(
            "exe_pe32_os4_win98", file_of(pe.build_pe32(major_os_version=4)), "w98.exe", "win98",
            expect_method=Method.PE_HEADER, expect_authoritative=False,
        ),
        Case(
            "exe_pe32_native_subsystem", file_of(pe.build_pe32(subsystem=pe.IMAGE_SUBSYSTEM_NATIVE)), "drv.exe", None,
            expect_method=Method.NONE, expect_authoritative=False,
        ),
        Case(
            "exe_pe32_os3_old_nt", file_of(pe.build_pe32(major_os_version=3)), "nt351.exe", None,
            expect_method=Method.NONE, expect_authoritative=False,
        ),
        # -- ROMs by content and by extension -------------------------------------
        Case(
            "nes_ines_bin", file_of(roms.build_ines()), "game.bin", "nes",
            expect_method=Method.MAGIC, expect_authoritative=True,
        ),
        Case(
            "nes_ines_ext", file_of(roms.build_ines()), "game.nes", "nes",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "snes_lorom_ext_sfc", file_of(roms.build_snes_lorom()), "game.sfc", "snes",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "snes_lorom_ext_smc", file_of(roms.build_snes_lorom()), "game.smc", "snes",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "n64_z64_ext", file_of(roms.build_n64("z64")), "game.z64", "n64",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "n64_v64_ext", file_of(roms.build_n64("v64")), "game.v64", "n64",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "n64_n64_ext", file_of(roms.build_n64("n64")), "game.n64", "n64",
            expect_method=Method.EXTENSION, expect_authoritative=False,
        ),
        Case(
            "n64_big_endian_bin", file_of(roms.build_n64("z64")), "game.bin", "n64",
            expect_method=Method.MAGIC, expect_authoritative=True,
        ),
        Case(
            "n64_byteswapped_bin", file_of(roms.build_n64("v64")), "game.bin", "n64",
            expect_method=Method.MAGIC, expect_authoritative=True,
        ),
        Case(
            "n64_little_endian_bin", file_of(roms.build_n64("n64")), "game.bin", "n64",
            expect_method=Method.MAGIC, expect_authoritative=True,
        ),
        # -- Directories ---------------------------------------------------------
        Case("dir_empty", dir_of({}), "empty_dir", None, expect_method=Method.NONE, expect_authoritative=False),
        Case(
            "dir_system_cnf_boot2", dir_of({"SYSTEM.CNF": PS2_CNF.encode("ascii")}), "ps2_dir", "ps2",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case(
            "dir_system_cnf_boot", dir_of({"SYSTEM.CNF": PS1_CNF.encode("ascii")}), "ps1_dir", "ps1",
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case("dir_system_cnf_without_boot_key_no_era", dir_of({"SYSTEM.CNF": b"VER = 1.00\r\n"}), "nokey_dir", None),
        Case(
            "dir_windows_xp_installer", dir_of({"XPSP": b""}), "xp_dir", "winxp",
            expect_method=Method.DIRECTORY_MARKER, expect_authoritative=False,
        ),
        # -- Hash index interplay ------------------------------------------------
        Case(
            "hash_sha1_hit_names_ps1", file_of(ps1_hash_bin), "game.bin", "ps1", index=lambda d: fx.write_synthetic_index(d),
            expect_method=Method.HASH_SHA1, expect_authoritative=True,
        ),
        Case(
            "hash_md5_hit_is_not_authoritative", file_of(fx.CAUTION_MD5_CONTENT), "game.bin", "ps1",
            index=lambda d: fx.write_synthetic_index(d),
            expect_method=Method.HASH_MD5, expect_authoritative=False,
        ),
        Case(
            "hash_chd_header_claim_is_not_authoritative", file_of(fx.build_synthetic_chd(fx.CHD_EMBEDDED_SHA1)), "dc.chd",
            "dreamcast", index=lambda d: fx.write_synthetic_index(d),
            expect_method=Method.CHD_HEADER_CLAIM, expect_authoritative=False,
        ),
        Case(
            "hash_index_hit_without_era_falls_through", file_of(ps1_bin), "game.bin", "ps1",
            index=lambda d: index.write_index_v1(
                d / "index.json", [index.entry_for(ps1_bin, title="Eraless (USA)", era=None)],
            ),
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
        Case(
            "hash_wrong_hash_entry_does_not_override", file_of(ps1_bin), "game.bin", "ps1",
            index=lambda d: index.write_index_v1(
                d / "index.json", [index.wrong_hash_entry(ps1_bin, title="Other (USA)", era="dreamcast")],
            ),
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ),
    ]
    for kind in ("invalid_json", "truncated", "not_object", "bad_entry", "empty"):
        cases.append(Case(
            f"hash_corrupt_index_{kind}_falls_back_to_heuristics", file_of(ps1_bin), "game.bin", "ps1",
            index=lambda d, kind=kind: index.write_corrupt_index(d / "index.json", kind),
            expect_method=Method.SYSTEM_CNF, expect_authoritative=False,
        ))
    return cases


# ---------------------------------------------------------------------------
# Zero-byte file for every extension detect() handles
# ---------------------------------------------------------------------------

def detector_extensions() -> frozenset[str]:
    """Extensions detector._detect_file branches on (read from its source) plus every
    extension a magic signature applies to, each with its leading dot."""
    source = textwrap.dedent(inspect.getsource(detector._detect_file))
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "suffix":
            for comparator in node.comparators:
                for sub in ast.walk(comparator):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.startswith("."):
                        found.add(sub.value)
    for sig in magic_detect._SIGNATURES:
        found.update("." + ext for ext in sig["applies_to"])
    return frozenset(found)


# Zero-byte files for which detect() currently returns an era, from extension
# alone. Observed behavior, listed so that fixing one forces a marker removal.
_ZERO_BYTE_WRONG: dict[str, str] = {
    ".img": "F-IMG-SIZE-ONLY",
    ".xiso": "F-EXT-ONLY-EMPTY",
    ".xex": "F-EXT-ONLY-EMPTY",
    ".z64": "F-EXT-ONLY-EMPTY",
    ".n64": "F-EXT-ONLY-EMPTY",
    ".v64": "F-EXT-ONLY-EMPTY",
    ".sfc": "F-EXT-ONLY-EMPTY",
    ".smc": "F-EXT-ONLY-EMPTY",
    ".fig": "F-EXT-ONLY-EMPTY",
    ".swc": "F-EXT-ONLY-EMPTY",
    ".nes": "F-EXT-ONLY-EMPTY",
    ".pkg": "F-EXT-ONLY-EMPTY",
    ".gdi": "F-EXT-ONLY-EMPTY",
    ".cdi": "F-EXT-ONLY-EMPTY",
}


# Method observed for the zero-byte files that correctly get no era; any
# extension not listed here is Method.NONE. Never authoritative (no era).
_ZERO_BYTE_METHOD: dict[str, Method] = {".nds": Method.EXTENSION}


def _zero_byte_cases() -> list[Case]:
    cases = []
    for ext in sorted(detector_extensions()):
        finding = _ZERO_BYTE_WRONG.get(ext)
        cases.append(Case(
            f"zero_byte{ext.replace('.', '_')}", file_of(b""), f"empty{ext}", None,
            (finding,) if finding else (), finding is not None,
            expect_method=None if finding else _ZERO_BYTE_METHOD.get(ext, Method.NONE),
            expect_authoritative=None if finding else False,
        ))
    for case_id, filename in (("zero_byte_no_extension", "empty"), ("zero_byte_unhandled_extension", "empty.txt")):
        cases.append(Case(
            case_id, file_of(b""), filename, None, expect_method=Method.NONE, expect_authoritative=False,
        ))
    return cases


# ---------------------------------------------------------------------------
# Truncated copies, cut at each structural boundary
# ---------------------------------------------------------------------------

def _truncations(
    stem: str, ext: str, data: bytes, cuts: list[int], *, era: Era | None, intact_from: int, base_known_wrong: bool = False,
    method: Method | None = None, authoritative: bool | None = None,
) -> list[Case]:
    """One case per cut length in *cuts* (each shorter than *data*).

    The era is asserted only for cuts at or past *intact_from* (every byte the
    parser reads is still present) and only when the whole-file case is not
    itself known wrong; every other cut just must not fail. *method* and
    *authoritative* are expected on exactly the asserted cuts.
    """
    out = []
    for cut in sorted({c for c in cuts if 0 <= c < len(data)}):
        asserted = not base_known_wrong and cut >= intact_from
        out.append(Case(
            f"trunc_{stem}_at_{cut}", file_of(data[:cut]), f"{stem}{ext}", era if asserted else NOT_ASSERTED,
            expect_method=method if asserted else None,
            expect_authoritative=authoritative if asserted else None,
        ))
    return out


def _truncated_cases() -> list[Case]:
    cases: list[Case] = []

    ps1 = ps_raw(PS1_CNF)
    cnf_end = sectors.user_offset(19, RAW, len(PS1_CNF))
    cases += _truncations(
        "ps1_raw_bin", ".bin", ps1, sectors.iso_boundaries(RAW, image_len=len(ps1)) + [cnf_end - 1, cnf_end],
        era="ps1", intact_from=cnf_end, method=Method.SYSTEM_CNF, authoritative=False,
    )

    sfb = ps3_iso()
    cases += _truncations(
        "ps3_iso", ".iso", sfb, sectors.iso_boundaries("cooked", image_len=len(sfb)), era="ps3", intact_from=19 * 2048,
        method=Method.STRUCTURAL, authoritative=False,
    )

    xbe = xdvdfs_image("DEFAULT.XBE")
    cases += _truncations(
        "xdvdfs_xbe_iso", ".iso", xbe.data, xbe.boundaries() + [xbe.signal_end - 1], era="xbox", intact_from=xbe.structure_end,
        method=Method.MAGIC, authoritative=False,
    )

    gd = chd_image(5, chd.track_entry(chd.TAG_CHGD, track_type="MODE1_RAW"))
    cases += _truncations(
        "chd_v5_chgd", ".chd", gd.data, gd.boundaries() + [gd.meta_header_end(0) - 1],
        era="dreamcast", intact_from=gd.meta_header_end(0), method=Method.STRUCTURAL, authoritative=False,
    )
    v4 = chd_image(4, chd.track_entry(chd.TAG_CHT2))
    cases += _truncations("chd_v4_cht2", ".chd", v4.data, v4.boundaries(), era=None, intact_from=len(v4.data))

    exe = pe.build_pe32(major_os_version=5)
    cases += _truncations(
        "pe32_os5", ".exe", exe, [0, 1, 2, 0x20, 0x3C, 0x40, 0x80, 0x84, 0x98, 0xC0, 0xDF, 0xE0, 0xE1, 0x1FF],
        era="winxp", intact_from=0x80 + 96, method=Method.PE_HEADER, authoritative=False,
    )

    nes = roms.build_ines()
    cases += _truncations(
        "ines_bin", ".bin", nes, [0, 1, 2, 3, 4, 8, 15, 16, 17], era="nes", intact_from=4,
        method=Method.MAGIC, authoritative=True,
    )

    n64 = roms.build_n64("z64")
    cases += _truncations(
        "n64_bin", ".bin", n64, [0, 1, 2, 3, 4, 0x20, 0x3F, 0x40, 0x41], era="n64", intact_from=4,
        method=Method.MAGIC, authoritative=True,
    )
    return cases


CASES: tuple[Case, ...] = tuple(_hand_written() + _zero_byte_cases() + _truncated_cases())
