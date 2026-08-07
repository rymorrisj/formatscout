"""Shared synthetic fixtures for backend.service.utils.smart_media_detector tests.

Not a test module itself (no test_ prefix, nothing here is collected by pytest).
Plain helper functions/constants, imported directly by test_classify.py and
test_magic_detect.py, following this package's existing convention (see
test_iso_detect.py) of local per-test-file imports over a shared conftest.py.

hash_index.json in production is ~88MB, real DAT-derived data, never to be
loaded directly in a test. Every hash-index-shaped fixture here is a small,
in-memory/tmp_path-only synthetic index built from scratch.
"""

import hashlib
import json
import struct
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Generic hash helpers, mirror hash_lookup.hash_file()'s algorithm exactly
# (sha1/md5 over the full buffer, crc32 masked to unsigned 32-bit hex) so a
# fixture file's real computed hash always matches what's baked into the
# synthetic index below.
# ---------------------------------------------------------------------------


def hashes_for(content: bytes) -> dict[str, str]:
    return {
        "sha1": hashlib.sha1(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
        "crc32": format(zlib.crc32(content) & 0xFFFFFFFF, "08x"),
    }


def _synthetic_sha1(label: str) -> str:
    """Deterministic 40-hex key for an index entry that represents 'a record
    already in the index under some other file's hash', not derived from
    any fixture file's real content, since that's the point of these entries.
    """
    return hashlib.sha1(f"peach1up-synthetic-fixture:{label}".encode()).hexdigest()


def patch_classify_index(monkeypatch, index_path: Path) -> None:
    """Points classify.py's module-level _INDEX_PATH constant at *index_path*
    for the duration of one test.

    classify() has no index-path parameter of its own, unlike
    fuzzy_title_match()/hash_lookup.lookup(), which both take index_path
    directly, classify() always reads its own private _INDEX_PATH module
    constant (pointing at the real hash_index.json). Monkeypatching that
    constant is the only way to run classify() against a synthetic index
    without touching the real 88MB file.
    """
    from backend.service.utils.smart_media_detector import classify as classify_module

    monkeypatch.setattr(classify_module, "_INDEX_PATH", index_path)


def patch_verify_index(monkeypatch, index_path: Path) -> None:
    """Points verify.py's own module-level _INDEX_PATH constant at *index_path*,
    same rationale and pattern as patch_classify_index(). verify.py declares its
    own private _INDEX_PATH separate from classify.py's, so it needs its own patch.
    """
    from backend.service.utils.smart_media_detector import verify as verify_module

    monkeypatch.setattr(verify_module, "_INDEX_PATH", index_path)


def patch_detector_index(monkeypatch, index_path: Path) -> None:
    """Points detector.py's module-level _INDEX_PATH constant at *index_path*,
    same rationale as patch_classify_index()/patch_verify_index(). Needed
    whenever a test drives detect() itself (as opposed to detect_directory()
    or another dispatch target directly) on a directory: detect()'s Tier-1
    hash_lookup.lookup() call reads and caches the real ~88MB hash_index.json
    on first use otherwise. Pointing at a tmp_path with no file at all is the
    normal case here (not a synthetic index), hash_lookup._load_cached()
    raises FileNotFoundError immediately for a missing path, which detect()
    already catches and falls through on, so this is the fast, minimal way to
    isolate a directory-dispatch test from the real index without building one.
    """
    from backend.service.utils.smart_media_detector import detector as detector_module

    monkeypatch.setattr(detector_module, "_INDEX_PATH", index_path)


# ---------------------------------------------------------------------------
# Part 1.1, synthetic hash_index.json (5 entries)
# ---------------------------------------------------------------------------

VERIFIED_CONTENT = b"PEACH1UP_SYNTHETIC_VERIFIED_PS1_DISC"
CAUTION_MD5_CONTENT = b"PEACH1UP_SYNTHETIC_CAUTION_MD5_SOURCE"
CAUTION_CRC32_CONTENT = b"PEACH1UP_SYNTHETIC_CAUTION_CRC32_SOURCE"
UNINDEXED_CONTENT = b"PEACH1UP_SYNTHETIC_UNINDEXED_FILE_NO_HASH_MATCH"

CHD_EMBEDDED_SHA1 = _synthetic_sha1("chd-embedded-rawsha1")
CAUTION_ENTRY_SHA1 = _synthetic_sha1("caution-entry-own-sha1")
TITLE_MATCH_ENTRY_SHA1 = _synthetic_sha1("title-match-entry-own-sha1")
ERA_NONE_TRAP_SHA1 = _synthetic_sha1("era-none-trap-entry-own-sha1")

TITLE_MATCH_INDEXED_TITLE = "Final Fantasy VII (USA)"
# ratio (SequenceMatcher, normalized) vs TITLE_MATCH_INDEXED_TITLE == 0.8750, above 0.80.
TITLE_QUERY_ABOVE_THRESHOLD = "Final Fantasy 7"
# ratio vs TITLE_MATCH_INDEXED_TITLE == 0.6471, below 0.80.
TITLE_QUERY_BELOW_THRESHOLD = "Fantasy Final VII"

ERA_NONE_TRAP_TITLE = "Untracked PC Game (USA)"


def build_synthetic_index() -> dict[str, dict]:
    """Raw dict matching hash_index.json's real schema (verified against
    hash_lookup.py/classify.py and a handful of real entries):
    {sha1_hex: {title, platform, era, source, md5?, crc32?}}.

    Exactly 5 entries:
      1. sha1-only, no md5/crc32 keys at all (mirrors a real record sourced
         from a DAT that only supplied sha1). Drives the "verified" tests.
      2. md5+crc32 populated, own sha1 unrelated to any fixture file's real
         hash. Drives both caution sub-tiers (md5-hit, crc32-hit) via two
         different source files that each collide on exactly one field.
      3. CHD-style, keyed by embedded rawsha1 rather than any file's real
         on-disk hash (chdman wraps/compresses, so a .chd's raw file hash
         never equals the original dump's hash, see chd_validator.py).
      4. title-match entry (era=ps1), used by both the above- and
         below-threshold fuzzy_title_match tests.
      5. era=None trap, a title that fuzzy-matches trivially (it's the
         exact indexed string) but carries no era. Used to prove classify()
         never turns this into a false "mismatch": fuzzy_title_match()
         fails closed on era=None rather than searching every era=None
         record, a real, large bucket in production (e.g. the unmapped
         "IBM - PC compatible" DAT, see README's Current coverage state).
         If that guard were ever removed, this exact shape (matching title,
         no era) is what would start producing a false "mismatch".
    """
    verified_hashes = hashes_for(VERIFIED_CONTENT)
    caution_md5_hashes = hashes_for(CAUTION_MD5_CONTENT)
    caution_crc32_hashes = hashes_for(CAUTION_CRC32_CONTENT)

    return {
        verified_hashes["sha1"]: {
            "title": "Synthetic Verified Game (USA)",
            "platform": "Sony PlayStation",
            "era": "ps1",
            "source": "synthetic-fixture",
        },
        CAUTION_ENTRY_SHA1: {
            "title": "Synthetic Caution Game (USA)",
            "platform": "Sony PlayStation",
            "era": "ps1",
            "source": "synthetic-fixture",
            "md5": caution_md5_hashes["md5"],
            "crc32": caution_crc32_hashes["crc32"],
        },
        CHD_EMBEDDED_SHA1: {
            "title": "Synthetic CHD Disc (USA)",
            "platform": "Sega Dreamcast",
            "era": "dreamcast",
            "source": "synthetic-fixture",
        },
        TITLE_MATCH_ENTRY_SHA1: {
            "title": TITLE_MATCH_INDEXED_TITLE,
            "platform": "Sony PlayStation",
            "era": "ps1",
            "source": "synthetic-fixture",
        },
        ERA_NONE_TRAP_SHA1: {
            "title": ERA_NONE_TRAP_TITLE,
            "platform": None,
            "era": None,
            "source": "synthetic-fixture",
        },
    }


def write_synthetic_index(tmp_path: Path) -> Path:
    index_path = tmp_path / "hash_index.json"
    index_path.write_text(json.dumps(build_synthetic_index()), encoding="utf-8")
    return index_path


def build_synthetic_chd(embedded_sha1_hex: str) -> bytes:
    """Minimal CHD v5 header: real magic + real rawsha1 offset/length, no
    hunk data (extract_embedded_sha1() only reads header bytes).
    """
    raw = bytes.fromhex(embedded_sha1_hex)
    assert len(raw) == 20
    buf = bytearray(100)
    buf[0:8] = b"MComprHD"
    buf[64:84] = raw
    return bytes(buf)


# ---------------------------------------------------------------------------
# Part 1.1b, CHD header and metadata-chain builder, for chd_validator.detect()
# ---------------------------------------------------------------------------
#
# CHD v5 fixed-header field offsets (chd.h, mirrored from chd_validator.py):
#   magic        @0,  8 bytes literal "MComprHD"
#   logicalbytes @32, 8 bytes big-endian uint64 (uncompressed image size)
#   meta_offset  @48, 8 bytes big-endian uint64 (offset of first metadata entry, 0 = none)
#   rawsha1      @64, 20 bytes (all-zero = unset)
#
# A metadata entry is a 16-byte header at its own offset in the file:
#   tag(4) + flags(1)+length(3) packed as one big-endian uint32 + next_offset(8, big-endian uint64)
# chd_validator.detect() only reads the tag and next_offset fields, flags/length
# content is never inspected, so build_chd_metadata_entry() leaves them zeroed.

CHD_HEADER_SIZE = 124  # real CHD v5 header size; only matters as a safe minimum buffer length
CHD_META_ENTRY_LEN = 16
_CHD_MAGIC_FOR_FIXTURES = b"MComprHD"


def build_chd_header(
    *, rawsha1: bytes | None = None, logical_bytes: int = 0, meta_offset: int = 0, size: int = CHD_HEADER_SIZE,
) -> bytearray:
    """Base CHD v5-shaped header buffer, no metadata entries placed yet.

    rawsha1=None leaves the field all-zero (the "unset" case extract_embedded_sha1()
    must treat distinctly from a real hash). size may be extended by the caller to
    make room for metadata entries appended after the header.
    """
    buf = bytearray(max(size, 84))
    buf[0:8] = _CHD_MAGIC_FOR_FIXTURES
    struct.pack_into(">Q", buf, 32, logical_bytes)
    struct.pack_into(">Q", buf, 48, meta_offset)
    if rawsha1 is not None:
        assert len(rawsha1) == 20
        buf[64:84] = rawsha1
    return buf


def build_chd_metadata_entry(tag: bytes, next_offset: int) -> bytes:
    """16-byte metadata entry header: tag(4) + flags/length(4, left zero) + next_offset(8, big-endian).

    tag must be exactly 4 bytes (e.g. b"CHGD", b"CHTR", b"CHT2", or any other
    4-byte value to build an unrecognised-tag entry for chain-termination tests).
    """
    assert len(tag) == 4
    entry = bytearray(CHD_META_ENTRY_LEN)
    entry[0:4] = tag
    struct.pack_into(">Q", entry, 8, next_offset)
    return bytes(entry)


def place_chd_metadata_entry(buf: bytearray, offset: int, tag: bytes, next_offset: int) -> None:
    """Writes a metadata entry into buf at offset. buf must already be long
    enough (extend it via build_chd_header(size=...) or bytearray padding
    before calling this).
    """
    entry = build_chd_metadata_entry(tag, next_offset)
    buf[offset:offset + len(entry)] = entry


# ---------------------------------------------------------------------------
# Part 1.2, synthetic 2352-byte Mode-2 CD sector builder, for
# magic_detect._resolve_ps_generation() / resolve_ps_generation_from_file()
# ---------------------------------------------------------------------------

SECTOR = 2352
DATA_OFF = 24
_ROOT_LBA = 20
_CNF_LBA = 21


def _dir_record(name: bytes, lba: int, size: int) -> bytes:
    """Minimal ISO9660 directory record, only the fields
    magic_detect._resolve_ps_generation() actually reads: record length
    (offset 0), LBA (offset 2, LE), data length (offset 10, LE), file
    identifier length (offset 32), file identifier (offset 33+).
    """
    name_len = len(name)
    rec = bytearray(33 + name_len)
    rec[0] = len(rec)
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into("<I", rec, 10, size)
    rec[32] = name_len
    rec[33:33 + name_len] = name
    return bytes(rec)


def build_ps_disc_bin(
    *, boot_line: str | None, include_pvd: bool = True, include_system_cnf: bool = True,
) -> bytes:
    """Raw Mode-2/2352 BIN image covering sectors 0..21, with a valid ISO9660
    PVD at sector 16 (root dir at sector 20) and, when requested, a
    SYSTEM.CNF entry at sector 21 containing *boot_line*.

    include_pvd=False, no PVD at all (sector 16 left zeroed, byte 0 != 1).
    include_system_cnf=False, PVD present, but root dir has no SYSTEM.CNF
        entry (root dir sector left zeroed).
    """
    buf = bytearray((_CNF_LBA + 1) * SECTOR)
    if not include_pvd:
        return bytes(buf)

    pvd_start = 16 * SECTOR + DATA_OFF
    buf[pvd_start] = 1  # ISO9660 PVD type code
    root_size = 2048
    buf[pvd_start + 158:pvd_start + 162] = struct.pack("<I", _ROOT_LBA)
    buf[pvd_start + 166:pvd_start + 170] = struct.pack("<I", root_size)

    if include_system_cnf:
        cnf_bytes = (boot_line or "").encode("ascii")
        rec = _dir_record(b"SYSTEM.CNF", _CNF_LBA, len(cnf_bytes))
        root_start = _ROOT_LBA * SECTOR + DATA_OFF
        buf[root_start:root_start + len(rec)] = rec

        cnf_start = _CNF_LBA * SECTOR + DATA_OFF
        buf[cnf_start:cnf_start + len(cnf_bytes)] = cnf_bytes

    return bytes(buf)


# ---------------------------------------------------------------------------
# Part 1.3, per-signature fixtures for magic_detect.detect_from_magic(),
# magic bytes transcribed directly from magic_signatures.toml
# ---------------------------------------------------------------------------


def _magic_blob(magic_hex: str, offset: int, total_len: int = 64) -> bytes:
    magic = bytes(int(b, 16) for b in magic_hex.split())
    buf = bytearray(max(total_len, offset + len(magic)))
    buf[offset:offset + len(magic)] = magic
    return bytes(buf)


CDROM_SYNC_AMBIGUOUS_BLOB = _magic_blob("00 FF FF FF FF FF FF FF FF FF FF 00", 0x00)
DREAMCAST_IP_BIN_BLOB = _magic_blob("53 45 47 41 20 53 45 47 41 4B 41 54 41 4E 41", 0x10)
N64_BIG_ENDIAN_BLOB = _magic_blob("80 37 12 40", 0x00)
N64_BYTESWAPPED_BLOB = _magic_blob("37 80 40 12", 0x00)
N64_LITTLE_ENDIAN_BLOB = _magic_blob("40 12 37 80", 0x00)
NES_HEADER_BLOB = _magic_blob("4E 45 53 1A", 0x00)


# ---------------------------------------------------------------------------
# Part 1.4, minimal PE/MZ header builder, for exe_detect.detect_exe()
# ---------------------------------------------------------------------------
#
# Field offsets mirrored from exe_detect.py's own reading code:
#   e_lfanew (PE offset pointer) @0x3C in the MZ header, 4 bytes little-endian
#   PE signature "PE\0\0"        @pe_offset, 4 bytes
#   MajorOperatingSystemVersion  @pe_offset+64, 2 bytes little-endian (IMAGE_OPTIONAL_HEADER)
#   Subsystem                    @pe_offset+92, 2 bytes little-endian
# exe_detect.py requires pe_offset + 96 <= len(header) before reading either
# field, so a too-large pe_offset with no room left is its own branch
# ("garbage PE offset"), distinct from a too-short MZ-only header.


def build_pe_header(
    *,
    mz: bool = True,
    total_len: int = 512,
    pe_offset: int | None = 0x80,
    pe_signature: bytes = b"PE\x00\x00",
    major_os_version: int = 4,
    subsystem: int = 2,
) -> bytes:
    """pe_offset=None builds an MZ-only header (no e_lfanew written at all).
    Use this for the too-short-for-a-PE-offset case by also passing a small
    total_len (< 0x40). Passing a pe_offset that leaves no room for the
    Subsystem/MajorOperatingSystemVersion fields (pe_offset + 96 > total_len)
    builds the "garbage PE offset" case; the PE signature and version fields
    are silently not written in that case since exe_detect.py never reads
    that far.
    """
    buf = bytearray(total_len)
    if mz:
        buf[0:2] = b"MZ"
    if pe_offset is None:
        return bytes(buf)

    struct.pack_into("<I", buf, 0x3C, pe_offset)
    if pe_offset + 96 > total_len:
        return bytes(buf)

    buf[pe_offset:pe_offset + 4] = pe_signature
    struct.pack_into("<H", buf, pe_offset + 64, major_os_version)
    struct.pack_into("<H", buf, pe_offset + 92, subsystem)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Part 2, plain ISO 9660 image builder (2048 bytes/sector, no Mode-2/2352
# raw-CD framing), for iso_detect.detect_from_pvd() / _root_dir_entry_names()
# / _detect_from_xbe_scan(). Distinct from Part 1.2's Mode-2 BIN sector
# builder above: detect_from_pvd() reads a plain .iso file directly at
# 2048-byte sector boundaries (fh.seek(32768) for the PVD sector, root_lba *
# 2048 for the root directory), no 24-byte Mode-2 data offset involved.
#
# Field offsets mirrored from detect_from_pvd()'s own reads exactly:
#   type code   @0            (must be 1 for a PVD)
#   system_id   @8,   32 bytes
#   volume_id   @40,  32 bytes
#   publisher   @318, 128 bytes
#   preparer    @446, 128 bytes
#   root LBA    @158, 4 bytes little-endian (sector number)
#   root size   @166, 4 bytes little-endian (bytes)
# ---------------------------------------------------------------------------

ISO_SECTOR = 2048
_ISO_PVD_SECTOR = 16
_ISO_ROOT_DIR_SECTOR = 20


def _pad_field(value: str, length: int) -> bytes:
    return value.encode("ascii")[:length].ljust(length, b" ")


def build_pvd_iso(
    *,
    system_id: str = "",
    volume_id: str = "",
    publisher: str = "",
    preparer: str = "",
    root_entries: list[str] | None = None,
) -> bytes:
    """Full plain-ISO image covering the PVD sector (16) and, when
    root_entries is given, a root directory sector (20) referenced by the
    PVD's own root LBA/size fields.

    root_entries reuses Part 1.2's _dir_record() builder (rec_len@0,
    name_len@32, name@33+, the only fields _root_dir_entry_names() reads),
    with dummy lba/size of 0 since detect_from_pvd()'s own directory-entry
    checks (PS3_DISC.SFB / .XBE scan) only ever look at the name.

    root_entries=None (the default) leaves root LBA/size at 0, matching a
    disc with no directory data to scan, used for the plain volume-label/
    publisher/preparer keyword-match variants, where the structural checks
    (PS3_DISC.SFB, .xbe scan) must have nothing to match against.
    """
    total_sectors = max(_ISO_ROOT_DIR_SECTOR, _ISO_PVD_SECTOR) + 1
    buf = bytearray(total_sectors * ISO_SECTOR)

    pvd_start = _ISO_PVD_SECTOR * ISO_SECTOR
    buf[pvd_start] = 1
    buf[pvd_start + 8:pvd_start + 40] = _pad_field(system_id, 32)
    buf[pvd_start + 40:pvd_start + 72] = _pad_field(volume_id, 32)
    buf[pvd_start + 318:pvd_start + 446] = _pad_field(publisher, 128)
    buf[pvd_start + 446:pvd_start + 574] = _pad_field(preparer, 128)

    if root_entries:
        root_dir_bytes = bytearray()
        for name in root_entries:
            root_dir_bytes += _dir_record(name.encode("ascii"), 0, 0)
        struct.pack_into("<I", buf, pvd_start + 158, _ISO_ROOT_DIR_SECTOR)
        struct.pack_into("<I", buf, pvd_start + 166, len(root_dir_bytes))
        root_start = _ISO_ROOT_DIR_SECTOR * ISO_SECTOR
        buf[root_start:root_start + len(root_dir_bytes)] = root_dir_bytes

    return bytes(buf)


def write_pvd_iso(path: Path, **kwargs) -> Path:
    """Writes build_pvd_iso(**kwargs)'s bytes to *path* and returns it, for
    tests that need a real on-disk file (detect_from_pvd() takes a Path).
    """
    path.write_bytes(build_pvd_iso(**kwargs))
    return path


# Exact volume-label substring keywords from iso_detect.detect_from_pvd()'s
# own keyword loop, transcribed verbatim so a typo here can't silently make a
# parametrized test pass against the wrong string.
WINXP_VOLUME_KEYWORDS = ("WINDOWS XP", "WINXP", "WXPEVOL", "XP_")
WIN98_VOLUME_KEYWORDS = ("WIN98", "WINDOWS 98", "W98", "MEMPHIS")
WIN95_VOLUME_KEYWORDS = ("WIN95", "WINDOWS 95", "CHICAGO")
DOS_VOLUME_KEYWORDS = ("MSDOS", "MS-DOS", "PCDOS", "FREEDOS")
# Exact publisher/preparer substrings from iso_detect._DOS_PUBLISHERS.
DOS_PUBLISHERS = (
    "GT INTERACTIVE", "ID SOFTWARE", "APOGEE", "3D REALMS", "SIERRA ON-LINE",
    "SIERRA", "ACTIVISION", "MICROPROSE", "LUCASARTS", "INTERPLAY", "BRODERBUND",
)


# ---------------------------------------------------------------------------
# Part 3, PS3/XEX folder-shape builders, for directory_detect.py's
# is_disc_format_folder() / find_eboot() / find_default_xex() /
# resolve_ps3_target() / resolve_xex_target() and the _detect_from_directory()
# dispatch that delegates to them.
# ---------------------------------------------------------------------------

def build_ps3_disc_folder(tmp_path: Path, *, with_eboot: bool = True, name: str = "ps3_disc") -> Path:
    """PS3_DISC.SFB at root, optionally + PS3_GAME/USRDIR/EBOOT.BIN (the
    disc-format dump shape).

    with_eboot=False reproduces the original bug's exact case: PS3_DISC.SFB
    present at the root, but no EBOOT.BIN anywhere under the folder. Before
    the fix, the disc-format branch trusted the SFB marker alone and never
    checked for a resolvable boot file at all.
    """
    folder = tmp_path / name
    folder.mkdir()
    (folder / "PS3_DISC.SFB").write_bytes(b"\x00")
    if with_eboot:
        usrdir = folder / "PS3_GAME" / "USRDIR"
        usrdir.mkdir(parents=True)
        (usrdir / "EBOOT.BIN").write_bytes(b"\x00")
    return folder


def build_ps3_installed_folder(tmp_path: Path, *, name: str = "ps3_installed") -> Path:
    """USRDIR/EBOOT.BIN directly under the folder, no PS3_DISC.SFB, the
    installed/extracted dev_hdd0/game/<TITLE_ID>/ shape.
    """
    folder = tmp_path / name
    usrdir = folder / "USRDIR"
    usrdir.mkdir(parents=True)
    (usrdir / "EBOOT.BIN").write_bytes(b"\x00")
    return folder


def build_non_ps3_folder(tmp_path: Path, *, name: str = "not_ps3") -> Path:
    """Neither PS3_DISC.SFB nor a resolvable EBOOT.BIN present, negative case.

    Uses a .bin filename deliberately: directory_detect._detect_from_directory()
    has a generic "DOS-only extensions" fallback heuristic keyed off a fixed
    extension set ({.exe, .com, .bat, .cfg, .txt, .ini, ""}) that would
    misclassify this folder as era="dos" if given a .txt/.exe/etc. file
    instead, .bin isn't in that set, so this fixture stays a clean "no
    signal" negative case for the PS3/XEX resolvers specifically.
    """
    folder = tmp_path / name
    folder.mkdir()
    (folder / "OTHERFILE.BIN").write_bytes(b"nothing ps3-shaped here")
    return folder


def build_xex_folder(tmp_path: Path, *, xex_names: list[str] | None = None, name: str = "xex_folder") -> Path:
    """Extracted Xbox 360 folder containing the given .xex filenames
    (default: a single "default.xex"). Pass multiple non-"default.xex" names
    to build find_default_xex()'s tie-break/fallback case.
    """
    folder = tmp_path / name
    folder.mkdir()
    for xex_name in (xex_names or ["default.xex"]):
        (folder / xex_name).write_bytes(b"\x00")
    return folder


# ---------------------------------------------------------------------------
# Part 4, minimal No-Intro/Redump-shaped DAT XML builder, for
# hashing/dat_parser.py's parse_dat() and hashing/build_index.py's main().
#
# Schema mirrors parse_dat()'s own reads exactly, verified by reading that
# module directly, not assumed from a generic DAT description:
#   root element (any tag name, parse_dat() never checks it)
#     header/name           -> platform hint (root.find("header").find("name").text)
#     game[@name]            -> game.get("name"), a <game> with no name attribute
#                               at all is skipped (logs a warning), not an error
#       rom[@sha1|@md5|@crc|@crc32] -> a <rom> with none of these four attributes
#                               at all is skipped (logs a warning); parse_dat()
#                               accepts "crc" (Redump's own attribute name) or
#                               "crc32" interchangeably via rom.get("crc") or
#                               rom.get("crc32")
# One record is produced per <rom>, not per <game>. A <game> with two <rom>
# children (a real multi-track Redump shape) yields two records sharing the
# same title/platform/era/source.
# ---------------------------------------------------------------------------

def build_dat_xml(
    *, header_name: str | None = None, games: list[dict] | None = None,
) -> str:
    """games: list of {"name": str, "roms": [dict, ...]} dicts.

    Omit the "name" key entirely (not name=None) to build a <game> with no
    name attribute at all, parse_dat()'s missing-name-skip case. Each entry
    in "roms" is a dict of XML attribute name to value, rendered verbatim
    onto a <rom/> element, an empty dict builds a <rom/> with no hash
    attributes at all, parse_dat()'s no-hash-fields-skip case.
    """
    lines = ["<datafile>"]
    if header_name is not None:
        lines.append(f"  <header><name>{header_name}</name></header>")
    for game in (games or []):
        if "name" in game:
            lines.append(f'  <game name="{game["name"]}">')
        else:
            lines.append("  <game>")
        for rom in game.get("roms", []):
            attrs = " ".join(f'{k}="{v}"' for k, v in rom.items())
            lines.append(f"    <rom {attrs}/>" if attrs else "    <rom/>")
        lines.append("  </game>")
    lines.append("</datafile>")
    return "\n".join(lines)


def write_dat_xml(path: Path, **kwargs) -> Path:
    path.write_text(build_dat_xml(**kwargs), encoding="utf-8")
    return path
