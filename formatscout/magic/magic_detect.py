import logging
import struct
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from ..constants import ISO_LOGICAL_SECTOR_BYTES, ROOT_DIR_READ_CAP_BYTES
from ..iso9660_dir import iter_dir_records

if TYPE_CHECKING:
    from ..result import Method

logger = logging.getLogger(__name__)

_TOML_PATH = Path(__file__).parent / "magic_signatures.toml"

# Raw Mode 2 CD geometry: each physical sector is 2352 bytes, of which the
# first 24 are sync/header and the next ISO_LOGICAL_SECTOR_BYTES are the user
# data an ISO 9660 structure actually lives in.
_MODE2_SECTOR_BYTES = 2352
_MODE2_DATA_OFFSET = 24

with _TOML_PATH.open("rb") as _f:
    _RAW = tomllib.load(_f)


# The two reasons detect_from_magic() returns when the generic CD-ROM sync
# signature was resolved through SYSTEM.CNF rather than by a platform magic.
# magic_tags() keys on these exact strings.
_SYSTEM_CNF_PS2_REASON = "CD-ROM sector sync matched; SYSTEM.CNF BOOT2 key indicates PS2"
_SYSTEM_CNF_PS1_REASON = "CD-ROM sector sync matched; SYSTEM.CNF BOOT key indicates PS1"


def _parse_magic(hex_str: str) -> bytes:
    return bytes(int(b, 16) for b in hex_str.split())


_SIGNATURES: list[dict] = [
    {
        "era": s["era"],
        "offset": s["offset"],
        "magic_bytes": _parse_magic(s["magic"]),
        "reason": s["reason"],
        "applies_to": s["applies_to"],
    }
    for s in _RAW.get("signatures", [])
]


# SYSTEM.CNF is a few short KEY = VALUE lines. Every reader (raw Mode 2,
# extracted file, plain ISO 9660 in iso_detect) reads at most this many bytes.
SYSTEM_CNF_READ_CAP_BYTES = 512


def classify_system_cnf(content: str) -> str:
    """Classify SYSTEM.CNF text by strict key match: "ps2", "ps1" or "unknown".

    Shared by every SYSTEM.CNF reader (raw Mode 2 .bin, extracted file in a
    directory, plain ISO 9660 in iso_detect.py). Each line is split at its
    first "=", and the key is the text before it with surrounding whitespace
    removed, compared exactly (case-sensitive):

    - a line whose key is BOOT2 means "ps2" (wins over a BOOT line);
    - otherwise a line whose key is BOOT means "ps1";
    - anything else (empty or garbage content, a line with no "=", a key such
      as BOOTX or XBOOT2, BOOT2 appearing only inside a value) is "unknown".

    "unknown" is no signal, never a PS1 default.
    """
    has_boot = False
    for line in content.splitlines():
        key, sep, _value = line.partition("=")
        if not sep:
            continue
        key = key.strip(" \t\x00﻿")
        if key == "BOOT2":
            return "ps2"
        if key == "BOOT":
            has_boot = True
    return "ps1" if has_boot else "unknown"


def resolve_ps_generation_from_file(cnf_path: Path) -> str:
    """
    Classify PS1 vs PS2 from an already-extracted SYSTEM.CNF file on disk.

    Used for directory-based items: the file is directly readable, no CD
    sector arithmetic needed. Uses the same strict key rule as every other
    SYSTEM.CNF reader, see classify_system_cnf().

    Documented internal API: called from directory_detect.py, not just
    within this module, so it is not underscore-prefixed despite not being
    part of the public formatscout.__init__ surface.

    Reads the first SYSTEM_CNF_READ_CAP_BYTES bytes and returns "ps2" for a
    BOOT2 key, "ps1" for a BOOT key, and "unknown" when neither key is
    present (including an empty or garbage file) or the file cannot be
    opened or read. Callers must treat "unknown" as no signal, not as PS1.
    """
    try:
        with cnf_path.open("rb") as fh:
            content = fh.read(SYSTEM_CNF_READ_CAP_BYTES).decode("ascii", errors="replace")
        return classify_system_cnf(content)
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to read SYSTEM.CNF at %s: %s", cnf_path, exc)
        return "unknown"


def _read_mode2_user_data(fh: BinaryIO, start_lba: int, length: int) -> bytes:
    """Read *length* bytes of logical user data starting at *start_lba* from a
    raw Mode 2 image, one physical sector at a time.

    Logical data is not contiguous on a raw CD image:
    - Each _MODE2_SECTOR_BYTES-byte sector carries only
      ISO_LOGICAL_SECTOR_BYTES of payload, behind a _MODE2_DATA_OFFSET-byte
      sync/header.
    - A straight-through read would splice sync bytes into the buffer and
      garble every directory record past the first sector.

    Callers must cap *length* themselves. See ROOT_DIR_READ_CAP_BYTES.
    """
    chunks: list[bytes] = []
    remaining = length
    lba = start_lba
    while remaining > 0:
        fh.seek(lba * _MODE2_SECTOR_BYTES + _MODE2_DATA_OFFSET)
        chunk = fh.read(min(remaining, ISO_LOGICAL_SECTOR_BYTES))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
        lba += 1
    return b"".join(chunks)


def _resolve_ps_generation(path: Path) -> str:
    """Classify PS1 vs PS2 from a raw CD-ROM sector read.

    Returns "unknown" when the PVD, the root directory, or the SYSTEM.CNF
    entry cannot be read or located. Once SYSTEM.CNF is read, it is
    classified by classify_system_cnf(): "ps2" for a BOOT2 key, "ps1" for a
    BOOT key, "unknown" when neither key is present (including empty or
    garbage content). A SYSTEM.CNF entry with size 0 is read as
    SYSTEM_CNF_READ_CAP_BYTES bytes.

    The sync pattern that gates this call is a generic Mode 2 CD-ROM
    marker. It is not proof the disc is a PlayStation title. Callers must
    treat "unknown" as no signal, not default to PS1.
    """
    try:
        with path.open("rb") as fh:
            pvd = _read_mode2_user_data(fh, 16, ISO_LOGICAL_SECTOR_BYTES)
            if len(pvd) < 190 or pvd[0] != 1:
                return "unknown"

            root_lba = struct.unpack_from("<I", pvd, 158)[0]
            root_size = struct.unpack_from("<I", pvd, 166)[0]
            if root_lba == 0 or root_size == 0:
                return "unknown"

            # root_size is a 32-bit field read straight out of an untrusted
            # image, so it can declare up to 4 GB. Cap it exactly as
            # iso_detect._read_root_dir does before allocating anything.
            dir_data = _read_mode2_user_data(
                fh, root_lba, min(root_size, ROOT_DIR_READ_CAP_BYTES),
            )

            system_cnf_lba = None
            system_cnf_size = 0
            for rec in iter_dir_records(dir_data):
                if rec.name == "SYSTEM.CNF":
                    system_cnf_lba = rec.lba
                    system_cnf_size = rec.size
                    break

            if system_cnf_lba is None:
                return "unknown"

            raw_cnf = _read_mode2_user_data(
                fh, system_cnf_lba, min(system_cnf_size or SYSTEM_CNF_READ_CAP_BYTES, SYSTEM_CNF_READ_CAP_BYTES),
            )
            return classify_system_cnf(raw_cnf.decode("ascii", errors="replace"))
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to resolve PS generation from raw CD sectors of %s: %s", path, exc)
        return "unknown"


def detect_from_magic(path: Path, extension: str) -> tuple[str | None, str]:
    try:
        applicable = [s for s in _SIGNATURES if extension in s["applies_to"]]
        checked: set[tuple[int, bytes]] = set()

        with path.open("rb") as fh:
            for sig in applicable:
                key = (sig["offset"], sig["magic_bytes"])
                if key in checked:
                    continue
                checked.add(key)
                fh.seek(sig["offset"])
                data = fh.read(len(sig["magic_bytes"]))
                if data == sig["magic_bytes"]:
                    if sig["era"] == "cdrom_sync_ambiguous":
                        resolved = _resolve_ps_generation(path)
                        if resolved == "ps2":
                            return "ps2", _SYSTEM_CNF_PS2_REASON
                        if resolved == "ps1":
                            return "ps1", _SYSTEM_CNF_PS1_REASON
                        # "unknown": the sync pattern is a generic Mode 2 marker,
                        # not a match. continue, not return: a later .bin
                        # signature (Dreamcast, N64, NES) still needs a chance
                        # to match.
                        continue
                    return sig["era"], sig["reason"]

        return None, ""
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        # Same (None, "") return as the "no signature matched" case above,
        # deliberately: callers already treat that as "no signal" and adding
        # a distinct return shape here would ripple through every caller for
        # a difference only useful for debugging. The debug log is what
        # actually distinguishes the two: a read/parse failure logs, a clean
        # no-match does not.
        logger.debug("Failed to read %s while matching magic signatures: %s", path, exc)
        return None, ""


def magic_tags(reason: str) -> tuple["Method", bool]:
    """(method, authoritative) for a detect_from_magic() hit, given its reason.

    A hit resolved through SYSTEM.CNF (the generic Mode 2 sync pattern plus
    a strict BOOT/BOOT2 key match) is Method.SYSTEM_CNF and not
    authoritative: the sync pattern that gates the read is not
    PlayStation-specific, and the raw sector walk does not check the PVD's
    CD001 identifier. Every other hit is a platform-specific signature
    (Dreamcast IP.BIN, N64, iNES) and is authoritative.

    Callers pass the reason exactly as detect_from_magic() returned it,
    before adding any text of their own.
    """
    # Imported here, not at module level, so this module's import-time
    # dependencies stay constants + iso9660_dir only (test_magic_detect.py
    # imports an isolated copy of it to test TOML parsing at import time).
    from ..result import Method

    if reason in (_SYSTEM_CNF_PS2_REASON, _SYSTEM_CNF_PS1_REASON):
        return Method.SYSTEM_CNF, False
    return Method.MAGIC, True
