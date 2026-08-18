import struct
import tomllib
from pathlib import Path
from typing import BinaryIO

from ..constants import ISO_LOGICAL_SECTOR_BYTES, ROOT_DIR_READ_CAP_BYTES
from ..iso9660_dir import iter_dir_records

_TOML_PATH = Path(__file__).parent / "magic_signatures.toml"

# Raw Mode 2 CD geometry: each physical sector is 2352 bytes, of which the
# first 24 are sync/header and the next ISO_LOGICAL_SECTOR_BYTES are the user
# data an ISO 9660 structure actually lives in.
_MODE2_SECTOR_BYTES = 2352
_MODE2_DATA_OFFSET = 24

with _TOML_PATH.open("rb") as _f:
    _RAW = tomllib.load(_f)


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


def _classify_system_cnf(content: str) -> str:
    return "ps2" if "BOOT2" in content else "ps1"


def resolve_ps_generation_from_file(cnf_path: Path) -> str:
    """
    Classify PS1 vs PS2 from an already-extracted SYSTEM.CNF file on disk.

    Used for directory-based items: the file is directly readable, no CD
    sector arithmetic needed. Uses the same BOOT/BOOT2 marker logic as
    _resolve_ps_generation.

    Documented internal API: called from directory_detect.py, not just
    within this module, so it is not underscore-prefixed despite not being
    part of the public formatscout.__init__ surface.

    Returns "unknown" if the file cannot be read. Never a guessed console.
    Callers must treat "unknown" as no signal, not as PS1.
    """
    try:
        with cnf_path.open("rb") as fh:
            content = fh.read(512).decode("ascii", errors="replace")
        return _classify_system_cnf(content)
    except Exception:
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

    Returns "unknown" whenever SYSTEM.CNF cannot be located or read. Never
    a guessed console.

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
                fh, system_cnf_lba, min(system_cnf_size or 512, 512),
            )
            return _classify_system_cnf(raw_cnf.decode("ascii", errors="replace"))
    except Exception:
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
                            return "ps2", "CD-ROM sector sync matched; SYSTEM.CNF BOOT2 key indicates PS2"
                        if resolved == "ps1":
                            return "ps1", "CD-ROM sector sync matched; SYSTEM.CNF BOOT key indicates PS1"
                        # "unknown": the sync pattern is a generic Mode 2 marker,
                        # not a match. continue, not return: a later .bin
                        # signature (Dreamcast, N64, NES) still needs a chance
                        # to match.
                        continue
                    return sig["era"], sig["reason"]

        return None, ""
    except Exception:
        return None, ""
