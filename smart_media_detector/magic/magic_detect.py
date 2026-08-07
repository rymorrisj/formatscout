import struct
import tomllib
from pathlib import Path

_TOML_PATH = Path(__file__).parent / "magic_signatures.toml"

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
    Classify PS1 vs PS2 from an already-extracted SYSTEM.CNF file on disk
    (directory-based items — no CD sector arithmetic needed since the file
    is directly readable). Same BOOT/BOOT2 marker logic as _resolve_ps_generation.

    Returns "unknown" (never a guessed console) if the file cannot be read.
    Callers must treat "unknown" as no signal, not as PS1.
    """
    try:
        with cnf_path.open("rb") as fh:
            content = fh.read(512).decode("ascii", errors="replace")
        return _classify_system_cnf(content)
    except Exception:
        return "unknown"


def _resolve_ps_generation(path: Path) -> str:
    """Classify PS1 vs PS2 from a raw CD-ROM sector read.

    Returns "unknown" (never a guessed console) whenever SYSTEM.CNF cannot be
    located or read. The sync pattern that gates this call is a generic
    Mode 2 CD-ROM marker, not proof the disc is a PlayStation title at all,
    so callers must treat "unknown" as no signal rather than default to PS1.
    """
    # Mode 2 raw BIN: 2352-byte sectors, data payload starts at byte 24
    SECTOR = 2352
    DATA_OFF = 24
    try:
        with path.open("rb") as fh:
            fh.seek(16 * SECTOR + DATA_OFF)
            pvd = fh.read(2048)
            if len(pvd) < 190 or pvd[0] != 1:
                return "unknown"

            root_lba = struct.unpack_from("<I", pvd, 158)[0]
            root_size = struct.unpack_from("<I", pvd, 166)[0]

            fh.seek(root_lba * SECTOR + DATA_OFF)
            dir_data = fh.read(root_size)

            system_cnf_lba = None
            system_cnf_size = 0
            i = 0
            while i < len(dir_data):
                rec_len = dir_data[i]
                if rec_len == 0:
                    i += 1
                    continue
                if i + 33 > len(dir_data):
                    break
                name_len = dir_data[i + 32]
                if i + 33 + name_len > len(dir_data):
                    break
                name = dir_data[i + 33: i + 33 + name_len].decode("ascii", errors="replace")
                name = name.split(";")[0]
                if name.upper() == "SYSTEM.CNF":
                    system_cnf_lba = struct.unpack_from("<I", dir_data, i + 2)[0]
                    system_cnf_size = struct.unpack_from("<I", dir_data, i + 10)[0]
                    break
                i += rec_len

            if system_cnf_lba is None:
                return "unknown"

            fh.seek(system_cnf_lba * SECTOR + DATA_OFF)
            content = fh.read(min(system_cnf_size or 512, 512)).decode("ascii", errors="replace")
            return _classify_system_cnf(content)
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
                        # resolved == "unknown": sync pattern alone doesn't prove
                        # PS1/PS2 (it's a generic Mode 2 CD-ROM marker) and
                        # SYSTEM.CNF couldn't confirm which, so stop treating this
                        # signature as a match and keep evaluating the rest.
                        # Returning here instead would abandon every later
                        # signature that also applies to this extension, which for
                        # .bin means the Dreamcast IP.BIN magic at 0x10 plus the
                        # N64 and NES entries never get tested at all.
                        continue
                    return sig["era"], sig["reason"]

        return None, ""
    except Exception:
        return None, ""
