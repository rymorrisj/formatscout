"""Minimal ISO 9660 image builder with optional raw-CD sector framing.

Builder only: produces small synthetic images (< 1 MiB) with a fake volume
label. EDC/ECC fields in raw framings are left ZERO, so the images are
structurally parseable but not bit-valid CD sectors.

Layout: LBA 0-15 zeroed system area, 16 PVD, 17 terminator, 18.. root
directory, then each file's extent at consecutive LBAs (each rounded up to
whole 2048-byte sectors).
"""

import re
import struct
from typing import Literal

from formatscout.constants import ISO_LOGICAL_SECTOR_BYTES
from formatscout.tests.smart_media_fixtures import SECTOR

Framing = Literal["cooked", "mode1", "mode2_form1"]

MAX_IMAGE_BYTES = 1024 * 1024
_PVD_LBA = 16
_TERMINATOR_LBA = 17
_ROOT_LBA = 18
_NAME_RE = re.compile(r"^[A-Z0-9_]+\.[A-Z0-9_]*$")
_SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
# Mode 2 Form 1 subheader: file, channel, submode, coding, repeated twice.
# Only submode 0x08 (data) is set on every sector; no EOR/EOF flags.
_SUBHEADER = bytes([0, 0, 0x08, 0]) * 2
_USER_OFFSETS = {"cooked": 0, "mode1": 16, "mode2_form1": 24}
_SECTOR_SIZES = {"cooked": ISO_LOGICAL_SECTOR_BYTES, "mode1": SECTOR, "mode2_form1": SECTOR}


def user_data_offset(framing: Framing) -> int:
    """Offset of the 2048 user-data bytes within one physical sector."""
    return _USER_OFFSETS[framing]


def sector_size(framing: Framing) -> int:
    """Physical bytes per sector (2048 cooked, 2352 raw)."""
    return _SECTOR_SIZES[framing]


def read_user_sector(image: bytes, lba: int, framing: Framing) -> bytes:
    """Return the 2048 user-data bytes of sector *lba*."""
    start = lba * sector_size(framing) + user_data_offset(framing)
    return image[start:start + ISO_LOGICAL_SECTOR_BYTES]


def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _text(value: str, length: int) -> bytes:
    return value.encode("ascii")[:length].ljust(length, b" ")


def _dir_record(ident: bytes, lba: int, size: int, flags: int) -> bytes:
    """Full ECMA-119 directory record (dates zero, pad byte if ident length is even)."""
    length = 33 + len(ident)
    if len(ident) % 2 == 0:
        length += 1
    rec = bytearray(length)
    rec[0] = length
    rec[2:10] = _both32(lba)
    rec[10:18] = _both32(size)
    rec[25] = flags
    rec[28:32] = _both16(1)
    rec[32] = len(ident)
    rec[33:33 + len(ident)] = ident
    return bytes(rec)


def _validate_name(name: str) -> None:
    if len(name) > 30 or not _NAME_RE.match(name):
        raise ValueError(f"invalid ISO 9660 file name: {name!r}")


def _pack_records(records: list[bytes]) -> bytes:
    """Concatenate records, padding so none spans a 2048-byte sector."""
    out = bytearray()
    for rec in records:
        room = ISO_LOGICAL_SECTOR_BYTES - (len(out) % ISO_LOGICAL_SECTOR_BYTES)
        if len(rec) > room:
            out += b"\x00" * room
        out += rec
    return bytes(out).ljust(
        -(-len(out) // ISO_LOGICAL_SECTOR_BYTES) * ISO_LOGICAL_SECTOR_BYTES, b"\x00",
    )


def _sectors(size: int) -> int:
    return -(-size // ISO_LOGICAL_SECTOR_BYTES)


def _msf_bcd(lba: int) -> bytes:
    frames = lba + 150
    minute, second, frame = frames // 4500, (frames // 75) % 60, frames % 75
    return bytes(((v // 10) << 4) | (v % 10) for v in (minute, second, frame))


def _frame(lba: int, user: bytes, framing: Framing) -> bytes:
    if framing == "cooked":
        return user
    header = _SYNC + _msf_bcd(lba)
    if framing == "mode1":
        return header + b"\x01" + user + b"\x00" * 288
    return header + b"\x02" + _SUBHEADER + user + b"\x00" * 280


def build_iso(
    files: dict[str, bytes],
    *,
    volume_id: str = "FSTEST_VOL",
    system_id: str = "",
    publisher: str = "",
    preparer: str = "",
    system_cnf: str | bytes | None = None,
    framing: Framing = "cooked",
) -> bytes:
    """Build a small ISO 9660 image containing *files* in the root directory.

    system_cnf, if given, is added as root file SYSTEM.CNF. framing selects
    2048-byte cooked sectors, raw Mode 1 (user data at offset 16) or raw
    Mode 2 Form 1 (user data at offset 24); raw EDC/ECC bytes are zero.
    Raises ValueError for an invalid/duplicate file name or an image over 1 MiB.
    """
    if framing not in _USER_OFFSETS:
        raise ValueError(f"unknown framing: {framing!r}")
    contents = dict(files)
    if system_cnf is not None:
        if "SYSTEM.CNF" in contents:
            raise ValueError("SYSTEM.CNF given both in files and system_cnf")
        contents["SYSTEM.CNF"] = system_cnf.encode("ascii") if isinstance(system_cnf, str) else system_cnf
    for name in contents:
        _validate_name(name)
    names = sorted(contents)

    def root_records(root_size: int, file_lbas: dict[str, int]) -> list[bytes]:
        recs = [_dir_record(b"\x00", _ROOT_LBA, root_size, 0x02), _dir_record(b"\x01", _ROOT_LBA, root_size, 0x02)]
        for n in names:
            recs.append(_dir_record(f"{n};1".encode("ascii"), file_lbas.get(n, 0), len(contents[n]), 0))
        return recs

    root_sectors = _sectors(len(_pack_records(root_records(0, {}))))
    root_size = root_sectors * ISO_LOGICAL_SECTOR_BYTES
    next_lba = _ROOT_LBA + root_sectors
    file_lbas: dict[str, int] = {}
    for n in names:
        file_lbas[n] = next_lba
        next_lba += _sectors(len(contents[n]))
    total = next_lba

    sectors: dict[int, bytes] = {}
    pvd = bytearray(ISO_LOGICAL_SECTOR_BYTES)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = _text(system_id, 32)
    pvd[40:72] = _text(volume_id, 32)
    pvd[80:88] = _both32(total)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(ISO_LOGICAL_SECTOR_BYTES)
    pvd[156:190] = _dir_record(b"\x00", _ROOT_LBA, root_size, 0x02)
    pvd[318:446] = _text(publisher, 128)
    pvd[446:574] = _text(preparer, 128)
    pvd[881] = 1
    sectors[_PVD_LBA] = bytes(pvd)
    sectors[_TERMINATOR_LBA] = (b"\xff" + b"CD001" + b"\x01").ljust(ISO_LOGICAL_SECTOR_BYTES, b"\x00")

    root = _pack_records(root_records(root_size, file_lbas))
    for i in range(root_sectors):
        sectors[_ROOT_LBA + i] = root[i * ISO_LOGICAL_SECTOR_BYTES:(i + 1) * ISO_LOGICAL_SECTOR_BYTES]
    for n in names:
        data = contents[n].ljust(_sectors(len(contents[n])) * ISO_LOGICAL_SECTOR_BYTES, b"\x00")
        for i in range(len(data) // ISO_LOGICAL_SECTOR_BYTES):
            sectors[file_lbas[n] + i] = data[i * ISO_LOGICAL_SECTOR_BYTES:(i + 1) * ISO_LOGICAL_SECTOR_BYTES]

    if total * sector_size(framing) > MAX_IMAGE_BYTES:
        raise ValueError("synthetic image would exceed 1 MiB")
    blank = bytes(ISO_LOGICAL_SECTOR_BYTES)
    return b"".join(_frame(lba, sectors.get(lba, blank), framing) for lba in range(total))
