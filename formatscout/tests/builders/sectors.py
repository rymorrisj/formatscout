"""Raw CD sector framing helpers (builder only).

Thin, public wrapper over the framing already implemented in iso9660.py (sync
pattern, MSF header, Mode 1 or Mode 2 Form 1 subheader, zeroed EDC/ECC), so
there is exactly one implementation of the framing bytes. Use these when a
test needs framed sectors that are not an ISO 9660 image, or needs to know
where the structural boundaries of a framed image lie.
"""

from collections.abc import Iterable

from formatscout.constants import ISO_LOGICAL_SECTOR_BYTES
from formatscout.tests.builders.iso9660 import (
    _SYNC,
    Framing,
    _frame,
    sector_size,
    user_data_offset,
)

CD_SYNC = _SYNC  # 12 bytes: 00, ten FF, 00
SYNC_LEN = len(CD_SYNC)
HEADER_END = 16  # sync (12) + MSF (3) + mode (1)


def frame_sectors(user_sectors: Iterable[bytes], framing: Framing, *, first_lba: int = 0) -> bytes:
    """Frame consecutive 2048-byte user sectors starting at *first_lba*.

    Raises ValueError for a user sector that is not exactly 2048 bytes.
    """
    out = []
    for lba, user in enumerate(user_sectors, start=first_lba):
        if len(user) != ISO_LOGICAL_SECTOR_BYTES:
            raise ValueError(f"user sector {lba} is {len(user)} bytes, expected {ISO_LOGICAL_SECTOR_BYTES}")
        out.append(_frame(lba, user, framing))
    return b"".join(out)


def sector_boundaries(lba: int, framing: Framing) -> list[int]:
    """Byte offsets of the structural edges of physical sector *lba*.

    Cooked sectors have only their start; raw sectors also have the end of the
    sync pattern, the end of the header, the start of user data and the start
    of the next sector.
    """
    size = sector_size(framing)
    start = lba * size
    if framing == "cooked":
        return [start, start + size]
    return [start, start + SYNC_LEN, start + HEADER_END, start + user_data_offset(framing), start + size]


def user_offset(lba: int, framing: Framing, offset: int = 0) -> int:
    """Absolute file offset of byte *offset* of sector *lba*'s user data."""
    return lba * sector_size(framing) + user_data_offset(framing) + offset


# In-sector user-data offsets worth cutting at, per ISO 9660 sector role.
_PVD_USER_OFFSETS = (1, 6, 8, 40, 158, 166, 318, 574)
_ROOT_USER_OFFSETS = (33, 34, 68)


def iso_boundaries(framing: Framing, *, file_lbas: tuple[int, ...] = (19,), image_len: int | None = None) -> list[int]:
    """Sorted structural byte offsets of an image made by iso9660.build_iso.

    Covers sector 0 (system area), the PVD (16), terminator (17), root
    directory (18) and the given file extents. Offsets at or past *image_len*
    are dropped. For a small image with a single file the file extent is
    LBA 19.
    """
    points: set[int] = set()
    for lba in (0, 16, 17, 18, *file_lbas):
        points.update(sector_boundaries(lba, framing))
    for off in _PVD_USER_OFFSETS:
        points.add(user_offset(16, framing, off))
    for off in _ROOT_USER_OFFSETS:
        points.add(user_offset(18, framing, off))
    for lba in file_lbas:
        points.update({user_offset(lba, framing, 1), user_offset(lba, framing, 16)})
    return sorted(p for p in points if image_len is None or p < image_len)
