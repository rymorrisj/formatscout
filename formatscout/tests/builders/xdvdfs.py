"""Minimal XDVDFS (Xbox disc filesystem) image builder (builder only).

Layout, in 2048-byte sectors from the start of the image: 0-31 zero, 32 the
volume descriptor (magic at 0x10000, root directory sector and size, FILETIME,
padding, magic again at 0x7EC), 33 the root directory table, then each file's extent. The root directory is a degenerate binary tree (each entry's right
link points to the next name in sorted order). The default executable is
DEFAULT.XBE (original Xbox) or DEFAULT.XEX (Xbox 360).

Real XGD images put this structure at a partition offset behind a video
partition; this builder uses offset 0, which is the layout formatscout reads
(write the image at an XGD partition offset to exercise the unsupported-layout
path). UNVERIFIED against real media: the descriptor fields, the directory
entry layout and the 4-byte child-offset units are the same unverified
description xbox_image.py parses.
"""

import struct
from dataclasses import dataclass

XDVDFS_MAGIC = b"MICROSOFT*XBOX*MEDIA"
SECTOR = 2048
VOLUME_DESCRIPTOR_SECTOR = 32
ROOT_SECTOR = 33
_ATTR_ARCHIVE = 0x20

PAYLOAD_MAGIC = {".XBE": b"XBEH", ".XEX": b"XEX2"}


@dataclass(frozen=True)
class XdvdfsImage:
    """Built image plus the offsets a test needs to cut it at."""

    data: bytes
    magic_offset: int
    tail_magic_offset: int
    root_offset: int
    root_size: int
    file_offsets: dict[str, int]

    def boundaries(self) -> list[int]:
        """Sorted structural byte offsets worth truncating at."""
        points = {
            0, 1, self.magic_offset, self.magic_offset + 1,
            self.magic_offset + len(XDVDFS_MAGIC), self.magic_offset + 28,
            self.tail_magic_offset, self.tail_magic_offset + len(XDVDFS_MAGIC),
            self.root_offset, self.root_offset + 8, self.root_offset + self.root_size,
        }
        for off in self.file_offsets.values():
            points.update({off, off + 4})
        return sorted(p for p in points if p < len(self.data))

    @property
    def signal_end(self) -> int:
        """First cut length at which the 0x10000 magic is fully present."""
        return self.magic_offset + len(XDVDFS_MAGIC)

    @property
    def structure_end(self) -> int:
        """First cut length at which the root directory table is intact."""
        return self.root_offset + self.root_size


def _entry(left: int, right: int, sector: int, size: int, name: str) -> bytes:
    raw = name.encode("ascii")
    body = struct.pack("<HHIIBB", left, right, sector, size, _ATTR_ARCHIVE, len(raw)) + raw
    return body + b"\xff" * (-len(body) % 4)


def build_xdvdfs(
    executable: str = "DEFAULT.XBE",
    *,
    extra_files: dict[str, bytes] | None = None,
    payload_size: int = 256,
) -> XdvdfsImage:
    """Build a tiny XDVDFS image whose root holds *executable* and *extra_files*.

    The executable payload starts with XBEH (.XBE) or XEX2 (.XEX) followed by
    zeros. Names must be ASCII and at most 255 bytes.
    """
    ext = "." + executable.rsplit(".", 1)[-1].upper()
    files: dict[str, bytes] = {executable: PAYLOAD_MAGIC.get(ext, b"\0\0\0\0").ljust(payload_size, b"\0")}
    files.update(extra_files or {})

    names = sorted(files)
    entry_sizes = [len(_entry(0, 0, 0, 0, n)) for n in names]
    offsets = [sum(entry_sizes[:i]) for i in range(len(names))]
    root_size = -(-sum(entry_sizes) // SECTOR) * SECTOR

    lbas: dict[str, int] = {}
    next_lba = ROOT_SECTOR + root_size // SECTOR
    for n in names:
        lbas[n] = next_lba
        next_lba += -(-max(len(files[n]), 1) // SECTOR)

    table = b"".join(
        _entry(0, (offsets[i + 1] // 4) if i + 1 < len(names) else 0, lbas[n], len(files[n]), n)
        for i, n in enumerate(names)
    )
    root = table.ljust(root_size, b"\xff")

    descriptor = bytearray(SECTOR)
    descriptor[0:20] = XDVDFS_MAGIC
    struct.pack_into("<II", descriptor, 20, ROOT_SECTOR, root_size)
    struct.pack_into("<Q", descriptor, 28, 0x01D0000000000000)  # FILETIME, arbitrary fixed value
    tail = SECTOR - len(XDVDFS_MAGIC)
    descriptor[tail:tail + 20] = XDVDFS_MAGIC

    image = bytearray(next_lba * SECTOR)
    image[VOLUME_DESCRIPTOR_SECTOR * SECTOR:(VOLUME_DESCRIPTOR_SECTOR + 1) * SECTOR] = descriptor
    image[ROOT_SECTOR * SECTOR:ROOT_SECTOR * SECTOR + root_size] = root
    for n in names:
        start = lbas[n] * SECTOR
        image[start:start + len(files[n])] = files[n]

    magic_offset = VOLUME_DESCRIPTOR_SECTOR * SECTOR
    return XdvdfsImage(
        data=bytes(image),
        magic_offset=magic_offset,
        tail_magic_offset=magic_offset + tail,
        root_offset=ROOT_SECTOR * SECTOR,
        root_size=root_size,
        file_offsets={n: lbas[n] * SECTOR for n in names},
    )
