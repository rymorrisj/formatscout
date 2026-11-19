"""Internal Xbox optical-media identification, used only by iso_detect.py's
detect_iso(). Not part of this package's public surface, see __init__.py and
README.md, the extract-xiso signal this module produces reaches callers only
through ScanResult.requires_extraction on the standard detect()/classify()
result objects, never by importing this module directly.

Recognised layouts:

- "xiso": an XDVDFS volume whose descriptor sits at 0x10000 from the start of
  the file (a trimmed/rebuilt xISO). The descriptor is checked (20-byte
  magic, root directory sector and size) and the root directory table is
  walked, bounded, for DEFAULT.XBE (original Xbox) or DEFAULT.XEX (Xbox 360).
- "xgd1", "xgd2", "xgd3": the same 20-byte magic found at 0x10000 past one of
  the known XGD game-partition offsets (a full disc image with a video
  partition in front). Only the descriptor is checked; the tree is not
  walked there, iso_detect reports the layout as unsupported.

Anything else, including an ISO 9660 image of any size, is not Xbox media to
this module.

UNVERIFIED against real media: the XDVDFS volume descriptor field offsets,
the directory entry layout and child-offset arithmetic used by
_walk_root_names(), the XGD partition offsets, and the placement of
DEFAULT.XBE/DEFAULT.XEX in the root directory. They follow the synthetic
builder in tests/builders/xdvdfs.py and the commonly published description
of the format (extract-xiso), not a check against real discs.
"""

import logging
import struct
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

XDVDFS_MAGIC = b"MICROSOFT*XBOX*MEDIA"
XDVDFS_SECTOR_BYTES = 2048
# The volume descriptor is sector 32 of the XDVDFS partition. UNVERIFIED.
XDVDFS_DESCRIPTOR_OFFSET = 0x10000

# Volume descriptor fields, after the 20-byte magic. UNVERIFIED.
_ROOT_SECTOR_FIELD = 20  # u32 LE, root directory table start sector
_ROOT_SIZE_FIELD = 24  # u32 LE, root directory table size in bytes
_DESCRIPTOR_HEAD_BYTES = 28

# Start of the XDVDFS game partition in full XGD disc images, as published by
# extract-xiso. UNVERIFIED against real media.
XGD_PARTITION_OFFSETS: tuple[tuple[str, int], ...] = (
    ("xgd1", 0x18300000),
    ("xgd2", 0x0FD90000),
    ("xgd3", 0x02080000),
)

_ISO9660_MAGIC = b"CD001"
_ISO9660_OFFSET = 0x8001

# Directory entry, UNVERIFIED: u16 left child, u16 right child (both in
# 4-byte units from the start of the directory table, 0 = none), u32 start
# sector, u32 file size, u8 attributes, u8 name length, then the name. Unused
# table space is 0xFF filled, so a 0xFFFF child offset is padding, not a link.
_ENTRY = struct.Struct("<HHIIBB")
_CHILD_UNIT_BYTES = 4
_PAD_SHORT = 0xFFFF

# Bounds on the root directory walk. The table size is a 32-bit field read
# from an untrusted image, so the read is capped; the tree links are
# untrusted too, so the walk visits each offset at most once and stops at
# both an entry cap and a depth cap. Real root directories hold a few dozen
# entries; the depth cap leaves room for a fully degenerate (list-shaped)
# tree of that size.
XDVDFS_ROOT_READ_CAP_BYTES = 64 * 1024
XDVDFS_MAX_ENTRIES = 4096
XDVDFS_MAX_DEPTH = 256


@dataclass(frozen=True, slots=True)
class XboxProbe:
    """What probe_xbox_image() found.

    layout: "xiso" or one of the XGD_PARTITION_OFFSETS names.
    partition_offset: byte offset of the XDVDFS partition in the file.
    descriptor_valid: the root sector and size fields are non-zero and the
        root table starts inside the file.
    root_names: upper-cased root entry names (walked for "xiso" only).
    walk_truncated: the table read or the walk hit a cap.
    """
    layout: str
    partition_offset: int
    descriptor_valid: bool
    root_names: frozenset[str] = frozenset()
    walk_truncated: bool = False


def _walk_root_names(table: bytes) -> tuple[frozenset[str], bool]:
    """Collect entry names from an XDVDFS directory table (binary tree rooted
    at offset 0). Returns (names, truncated). Never raises on malformed data.

    Bounded: each offset is visited once (cycles end), at most
    XDVDFS_MAX_ENTRIES entries are visited, and children deeper than
    XDVDFS_MAX_DEPTH are not followed. Hitting either cap sets truncated.
    """
    names: set[str] = set()
    truncated = False
    seen: set[int] = set()
    stack: list[tuple[int, int]] = [(0, 0)]
    while stack:
        offset, depth = stack.pop()
        if offset in seen:
            continue
        if len(seen) >= XDVDFS_MAX_ENTRIES or depth > XDVDFS_MAX_DEPTH:
            truncated = True
            continue
        seen.add(offset)
        if offset + _ENTRY.size > len(table):
            continue
        left, right, _sector, _size, _attributes, name_len = _ENTRY.unpack_from(table, offset)
        if left == _PAD_SHORT and right == _PAD_SHORT:
            continue
        name_end = offset + _ENTRY.size + name_len
        if name_len == 0 or name_end > len(table):
            continue
        names.add(table[offset + _ENTRY.size:name_end].decode("ascii", errors="replace").upper())
        for child in (left, right):
            if child not in (0, _PAD_SHORT):
                stack.append((child * _CHILD_UNIT_BYTES, depth + 1))
    return frozenset(names), truncated


def _root_fields(head: bytes, partition_offset: int, file_size: int) -> tuple[int, int] | None:
    """(root table byte offset, root table size) when the descriptor's root
    fields are usable, else None."""
    if len(head) < _DESCRIPTOR_HEAD_BYTES:
        return None
    root_sector = struct.unpack_from("<I", head, _ROOT_SECTOR_FIELD)[0]
    root_size = struct.unpack_from("<I", head, _ROOT_SIZE_FIELD)[0]
    if root_sector == 0 or root_size == 0:
        return None
    root_offset = partition_offset + root_sector * XDVDFS_SECTOR_BYTES
    if root_offset >= file_size:
        return None
    return root_offset, root_size


def probe_xbox_image(path: Path) -> XboxProbe | None:
    """Look for an XDVDFS volume descriptor at 0x10000 and at 0x10000 past
    each known XGD partition offset. None when no magic matched or the file
    could not be read. Never raises on IO.

    Reads at most _DESCRIPTOR_HEAD_BYTES per candidate offset, plus at most
    XDVDFS_ROOT_READ_CAP_BYTES of root table for an "xiso" layout.
    """
    try:
        with path.open("rb") as fh:
            file_size = fh.seek(0, 2)
            for layout, partition_offset in (("xiso", 0), *XGD_PARTITION_OFFSETS):
                fh.seek(partition_offset + XDVDFS_DESCRIPTOR_OFFSET)
                head = fh.read(_DESCRIPTOR_HEAD_BYTES)
                if head[:len(XDVDFS_MAGIC)] != XDVDFS_MAGIC:
                    continue
                root = _root_fields(head, partition_offset, file_size)
                if root is None or layout != "xiso":
                    return XboxProbe(layout, partition_offset, root is not None)
                root_offset, root_size = root
                fh.seek(root_offset)
                table = fh.read(min(root_size, XDVDFS_ROOT_READ_CAP_BYTES))
                names, truncated = _walk_root_names(table)
                return XboxProbe(
                    layout, partition_offset, True, names,
                    truncated or root_size > XDVDFS_ROOT_READ_CAP_BYTES,
                )
        return None
    except OSError as exc:
        logger.debug("Failed to inspect %s for XDVDFS magic: %s", path, exc)
        return None


def has_iso9660_magic(path: Path) -> bool:
    """True when the ISO 9660 standard identifier "CD001" sits at 0x8001
    (sector 16, byte 1, 2048-byte sectors). Identifies the container only:
    no platform, at any file size. Never raises on IO.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(_ISO9660_OFFSET)
            return fh.read(len(_ISO9660_MAGIC)) == _ISO9660_MAGIC
    except OSError as exc:
        logger.debug("Failed to inspect %s for ISO 9660 magic: %s", path, exc)
        return False
