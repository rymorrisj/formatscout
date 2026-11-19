"""CHD container builder, versions 4 and 5 (builder only).

Produces small, structurally plausible CHD files: header, an uncompressed hunk
map, zero-filled hunk data, then a metadata chain. No compression is
implemented; the images are meant to be parsed by header/metadata readers
(chd_validator reads the v5 header offsets: logicalbytes @32, metaoffset @48,
rawsha1 @64, and walks the metadata chain by its 16-byte entry headers).

Header layouts:
  v5 (124 bytes): tag(8) length(4) version(4) compressors(16) logicalbytes(8)
      mapoffset(8) metaoffset(8) hunkbytes(4) unitbytes(4) rawsha1(20)
      sha1(20) parentsha1(20). Four zero compressors mean the map is a plain
      array of big-endian u32 hunk numbers.
  v4 (108 bytes): tag(8) length(4) version(4) flags(4) compression(4)
      totalhunks(4) logicalbytes(8) metaoffset(8) hunkbytes(4) sha1(20)
      parentsha1(20) rawsha1(20). The map is 16 bytes per hunk.
v4 fields sit at different offsets than v5, which is exactly what makes a v4
file interesting to a parser that assumes the v5 layout.

Metadata entry: tag(4) flags(1)+length(3) as one big-endian u32, next
offset(8), then the payload. Payloads here are NUL-terminated text in the
formats chdman writes.
"""

import struct
from dataclasses import dataclass

CHD_MAGIC = b"MComprHD"
V5_HEADER_LEN = 124
V4_HEADER_LEN = 108
META_HEADER_LEN = 16
CD_FRAME_BYTES = 2448  # 2352 sector + 96 subcode
DEFAULT_HUNK_BYTES = CD_FRAME_BYTES * 2

TAG_CHT2 = b"CHT2"  # CD track (current)
TAG_CHTR = b"CHTR"  # CD track (old)
TAG_CHGD = b"CHGD"  # GD-ROM track (Dreamcast)
TAG_CHGT = b"CHGT"  # GD-ROM track (old)
TAG_CHCD = b"CHCD"  # CD (oldest tag, binary payload)
TAG_DVD = b"DVD "   # DVD marker

_MDFLAG_CHECKSUM = 0x01


@dataclass(frozen=True)
class MetaEntry:
    """One metadata chain entry. *payload* is stored verbatim."""

    tag: bytes
    payload: bytes = b""
    flags: int = _MDFLAG_CHECKSUM

    def __post_init__(self) -> None:
        if len(self.tag) != 4:
            raise ValueError(f"metadata tag must be 4 bytes, got {self.tag!r}")


def track_entry(
    tag: bytes = TAG_CHT2, *, track: int = 1, track_type: str = "MODE2_RAW", frames: int = 300,
) -> MetaEntry:
    """A CD or GD-ROM track metadata entry with a chdman-style text payload."""
    base = f"TRACK:{track} TYPE:{track_type} SUBTYPE:NONE FRAMES:{frames}"
    if tag == TAG_CHTR:
        text = base
    elif tag in (TAG_CHGD, TAG_CHGT):
        text = f"{base} PAD:0 PREGAP:0 PGTYPE:{track_type} PGSUB:NONE POSTGAP:0"
    elif tag == TAG_CHT2:
        text = f"{base} PREGAP:0 PGTYPE:{track_type} PGSUB:NONE POSTGAP:0"
    else:
        raise ValueError(f"not a track tag: {tag!r}")
    return MetaEntry(tag, text.encode("ascii") + b"\x00")


def dvd_entry() -> MetaEntry:
    """The DVD marker entry chdman writes for createdvd images."""
    return MetaEntry(TAG_DVD, b"\x00")


@dataclass(frozen=True)
class ChdImage:
    """Built CHD plus the offsets a test needs to cut it at."""

    data: bytes
    version: int
    header_len: int
    logical_offset: int
    meta_ptr_offset: int
    rawsha1_offset: int
    map_offset: int
    map_end: int
    data_offset: int
    data_end: int
    meta_offsets: tuple[int, ...]
    meta_ends: tuple[int, ...]

    def boundaries(self) -> list[int]:
        """Sorted structural byte offsets worth truncating at."""
        points = {
            0, 1, 8, 12, 16, self.logical_offset, self.logical_offset + 8,
            self.meta_ptr_offset, self.meta_ptr_offset + 8, self.rawsha1_offset,
            self.rawsha1_offset + 20, self.header_len, self.map_offset, self.map_end,
            self.data_offset, self.data_end,
        }
        for start, end in zip(self.meta_offsets, self.meta_ends):
            points.update({start, start + 4, start + 8, start + META_HEADER_LEN, end})
        return sorted(p for p in points if 0 <= p < len(self.data))

    def meta_header_end(self, index: int) -> int:
        """Cut length at which metadata entry *index*'s 16-byte header is whole."""
        return self.meta_offsets[index] + META_HEADER_LEN


def _meta_blob(entries: tuple[MetaEntry, ...], base: int) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
    blob = bytearray()
    starts: list[int] = []
    ends: list[int] = []
    for i, entry in enumerate(entries):
        start = base + len(blob)
        end = start + META_HEADER_LEN + len(entry.payload)
        nxt = end if i + 1 < len(entries) else 0
        blob += entry.tag
        blob += struct.pack(">I", (entry.flags << 24) | len(entry.payload))
        blob += struct.pack(">Q", nxt)
        blob += entry.payload
        starts.append(start)
        ends.append(end)
    return bytes(blob), tuple(starts), tuple(ends)


def build_chd(
    *,
    version: int = 5,
    metadata: tuple[MetaEntry, ...] = (),
    logical_bytes: int | None = None,
    hunk_bytes: int = DEFAULT_HUNK_BYTES,
    hunks: int = 1,
    rawsha1: bytes | None = None,
) -> ChdImage:
    """Build a CHD of *version* 4 or 5 with an uncompressed map and *hunks* zero hunks.

    logical_bytes is the size the header declares (defaults to hunks *
    hunk_bytes); it is independent of the real file length so size rules can
    be exercised without large files. rawsha1 is stored where the version's
    layout puts it (all zero when None). Raises ValueError for another version.
    """
    if version not in (4, 5):
        raise ValueError(f"unsupported CHD version: {version}")
    if rawsha1 is not None and len(rawsha1) != 20:
        raise ValueError("rawsha1 must be 20 bytes")
    logical = hunks * hunk_bytes if logical_bytes is None else logical_bytes
    raw = rawsha1 or bytes(20)

    if version == 5:
        header_len = V5_HEADER_LEN
        map_offset = header_len
        map_end = map_offset + 4 * hunks
        data_offset = -(-map_end // hunk_bytes) * hunk_bytes
        data_end = data_offset + hunks * hunk_bytes
        logical_offset, meta_ptr_offset, rawsha1_offset = 32, 48, 64
    else:
        header_len = V4_HEADER_LEN
        map_offset = header_len
        map_end = map_offset + 16 * hunks
        data_offset = map_end
        data_end = data_offset + hunks * hunk_bytes
        logical_offset, meta_ptr_offset, rawsha1_offset = 28, 36, 88

    meta, starts, ends = _meta_blob(tuple(metadata), data_end)
    first_meta = starts[0] if starts else 0

    buf = bytearray(data_end)
    buf[0:8] = CHD_MAGIC
    struct.pack_into(">II", buf, 8, header_len, version)
    struct.pack_into(">Q", buf, logical_offset, logical)
    struct.pack_into(">Q", buf, meta_ptr_offset, first_meta)
    buf[rawsha1_offset:rawsha1_offset + 20] = raw
    if version == 5:
        struct.pack_into(">Q", buf, 40, map_offset)
        struct.pack_into(">II", buf, 56, hunk_bytes, CD_FRAME_BYTES)
        for i in range(hunks):
            struct.pack_into(">I", buf, map_offset + 4 * i, data_offset // hunk_bytes + i)
    else:
        struct.pack_into(">III", buf, 16, 0, 0, hunks)  # flags, compression none, totalhunks
        struct.pack_into(">I", buf, 44, hunk_bytes)
        for i in range(hunks):
            # offset(8) crc32(4) length(2) flags(1)=uncompressed type, pad(1)
            struct.pack_into(">QIHBx", buf, map_offset + 16 * i, data_offset + i * hunk_bytes, 0, hunk_bytes & 0xFFFF, 2)
    return ChdImage(
        data=bytes(buf) + meta,
        version=version,
        header_len=header_len,
        logical_offset=logical_offset,
        meta_ptr_offset=meta_ptr_offset,
        rawsha1_offset=rawsha1_offset,
        map_offset=map_offset,
        map_end=map_end,
        data_offset=data_offset,
        data_end=data_end,
        meta_offsets=starts,
        meta_ends=ends,
    )
