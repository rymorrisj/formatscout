"""Shared ISO 9660 directory-record parsing.

Used by iso_detect.py's plain-ISO root-directory walk and
magic.magic_detect.py's raw Mode 2 CD-ROM equivalent (the two callers pass in
dir_data read very differently, plain 2048-byte-sector file reads versus
de-interleaved Mode 2 payload bytes, but both have already reduced it to the
same flat, logical-sector-aligned record layout by the time it reaches here).
"""

import struct
from dataclasses import dataclass

from .constants import ISO_LOGICAL_SECTOR_BYTES


@dataclass(frozen=True, slots=True)
class DirRecord:
    name: str
    lba: int
    size: int


def iter_dir_records(dir_data: bytes):
    """Walk raw ISO 9660 directory-record bytes, yielding a DirRecord per
    entry (name upper-cased, ";version" suffix stripped).

    A record length of 0 means padding to the next
    ISO_LOGICAL_SECTOR_BYTES-byte logical sector boundary (ECMA-119:
    directory records never span a sector), not end of data, so parsing
    resumes at the next sector rather than stopping. A record whose declared
    length would read past the end of dir_data stops parsing cleanly instead
    of raising or reading garbage.
    """
    i = 0
    while i < len(dir_data):
        rec_len = dir_data[i]
        if rec_len == 0:
            i = (i | (ISO_LOGICAL_SECTOR_BYTES - 1)) + 1
            continue
        if i + 33 > len(dir_data):
            break
        name_len = dir_data[i + 32]
        if i + 33 + name_len > len(dir_data):
            break
        lba = struct.unpack_from("<I", dir_data, i + 2)[0]
        size = struct.unpack_from("<I", dir_data, i + 10)[0]
        name = dir_data[i + 33: i + 33 + name_len].decode("ascii", errors="replace")
        yield DirRecord(name=name.split(";")[0].upper(), lba=lba, size=size)
        i += rec_len
