"""MZ, NE and PE32 executable header builders (builder only).

Field offsets follow the real formats and the ones exe_detect reads:
e_lfanew at 0x3C, "PE\\0\\0" at e_lfanew, MajorOperatingSystemVersion at
e_lfanew + 64 and Subsystem at e_lfanew + 92 (optional header offsets 40 and
68 of a PE32 optional header, which starts at e_lfanew + 24).
"""

import struct

IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

NE_TARGET_OS2 = 1
NE_TARGET_WINDOWS = 2

_DEFAULT_PE_OFFSET = 0x80


def _mz_header(*, lfarlc: int, e_lfanew: int | None) -> bytearray:
    """64-byte DOS header: real MZ fields, e_lfanew optional."""
    hdr = bytearray(0x40)
    hdr[0:2] = b"MZ"
    # cblp, cp, crlc, cparhdr (paragraphs), minalloc, maxalloc, ss, sp, csum, ip, cs, lfarlc, ovno
    struct.pack_into("<13H", hdr, 2, 0x90, 1, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, lfarlc, 0)
    if e_lfanew is not None:
        struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    return hdr


def build_mz_dos(total_len: int = 0x200) -> bytes:
    """Plain DOS MZ executable: header with relocation table pointer 0x1C, no new-header pointer.

    e_lfanew (0x3C) is zero, so there is no "PE" or "NE" signature at offset 0.
    total_len must be at least 0x40.
    """
    if total_len < 0x40:
        raise ValueError("use build_mz_stub() for a header shorter than 0x40 bytes")
    return bytes(_mz_header(lfarlc=0x1C, e_lfanew=None).ljust(total_len, b"\x00"))


def build_mz_stub(total_len: int = 0x1C) -> bytes:
    """Truncated MZ: just the leading DOS header fields, shorter than 0x40 bytes."""
    if not 2 <= total_len < 0x40:
        raise ValueError("stub length must be 2..0x3F")
    return bytes(_mz_header(lfarlc=0x1C, e_lfanew=None)[:total_len])


def build_ne(*, target_os: int = NE_TARGET_WINDOWS, total_len: int = 0x100) -> bytes:
    """16-bit New Executable: MZ header whose e_lfanew points at an "NE" header.

    target_os is the NE target OS byte (1 OS/2, 2 Windows). total_len must
    leave room for the 64-byte NE header region.
    """
    offset = _DEFAULT_PE_OFFSET
    if total_len < offset + 0x40:
        raise ValueError("total_len too small for an NE header")
    buf = _mz_header(lfarlc=0x40, e_lfanew=offset).ljust(total_len, b"\x00")
    buf[offset:offset + 2] = b"NE"
    buf[offset + 2:offset + 4] = bytes((5, 10))  # linker version
    buf[offset + 0x36] = target_os
    return bytes(buf)


def build_pe32(
    *,
    major_os_version: int = 4,
    subsystem: int = IMAGE_SUBSYSTEM_WINDOWS_GUI,
    pe_offset: int = _DEFAULT_PE_OFFSET,
    total_len: int = 0x200,
) -> bytes:
    """PE32 (i386) image headers with a populated COFF and optional header.

    major_os_version lands in MajorOperatingSystemVersion and subsystem in
    Subsystem. No section table or code: only headers, padded to total_len.
    """
    if total_len < pe_offset + 24 + 224:
        raise ValueError("total_len too small for PE32 headers")
    buf = _mz_header(lfarlc=0x40, e_lfanew=pe_offset).ljust(total_len, b"\x00")
    buf[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    # COFF: machine i386, 0 sections, timestamp, symtab ptr, nsyms, optional size 224, characteristics
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x14C, 0, 0x3E000000, 0, 0, 224, 0x010F)
    opt = pe_offset + 24
    struct.pack_into("<H", buf, opt, 0x10B)  # PE32 magic
    struct.pack_into("<I", buf, opt + 28, 0x00400000)  # image base
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)  # section / file alignment
    struct.pack_into("<HH", buf, opt + 40, major_os_version, 0)
    struct.pack_into("<HH", buf, opt + 48, major_os_version, 0)  # subsystem version
    struct.pack_into("<II", buf, opt + 56, 0x1000, 0x200)  # image / headers size
    struct.pack_into("<H", buf, opt + 68, subsystem)
    return bytes(buf)
