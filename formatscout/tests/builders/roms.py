"""Tiny ROM and package builders: iNES, SNES, N64 (three byte orders), XEX2, PS3 PKG, PS4 PKG.

Only headers are meaningful; bodies are zero filled. Sizes stay small
(iNES ships one 16 KiB PRG bank, N64 a 4 KiB image).
"""

import struct
from typing import Literal

N64Order = Literal["z64", "v64", "n64"]

INES_MAGIC = b"NES\x1a"
XEX2_MAGIC = b"XEX2"
PS3_PKG_MAGIC = b"\x7fPKG"
PS4_PKG_MAGIC = b"\x7fCNT"
N64_MAGIC_BY_ORDER = {
    "z64": bytes.fromhex("80371240"),  # big-endian (native)
    "v64": bytes.fromhex("37804012"),  # 16-bit byteswapped
    "n64": bytes.fromhex("40123780"),  # 32-bit little-endian
}


def build_ines(*, prg_banks: int = 1, chr_banks: int = 0, mapper: int = 0) -> bytes:
    """iNES 1.0 image: 16-byte header, 16 KiB PRG banks, 8 KiB CHR banks."""
    header = bytearray(16)
    header[0:4] = INES_MAGIC
    header[4] = prg_banks
    header[5] = chr_banks
    header[6] = (mapper & 0x0F) << 4
    header[7] = mapper & 0xF0
    return bytes(header) + bytes(prg_banks * 0x4000 + chr_banks * 0x2000)


def build_snes_lorom(*, size: int = 0x8000, title: str = "FSCORPUS TEST") -> bytes:
    """Headerless LoROM image with an internal header at 0x7FC0 and valid checksum pair."""
    if size < 0x8000:
        raise ValueError("a LoROM image is at least 32 KiB")
    rom = bytearray(size)
    rom[0x7FC0:0x7FC0 + 21] = title.encode("ascii")[:21].ljust(21, b" ")
    rom[0x7FD5] = 0x20  # LoROM, slow
    rom[0x7FD7] = 0x08  # 256 KiB nominal
    rom[0x7FDC:0x7FE0] = struct.pack("<HH", 0xFFFF ^ 0x0000, 0x0000)  # complement, checksum
    return bytes(rom)


def build_n64(order: N64Order = "z64", *, size: int = 0x1000, name: str = "FSCORPUS TEST") -> bytes:
    """N64 ROM in z64 (big-endian), v64 (byteswapped) or n64 (little-endian) order.

    Built canonically big-endian (PI config, clock, PC, release, CRCs, 20-byte
    name at 0x20), then swapped: v64 swaps each 16-bit pair, n64 reverses each
    32-bit word. size must be a multiple of 4.
    """
    if size % 4 or size < 0x40:
        raise ValueError("size must be a multiple of 4 and at least 0x40")
    rom = bytearray(size)
    rom[0:4] = N64_MAGIC_BY_ORDER["z64"]
    struct.pack_into(">III", rom, 4, 0x0000000F, 0x80000400, 0x0000144B)
    rom[0x20:0x34] = name.encode("ascii")[:20].ljust(20, b" ")
    rom[0x3B:0x3F] = b"NFSE"
    if order == "z64":
        return bytes(rom)
    if order == "v64":
        for i in range(0, size, 2):
            rom[i], rom[i + 1] = rom[i + 1], rom[i]
        return bytes(rom)
    if order == "n64":
        for i in range(0, size, 4):
            rom[i:i + 4] = rom[i:i + 4][::-1]
        return bytes(rom)
    raise ValueError(f"unknown N64 byte order: {order!r}")


def build_xex2(*, size: int = 0x100) -> bytes:
    """Xbox 360 XEX2 header: magic, module flags, PE data and security offsets, zero optional headers."""
    buf = bytearray(max(size, 0x18))
    buf[0:4] = XEX2_MAGIC
    struct.pack_into(">IIIII", buf, 4, 0x00000001, 0x00000100, 0, 0x00000080, 0)
    return bytes(buf)


def build_ps3_pkg(*, content_id: str = "UP0000-FSCORPUS_00-0000000000000000", size: int = 0x100) -> bytes:
    """PS3 PKG header: 0x7F 'PKG', final-retail revision, type 1 (PS3), 36-byte content id at 0x30."""
    buf = bytearray(max(size, 0x80))
    buf[0:4] = PS3_PKG_MAGIC
    struct.pack_into(">HH", buf, 4, 0x8000, 0x0001)
    struct.pack_into(">QQ", buf, 0x10, 0x80, len(buf))  # metadata-ish fields: header size, total size
    raw = content_id.encode("ascii")[:36]
    buf[0x30:0x30 + len(raw)] = raw
    return bytes(buf)


def build_ps4_pkg(*, size: int = 0x100) -> bytes:
    """PS4 PKG header: 0x7F 'CNT' magic then big-endian type and flag fields."""
    buf = bytearray(max(size, 0x80))
    buf[0:4] = PS4_PKG_MAGIC
    struct.pack_into(">II", buf, 4, 0x00008000, 1)
    return bytes(buf)
