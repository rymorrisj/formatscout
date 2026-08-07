import struct
from pathlib import Path

from .result import ScanResult


def detect_exe(exe_path: Path) -> ScanResult:
    _null = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
    try:
        with exe_path.open("rb") as fh:
            header = fh.read(4096)

        if len(header) < 2 or header[:2] != b"MZ":
            return _null
        if len(header) < 0x40:
            return ScanResult(
                title=None, platform=None, era="dos", confidence=0.65,
                reason="MZ header present, too short for a PE offset — DOS executable",
            )

        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if pe_offset + 96 > len(header):
            return _null
        if header[pe_offset: pe_offset + 4] != b"PE\x00\x00":
            return ScanResult(
                title=None, platform=None, era="dos", confidence=0.65,
                reason="MZ header present, no PE signature — DOS executable",
            )

        # Optional header offset 68 = Subsystem; offset 40 = MajorOperatingSystemVersion
        subsystem = struct.unpack_from("<H", header, pe_offset + 92)[0]
        major_os = struct.unpack_from("<H", header, pe_offset + 64)[0]

        if subsystem not in (2, 3):
            return _null

        if major_os >= 5:
            return ScanResult(
                title=None, platform=None, era="winxp", confidence=0.75,
                reason=f"PE MajorOSVersion={major_os} — Windows XP era executable",
            )
        if major_os == 4:
            return ScanResult(
                title=None, platform=None, era="win98", confidence=0.75,
                reason=f"PE MajorOSVersion={major_os} — Windows 9x era executable",
            )
        return _null
    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"detection error reading PE header: {exc}",
        )
