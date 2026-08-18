import struct
from pathlib import Path

from .result import ScanResult, null_scan_result


def _classify_pe_header(header: bytes) -> tuple[str | None, float, str, int | None]:
    """Classify a PE/MZ header already read into memory.

    Shared by this module's detect_exe() and directory_detect._detect_from_pe(),
    which both parse the same MZ/PE structure (from a .exe file and from an
    AUTORUN.INF-pointed executable, respectively) and only differ in how they
    word the resulting reason string.

    Returns (era, confidence, branch, major_os). era is None (confidence 0.0)
    when nothing can be said: not MZ at all, a PE offset with no room left
    for the fields this needs, or a Subsystem/MajorOperatingSystemVersion
    combination this package does not classify. branch names which check
    produced the result ("too_short_mz", "no_pe_signature", "era_match", or
    "" for the no-match cases), letting each caller build its own reason
    text without re-deriving the classification logic. major_os is set only
    for "era_match".
    """
    if len(header) < 2 or header[:2] != b"MZ":
        return None, 0.0, "", None
    if len(header) < 0x40:
        return "dos", 0.65, "too_short_mz", None

    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset + 96 > len(header):
        return None, 0.0, "", None
    if header[pe_offset: pe_offset + 4] != b"PE\x00\x00":
        return "dos", 0.65, "no_pe_signature", None

    # Optional header offset 68 = Subsystem; offset 40 = MajorOperatingSystemVersion
    subsystem = struct.unpack_from("<H", header, pe_offset + 92)[0]
    major_os = struct.unpack_from("<H", header, pe_offset + 64)[0]

    if subsystem not in (2, 3):
        return None, 0.0, "", None
    if major_os >= 5:
        return "winxp", 0.75, "era_match", major_os
    if major_os == 4:
        return "win98", 0.75, "era_match", major_os
    return None, 0.0, "", None


def detect_exe(exe_path: Path) -> ScanResult:
    try:
        with exe_path.open("rb") as fh:
            header = fh.read(4096)

        era, confidence, branch, major_os = _classify_pe_header(header)

        if branch == "too_short_mz":
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason="MZ header present, too short for a PE offset, DOS executable",
            )
        if branch == "no_pe_signature":
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason="MZ header present, no PE signature, DOS executable",
            )
        if branch == "era_match":
            label = "Windows XP era executable" if era == "winxp" else "Windows 9x era executable"
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason=f"PE MajorOSVersion={major_os}, {label}",
            )
        return null_scan_result()
    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"detection error reading PE header: {exc}",
        )
