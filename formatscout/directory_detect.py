import logging
import struct
from pathlib import Path

from .constants import DIRECTORY_DEPTH2_SCAN_CAP_ENTRIES
from .exe_detect import _classify_pe_header
from .result import ScanResult, null_scan_result
from .utils.pointer_file import read_capped_lines

logger = logging.getLogger(__name__)

_WINDOWS_MARKERS = frozenset({"WINDOWS", "WIN", "SYSTEM", "SYSTEM32", "PROGRAM FILES", "PROGRA~1"})
_DOS_TOOLS = frozenset({"DEICE.EXE", "PKUNZIP.EXE", "PKUNZIP.COM", "LZMA.EXE"})


def detect_directory(path: Path) -> ScanResult:
    result = _detect_from_autorun(path)
    if result.era is not None:
        return result
    return _detect_from_directory(path)


def _detect_from_autorun(root: Path) -> ScanResult:
    _null = null_scan_result()
    try:
        autorun = None
        for name in ("AUTORUN.INF", "Autorun.inf", "autorun.inf"):
            candidate = root / name
            if candidate.is_file():
                autorun = candidate
                break
        if autorun is None:
            return _null
        exe_rel = _parse_autorun_exe(autorun)
        if exe_rel is None:
            return _null
        exe_path = root / exe_rel.replace("\\", "/")
        if not exe_path.is_file():
            return _null
        return _detect_from_pe(exe_path)
    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"autorun detection error: {exc}",
        )


def _parse_autorun_exe(autorun: Path) -> str | None:
    try:
        for line in read_capped_lines(autorun):
            stripped = line.strip()
            if stripped.upper().startswith(("OPEN=", "RUN=")):
                value = stripped.split("=", 1)[1].strip().strip('"')
                if value.lower().endswith(".exe"):
                    return value
        return None
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to parse AUTORUN.INF at %s: %s", autorun, exc)
        return None


def _detect_from_pe(exe_path: Path) -> ScanResult:
    """Distinct from exe_detect.detect_exe(): this reports AUTORUN.INF-specific
    reason text and is reached from a directory scan rather than a bare .exe
    path, but the underlying PE-header classification is shared, see
    exe_detect._classify_pe_header().
    """
    try:
        with exe_path.open("rb") as fh:
            header = fh.read(4096)

        era, confidence, branch, major_os = _classify_pe_header(header)

        if branch == "too_short_mz":
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason="AUTORUN.INF points to MZ-only (DOS) executable",
            )
        if branch == "no_pe_signature":
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason="AUTORUN.INF exe has MZ header but no PE signature, likely DOS",
            )
        if branch == "era_match":
            label = "(Windows NT 5+)" if era == "winxp" else "(Windows 9x era)"
            return ScanResult(
                title=None, platform=None, era=era, confidence=confidence,
                reason=f"PE MajorOperatingSystemVersion={major_os} {label}",
            )
        return null_scan_result()
    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"PE parse error: {exc}",
        )


def _detect_from_directory(root: Path) -> ScanResult:
    try:
        entries = {e.name.upper() for e in root.iterdir()}
    except OSError:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="cannot list directory",
        )

    # Checked first, same as the PVD root-dir scan in iso_detect.py: an exact
    # marker filename is a stronger signal than the keyword/marker checks below.
    if "PS3_DISC.SFB" in entries:
        return ScanResult(
            title=None, platform=None, era="ps3", confidence=0.9,
            reason="directory contains PS3_DISC.SFB, PS3 disc image",
        )
    if "XPSP" in entries or "I386" in entries:
        return ScanResult(
            title=None, platform=None, era="winxp", confidence=0.6,
            reason="directory contains Windows XP installer structure (XPSP or I386)",
        )
    if "WIN98" in entries or ("AUTOEXEC.BAT" in entries and "SYSTEM.DAT" in entries):
        return ScanResult(
            title=None, platform=None, era="win98", confidence=0.6,
            reason="directory contains Win98 marker files",
        )
    if "WIN95" in entries or ("SETUP.EXE" in entries and "WIN.COM" in entries):
        return ScanResult(
            title=None, platform=None, era="win95", confidence=0.6,
            reason="directory contains Win95 marker files",
        )
    if "SYSTEM.CNF" in entries:
        cnf_path = next(
            (e for e in root.iterdir() if e.is_file() and e.name.upper() == "SYSTEM.CNF"),
            None,
        )
        if cnf_path is not None:
            from .magic.magic_detect import resolve_ps_generation_from_file
            era = resolve_ps_generation_from_file(cnf_path)
            if era == "unknown":
                return ScanResult(
                    title=None, platform=None, era=None, confidence=0.4,
                    reason="directory contains SYSTEM.CNF but BOOT/BOOT2 key could not be read to confirm PS1 vs PS2",
                    warnings=["SYSTEM.CNF present but unreadable, select PS1 or PS2 manually"],
                )
            boot_key = "BOOT2" if era == "ps2" else "BOOT"
            return ScanResult(
                title=None, platform=None, era=era, confidence=0.8,
                reason=f"directory SYSTEM.CNF {boot_key} key indicates {era.upper()}",
            )
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.4,
            reason="directory contains SYSTEM.CNF but file could not be read to confirm generation",
            warnings=["SYSTEM.CNF present but unreadable, select PS1 or PS2 manually"],
        )
    if "INSTALL.BAT" in entries or "INSTALL.COM" in entries:
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.55,
            reason="directory contains INSTALL.BAT or INSTALL.COM at root",
        )

    depth2_names: set[str] = set(entries)
    try:
        for entry in root.iterdir():
            if len(depth2_names) >= DIRECTORY_DEPTH2_SCAN_CAP_ENTRIES:
                break
            if entry.is_dir():
                try:
                    for sub in entry.iterdir():
                        if len(depth2_names) >= DIRECTORY_DEPTH2_SCAN_CAP_ENTRIES:
                            break
                        depth2_names.add(sub.name.upper())
                except OSError:
                    pass
    except OSError:
        pass

    if _DOS_TOOLS.intersection(depth2_names):
        matched = next(iter(_DOS_TOOLS.intersection(depth2_names)))
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.6,
            reason=f"directory contains DOS decompression tool {matched}",
        )
    if any(n.endswith(".WAD") for n in depth2_names):
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.55,
            reason="directory contains .WAD file (DOS game data)",
        )
    root_exts_all = {Path(e).suffix.lower() for e in entries}
    if root_exts_all.intersection({".1", ".2", ".3"}) and ".dat" in root_exts_all:
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.55,
            reason="directory contains split archive files (.1/.2/.3) with .DAT, DOS installer",
        )
    if any(e.endswith(".BAT") for e in entries) and not entries.intersection(_WINDOWS_MARKERS):
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.5,
            reason="directory contains .BAT file at root with no Windows indicators",
        )
    root_exts = {Path(e).suffix.lower() for e in entries if "." in e}
    dos_only = root_exts.issubset({".exe", ".com", ".bat", ".cfg", ".txt", ".ini", ""})
    if root_exts and dos_only and not entries.intersection(_WINDOWS_MARKERS):
        return ScanResult(
            title=None, platform=None, era="dos", confidence=0.5,
            reason="directory contains only DOS-era executables with no Windows folders",
        )

    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0,
        reason="no signal found",
    )
