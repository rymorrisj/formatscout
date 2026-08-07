import struct
from pathlib import Path

from .iso_detect import _POINTER_FILE_READ_CAP_BYTES
from .result import ScanResult

_WINDOWS_MARKERS = frozenset({"WINDOWS", "WIN", "SYSTEM", "SYSTEM32", "PROGRAM FILES", "PROGRA~1"})
_DOS_TOOLS = frozenset({"DEICE.EXE", "PKUNZIP.EXE", "PKUNZIP.COM", "LZMA.EXE"})


def detect_directory(path: Path) -> ScanResult:
    result = _detect_from_autorun(path)
    if result.era is not None:
        return result
    return _detect_from_directory(path)


def _detect_from_autorun(root: Path) -> ScanResult:
    _null = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
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
        with autorun.open("rb") as fh:
            raw = fh.read(_POINTER_FILE_READ_CAP_BYTES)
        for line in raw.decode("utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.upper().startswith(("OPEN=", "RUN=")):
                value = stripped.split("=", 1)[1].strip().strip('"')
                if value.lower().endswith(".exe"):
                    return value
        return None
    except Exception:
        return None


def _detect_from_pe(exe_path: Path) -> ScanResult:
    _null = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
    try:
        with exe_path.open("rb") as fh:
            header = fh.read(4096)

        if len(header) < 2 or header[:2] != b"MZ":
            return _null
        if len(header) < 0x40:
            return ScanResult(
                title=None, platform=None, era="dos", confidence=0.65,
                reason="AUTORUN.INF points to MZ-only (DOS) executable",
            )

        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if pe_offset + 96 > len(header):
            return _null
        if header[pe_offset: pe_offset + 4] != b"PE\x00\x00":
            return ScanResult(
                title=None, platform=None, era="dos", confidence=0.65,
                reason="AUTORUN.INF exe has MZ header but no PE signature, likely DOS",
            )

        # Optional header offset 68 = Subsystem; offset 40 = MajorOperatingSystemVersion
        subsystem = struct.unpack_from("<H", header, pe_offset + 92)[0]
        major_os = struct.unpack_from("<H", header, pe_offset + 64)[0]

        if subsystem not in (2, 3):
            return _null

        if major_os >= 5:
            return ScanResult(
                title=None, platform=None, era="winxp", confidence=0.75,
                reason=f"PE MajorOperatingSystemVersion={major_os} (Windows NT 5+)",
            )
        if major_os == 4:
            return ScanResult(
                title=None, platform=None, era="win98", confidence=0.75,
                reason=f"PE MajorOperatingSystemVersion={major_os} (Windows 9x era)",
            )
        return _null
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
            if entry.is_dir():
                try:
                    for sub in entry.iterdir():
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
