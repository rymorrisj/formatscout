import logging
import struct
from pathlib import Path

from .iso_detect import _POINTER_FILE_READ_CAP_BYTES
from .result import MediaTarget, ScanResult

log = logging.getLogger(__name__)

_WINDOWS_MARKERS = frozenset({"WINDOWS", "WIN", "SYSTEM", "SYSTEM32", "PROGRAM FILES", "PROGRA~1"})
_DOS_TOOLS = frozenset({"DEICE.EXE", "PKUNZIP.EXE", "PKUNZIP.COM", "LZMA.EXE"})

# PS3_DISC.SFB at a folder's root (alongside PS3_GAME/, optionally PS3_UPDATE/)
# marks the folder as a disc-format dump. RPCS3's own "Boot Game" targets the
# folder itself in this case and does its own internal walk, so the folder is
# the launch unit, not a resolved EBOOT.BIN — a distinct shape from the
# dev_hdd0/game/<TITLE_ID>/ and loose extracted folders find_eboot resolves.
# Moved here from backend.service.backends.rpcs3 (was a backend-into-detector
# import, backwards from this package's standalone-vendorable goal): this
# package is the natural, dependency-free home for a structural folder-shape
# check, and rpcs3.py now imports it from here instead.
_PS3_DISC_MARKER_FILENAME = "PS3_DISC.SFB"


def is_disc_format_folder(folder: Path) -> bool:
    """Return True if *folder* is a disc-format dump (has PS3_DISC.SFB at its root)."""
    return (folder / _PS3_DISC_MARKER_FILENAME).is_file()


def find_eboot(folder: Path) -> Path | None:
    """Return the EBOOT.BIN path for *folder*, checking both known layouts.

    dev_hdd0/game/<TITLE_ID>/ folders (installed pkgs) hold USRDIR directly;
    extracted disc folders hold it one level down, under PS3_GAME/.
    """
    for candidate in (folder / "USRDIR" / "EBOOT.BIN", folder / "PS3_GAME" / "USRDIR" / "EBOOT.BIN"):
        if candidate.is_file():
            return candidate
    return None


def resolve_ps3_target(folder: Path) -> MediaTarget | None:
    """Resolve *folder* to a PS3 MediaTarget if it matches a known PS3 folder shape.

    The single resolver for both PS3 folder shapes, called once from both the
    ingest/detection layer (backend.service.games.items.best_detect_path) and
    the launch backend (backend.service.backends.rpcs3.launch), instead of
    each independently reimplementing the is_disc_format_folder/find_eboot
    check (the C4 inversion this package used to require a backend import
    for).

    A real, bootable EBOOT.BIN must exist for either shape to resolve — a
    folder with PS3_DISC.SFB but no findable EBOOT.BIN is not a valid target
    and returns None here, the same as a folder with neither signal. This is
    deliberate: the disc-format branch used to trust the SFB marker alone and
    skip this check, letting an unbootable folder reach RPCS3 before failing
    there instead of here.

    detect_path is always the resolved EBOOT.BIN (what classify()/hash_file()
    should hash); launch_path is always the folder itself (what RPCS3 is
    handed — it does its own internal walk from the folder root for both
    shapes). era is resolved structurally here, not by suffix-dispatching
    the returned EBOOT.BIN through detect()'s generic .bin handling — calling
    detect() on *folder* directly (which reaches this same structural check
    via detect_directory) is how a caller should get a ScanResult for a PS3
    folder, never detect() on the EBOOT.BIN file.

    Returns:
        None if *folder* is not a directory or has no resolvable PS3 shape.
    """
    if not folder.is_dir():
        return None
    eboot = find_eboot(folder)
    if eboot is None:
        return None
    kind = "disc_folder" if is_disc_format_folder(folder) else "installed_dir"
    return MediaTarget(
        kind=kind, detect_path=eboot, launch_path=folder,
        era="ps3", requires_install=False, license_files=(),
    )


def resolve_xex_target(folder: Path) -> MediaTarget | None:
    """Resolve *folder* to an Xbox 360 MediaTarget if it contains a bootable XEX.

    The single resolver for the XEX folder shape, called once from both the
    ingest/detection layer (backend.service.games.items.best_detect_path) and
    the launch backend (backend.service.backends.xenia.launch) instead of
    each independently calling find_default_xex. Unlike PS3, detect_path and
    launch_path are the same file here — Xenia is handed the resolved .xex
    directly, not the containing folder.

    Returns:
        None if *folder* is not a directory or contains no .xex file.
    """
    if not folder.is_dir():
        return None
    xex = find_default_xex(folder)
    if xex is None:
        return None
    return MediaTarget(
        kind="xex_folder", detect_path=xex, launch_path=xex,
        era="xbox360", requires_install=False, license_files=(),
    )


def find_default_xex(folder: Path) -> Path | None:
    """Return the launchable .xex path for an extracted Xbox 360 XEX folder.

    Prefers an exact "default.xex" match (case-insensitive) at the folder's
    top level, the conventional entry point Xenia itself looks for. If no
    default.xex exists but other .xex files are present, falls back to the
    alphabetically first one by filename, chosen deterministically rather
    than by filesystem iteration order, and logs a warning since this is a
    tie-break, not a confirmed match, and the wrong title could otherwise
    launch silently.

    Public (not module-private): the underlying lookup resolve_xex_target
    (above) wraps for both of its callers. Kept importable on its own too,
    since resolve_xex_target's MediaTarget wrapping is XEX-specific and a
    caller that only wants the raw path lookup shouldn't have to unwrap it.
    """
    try:
        xex_files = [f for f in folder.iterdir() if f.is_file() and f.suffix.lower() == ".xex"]
    except OSError:
        return None
    if not xex_files:
        return None
    for f in xex_files:
        if f.name.lower() == "default.xex":
            return f
    xex_files.sort(key=lambda f: f.name.lower())
    chosen = xex_files[0]
    log.warning(
        "xex resolver: no default.xex found in '%s', %d other .xex file(s) present, "
        "deterministically choosing '%s' (alphabetically first) as a tie-break. "
        "Rename the intended file to default.xex to avoid relying on this.",
        folder, len(xex_files), chosen.name,
    )
    return chosen


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
                reason="AUTORUN.INF exe has MZ header but no PE signature — likely DOS",
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

    # Delegates to resolve_ps3_target for both PS3 folder shapes (disc-format
    # dump with PS3_DISC.SFB, or an installed/extracted dev_hdd0/game/<ID>/
    # layout) rather than re-deriving the SFB/EBOOT check inline. A folder
    # with PS3_DISC.SFB but no resolvable EBOOT.BIN is not a valid PS3 target
    # and falls through to the remaining dispatch below, matching
    # resolve_ps3_target's own contract instead of trusting the SFB marker
    # alone.
    ps3_target = resolve_ps3_target(root)
    if ps3_target is not None:
        if ps3_target.kind == "disc_folder":
            return ScanResult(
                title=None, platform=None, era="ps3", confidence=0.9,
                reason="directory root contains PS3_DISC.SFB, PS3 disc dump",
            )
        return ScanResult(
            title=None, platform=None, era="ps3", confidence=0.85,
            reason="directory contains USRDIR/EBOOT.BIN (optionally under PS3_GAME/), installed or extracted PS3 title",
        )

    xex_target = resolve_xex_target(root)
    if xex_target is not None:
        return ScanResult(
            title=None, platform=None, era="xbox360", confidence=0.85,
            reason="directory contains a bootable .xex file (default.xex or resolved fallback)",
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
            reason="directory contains split archive files (.1/.2/.3) with .DAT — DOS installer",
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
