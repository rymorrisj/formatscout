import logging
from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .magic.magic_detect import detect_from_magic
from .result import ScanResult
from .validators import bin_validator
from .iso_detect import detect_iso, detect_cue, detect_chd, detect_from_pvd
from .exe_detect import detect_exe
from .directory_detect import detect_directory

_INDEX_PATH = Path(__file__).parent / "hashing" / "hash_index.json"

log = logging.getLogger(__name__)


# ── requires_install heuristic ───────────────────────────────────────────────
# Heuristic, may need tuning post-beta. Covers DOS-era raw .iso/.cue media,
# small .img floppy images, and installer-only DOS directories.

def _compute_requires_install(path: Path, era: str | None) -> bool:
    if era != "dos":
        return False
    if path.is_file():
        suffix = path.suffix.lower()
        if suffix in {".iso", ".cue"}:
            return True
        if suffix == ".img":
            try:
                return path.stat().st_size < 2 * 1024 * 1024
            except OSError:
                return False
        return False
    if path.is_dir():
        from .utils.blocklist import is_blocked
        try:
            exes = [
                e for e in path.iterdir()
                if e.is_file() and e.suffix.lower() in {".exe", ".com", ".bat"}
            ]
            if exes and all(is_blocked(e.stem) for e in exes):
                return True
        except OSError:
            pass
    return False


# ── Public entry point ────────────────────────────────────────────────────────

def detect(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    """dir_cache: optional, caller-owned {parent_dir: entries} map threaded down
    to bin_validator._find_cue. Pass one dict across repeated calls in a single
    scan pass (e.g. many .bin files in one directory) to avoid rescanning the
    same directory per file. None (default) preserves prior per-call behavior."""
    try:
        return _detect(path, dir_cache)
    except Exception as exc:
        log.warning("Unexpected error during media detection for '%s': %s", path, exc, exc_info=True)
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.0,
            reason="unexpected detection error",
            warnings=[str(exc)],
        )


def _detect(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    if not path.exists():
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="path does not exist",
        )

    # Tier 1: hash lookup, highest confidence, return immediately on match
    try:
        result = _hash_lookup.lookup(path, _INDEX_PATH)
        if result is not None and result.era is not None:
            result.requires_install = _compute_requires_install(path, result.era)
            return result
    except Exception as exc:
        if path.is_dir():
            # A directory reaching hash_file()'s path.open("rb") always fails
            # (PermissionError on Windows, IsADirectoryError on POSIX), this is
            # a caller bug, some upstream step should have resolved *path* to
            # its actual hashable media file before detection ran, not this
            # function's job to do. The traceback adds nothing actionable here.
            log.warning(
                "Hash lookup received a directory instead of a resolved media "
                "file for '%s': %s. The caller did not resolve this path to "
                "its actual launchable file before detection.",
                path, exc,
            )
        else:
            log.warning("Hash lookup failed for '%s': %s", path, exc, exc_info=True)
        # empty or missing index, continue to signal detection

    if path.is_file():
        result = _detect_file(path, dir_cache)
    elif path.is_dir():
        result = detect_directory(path)
    else:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="path is neither a file nor a directory",
        )

    result.requires_install = _compute_requires_install(path, result.era)
    return result


# ── File dispatch ─────────────────────────────────────────────────────────────

def _detect_file(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    suffix = path.suffix.lower()

    if suffix == ".nds":
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="NDS format is not supported",
            warnings=["NDS format is not supported by formatscout"],
        )

    if suffix == ".xiso":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.7,
            reason="file extension .xiso indicates Original Xbox disc image",
        )

    if suffix == ".xex":
        return ScanResult(
            title=None, platform=None, era="xbox360", confidence=0.7,
            reason="file extension .xex indicates Xbox 360 executable",
        )

    if suffix in {".z64", ".n64", ".v64"}:
        return ScanResult(
            title=None, platform=None, era="n64", confidence=0.7,
            reason=f"file extension {suffix} indicates Nintendo 64 ROM",
        )

    if suffix in {".sfc", ".smc", ".fig", ".swc"}:
        return ScanResult(
            title=None, platform=None, era="snes", confidence=0.7,
            reason=f"file extension {suffix} indicates SNES ROM",
        )

    if suffix == ".nes":
        return ScanResult(
            title=None, platform=None, era="nes", confidence=0.7,
            reason="file extension .nes indicates NES ROM",
        )

    if suffix in {".gdi", ".cdi"}:
        era, reason = detect_from_magic(path, suffix[1:])
        if era is not None:
            return ScanResult(title=None, platform=None, era=era, confidence=0.9, reason=reason)
        return ScanResult(
            title=None, platform=None, era="dreamcast", confidence=0.5,
            reason=f"file extension {suffix} suggests Dreamcast disc image",
            warnings=["no magic byte match; era inferred from extension only"],
        )

    if suffix == ".pkg":
        return ScanResult(
            title=None, platform=None, era="ps3", confidence=0.7,
            reason="file extension .pkg indicates PlayStation 3 package",
        )

    if suffix == ".iso":
        return detect_iso(path)

    if suffix == ".bin":
        era, reason = detect_from_magic(path, "bin")
        if era is not None:
            return ScanResult(title=None, platform=None, era=era, confidence=0.9, reason=reason)
        pvd = detect_from_pvd(path)
        if pvd.era is not None:
            return pvd
        return bin_validator.resolve_bin_cue(path, dir_cache)

    if suffix == ".cue":
        return detect_cue(path, dir_cache)

    if suffix == ".chd":
        return detect_chd(path)

    if suffix == ".img":
        try:
            if path.stat().st_size < 800 * 1024 * 1024:
                return ScanResult(
                    title=None, platform=None, era="dos", confidence=0.35,
                    reason="file extension .img under 800 MB suggests DOS-era image",
                    warnings=["low confidence: era inferred from extension and size only"],
                )
        except OSError:
            pass
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="no signal found",
        )

    if suffix == ".exe":
        return detect_exe(path)

    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0,
        reason="no signal found",
    )
