import logging
from pathlib import Path

from .constants import CD_SIZE_THRESHOLD_BYTES
from .hashing import hash_lookup as _hash_lookup
from .magic.magic_detect import detect_from_magic, magic_tags
from .result import Issue, Method, ScanResult, Status
from .validators import bin_validator
from .iso_detect import detect_iso, detect_cue, detect_chd, detect_from_pvd
from .exe_detect import detect_exe
from .directory_detect import detect_directory

_INDEX_PATH = _hash_lookup.default_index_path()

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


# ── Index-failure warning ────────────────────────────────────────────────────

_MAX_WARNING_REASON_CHARS = 120


def _one_line(text: str) -> str:
    """*text* as a single printable line of at most _MAX_WARNING_REASON_CHARS."""
    # Control characters (newlines, ESC, ...) become spaces so a message that
    # embeds server or OS text cannot inject terminal escapes or extra lines.
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    line = " ".join(printable.split())
    if len(line) > _MAX_WARNING_REASON_CHARS:
        line = line[:_MAX_WARNING_REASON_CHARS - 3] + "..."
    return line


def _index_unavailable_warning(exc: Exception) -> str:
    """One-line ScanResult warning for a hash-tier failure caused by the index
    (not by the input file): offline mode, download backoff or failure, or an
    oversized/corrupt index."""
    return f"hash index unavailable: {_one_line(str(exc))}; heuristics only"


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
            status=Status.ERROR,
            method=Method.NONE,
            issues=(Issue("unexpected_error", _one_line(f"{type(exc).__name__}: {exc}")),),
        )


def _detect(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    if not path.exists():
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="path does not exist",
            status=Status.ERROR, method=Method.NONE,
        )

    # Tier 1: hash lookup, highest confidence, return immediately on a match
    # that resolves an era (a match with era=None falls through to Tier 2+).
    # Directories are a first-class input (Tier 4), not a hashable file, so
    # skip this tier for them entirely rather than reaching hash_file()'s
    # path.open("rb") only to fail.
    index_warning: str | None = None
    if path.is_file():
        try:
            result = _hash_lookup.lookup(path, _INDEX_PATH)
            if result is not None and result.era is not None:
                result.requires_install = _compute_requires_install(path, result.era)
                return result
        except _hash_lookup._IndexUnavailableError as exc:
            # The index itself could not be obtained or trusted: surface it on
            # the result so callers can tell "no hash match" from "hash tier
            # did not run". The warning is attached once, after the heuristic
            # tiers have produced their result.
            index_warning = _index_unavailable_warning(exc)
            # One warning line per backoff window per process (no traceback);
            # the rest of a scan logs this at debug. The per-result warning
            # above is separate and unchanged.
            _hash_lookup._report_index_failure(f"{index_warning} (while scanning {str(path)!r})")
        except Exception as exc:
            # Quiet by design: FileNotFoundError for an index path that does
            # not exist (only reachable with a custom or patched index path,
            # the default is downloaded instead) means "no index built", and
            # the same exception type can also come from the input file
            # vanishing mid-scan, which is not an index problem. Everything
            # else here is an input-file read error.
            log.warning("Hash lookup failed for '%s': %s", path, exc, exc_info=True)

    if path.is_file():
        result = _detect_file(path, dir_cache)
    elif path.is_dir():
        result = detect_directory(path)
    else:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="path is neither a file nor a directory",
            status=Status.UNSUPPORTED, method=Method.NONE,
        )

    result.requires_install = _compute_requires_install(path, result.era)
    if index_warning is not None and index_warning not in result.warnings:
        result.warnings.append(index_warning)
    if index_warning is not None and all(issue.code != "index_unavailable" for issue in result.issues):
        result.issues += (Issue("index_unavailable", index_warning),)
    return result


# ── File dispatch ─────────────────────────────────────────────────────────────

def _detect_file(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    suffix = path.suffix.lower()

    if suffix == ".nds":
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="NDS format is not supported",
            warnings=["NDS format is not supported by formatscout"],
            status=Status.UNSUPPORTED, method=Method.EXTENSION, platform_hint="Nintendo DS",
        )

    if suffix == ".xiso":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.7,
            reason="file extension .xiso indicates Original Xbox disc image",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix == ".xex":
        return ScanResult(
            title=None, platform=None, era="xbox360", confidence=0.7,
            reason="file extension .xex indicates Xbox 360 executable",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix in {".z64", ".n64", ".v64"}:
        return ScanResult(
            title=None, platform=None, era="n64", confidence=0.7,
            reason=f"file extension {suffix} indicates Nintendo 64 ROM",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix in {".sfc", ".smc", ".fig", ".swc"}:
        return ScanResult(
            title=None, platform=None, era="snes", confidence=0.7,
            reason=f"file extension {suffix} indicates SNES ROM",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix == ".nes":
        return ScanResult(
            title=None, platform=None, era="nes", confidence=0.7,
            reason="file extension .nes indicates NES ROM",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix in {".gdi", ".cdi"}:
        era, reason = detect_from_magic(path, suffix[1:])
        if era is not None:
            method, authoritative = magic_tags(reason)
            return ScanResult(
                title=None, platform=None, era=era, confidence=0.9, reason=reason,
                method=method, authoritative=authoritative,
            )
        return ScanResult(
            title=None, platform=None, era="dreamcast", confidence=0.5,
            reason=f"file extension {suffix} suggests Dreamcast disc image",
            warnings=["no magic byte match; era inferred from extension only"],
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix == ".pkg":
        return ScanResult(
            title=None, platform=None, era="ps3", confidence=0.7,
            reason="file extension .pkg indicates PlayStation 3 package",
            method=Method.EXTENSION, authoritative=False,
        )

    if suffix == ".iso":
        return detect_iso(path)

    if suffix == ".bin":
        era, reason = detect_from_magic(path, "bin")
        if era is not None:
            method, authoritative = magic_tags(reason)
            return ScanResult(
                title=None, platform=None, era=era, confidence=0.9, reason=reason,
                method=method, authoritative=authoritative,
            )
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
            if path.stat().st_size < CD_SIZE_THRESHOLD_BYTES:
                return ScanResult(
                    title=None, platform=None, era="dos", confidence=0.35,
                    reason="file extension .img under 800 MB suggests DOS-era image",
                    warnings=["low confidence: era inferred from extension and size only"],
                    method=Method.SIZE_HEURISTIC, authoritative=False,
                )
        except OSError:
            pass
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="no signal found",
            status=Status.NO_SIGNAL, method=Method.NONE,
        )

    if suffix == ".exe":
        return detect_exe(path)

    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0,
        reason="no signal found",
        status=Status.NO_SIGNAL, method=Method.NONE,
    )
