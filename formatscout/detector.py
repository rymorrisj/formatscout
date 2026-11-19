import logging
from pathlib import Path

from .constants import CD_SIZE_THRESHOLD_BYTES, TITLE_MATCH_CONFIDENCE
from .hashing import hash_lookup as _hash_lookup
from .hashing import title_match as _title_match
from .index_errors import INDEX_UNAVAILABLE, IndexUnavailable
from .index_path import coerce_index_path, resolve_index_path
from .magic.magic_detect import detect_from_magic, magic_tags
from .result import Issue, IssueCode, Method, ScanResult, Status
from .validators import bin_validator
from .iso_detect import detect_iso, detect_cue, detect_chd, detect_from_pvd
from .exe_detect import detect_exe
from .directory_detect import detect_directory
from .utils.text import one_line as _one_line

# Override hook for the index path (None: explicit argument, then
# FORMATSCOUT_INDEX_PATH, then the default cache; see index_path.py). The test
# suite points it at a tmp path; leave it None in application code.
_INDEX_PATH: Path | None = None

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


# ── md5/crc32/CHD header claim corroboration ─────────────────────────────────
# An md5 or crc32 index hit is not proof (see hash_lookup.lookup()), and nor is
# a CHD header rawsha1 hit: the header is forgeable and the value is never
# checked against the hunks. None of them short-circuits detection: the suffix
# dispatch runs as well (detect_chd() for a .chd) and the two are reconciled
# in _reconcile_weak_hash(). Only these methods count as structural evidence
# that can corroborate or overrule the hit; extension-only and size-threshold
# results are not evidence about the file's content.

_WEAK_HASH_METHODS = frozenset({Method.HASH_MD5, Method.HASH_CRC32, Method.CHD_HEADER_CLAIM})
_STRUCTURAL_METHODS = frozenset({
    Method.MAGIC, Method.STRUCTURAL, Method.SYSTEM_CNF, Method.PE_HEADER, Method.DIRECTORY_MARKER,
})
# Confidence of a hit that nothing structural corroborates (all in
# Tier.WEAK). lookup() itself still reports 0.85 (md5), 0.75 (crc32) and 1.0
# (CHD header claim).
_UNCORROBORATED_HASH_CONFIDENCE = {
    Method.HASH_MD5: 0.45, Method.HASH_CRC32: 0.35, Method.CHD_HEADER_CLAIM: 0.45,
}
_HASH_KINDS = {Method.HASH_MD5: "md5", Method.HASH_CRC32: "crc32", Method.CHD_HEADER_CLAIM: "chd_rawsha1"}


def _hash_kind(hit: ScanResult) -> str:
    """Short name of the hash a held-back hit matched on, used in evidence
    codes and messages ("md5", "crc32" or "chd_rawsha1")."""
    return _HASH_KINDS[hit.method]


def _claim_issue(message: str) -> Issue:
    """CLAIM_UNVERIFIED issue for a result whose era rests on a CHD header
    rawsha1 claim."""
    return Issue(IssueCode.CLAIM_UNVERIFIED, message)


def _structural_for_weak_hit(
    path: Path, dir_cache: dict[Path, list[Path]] | None,
) -> ScanResult | None:
    """The suffix dispatch result for a file that already has an md5/crc32
    hit or a CHD header claim, or None if the dispatch raised: the hit then
    stands alone instead of being lost to detect()'s catch-all."""
    try:
        return _detect_file(path, dir_cache)
    except Exception as exc:
        log.warning("Structural detection failed for '%s' after a hash hit: %s", path, exc, exc_info=True)
        return None


def _conflict_issue(hit: ScanResult, other: ScanResult, kept: str) -> tuple[Issue, str]:
    other_eras = other.era if other.era is not None else "/".join(c.era for c in other.candidates)
    message = _one_line(
        f"{_hash_kind(hit)} index hit names {hit.era!r} but {other.method} evidence names "
        f"{other_eras!r}; {kept} kept",
        limit=200,
    )
    return Issue(IssueCode.CONFLICTING_EVIDENCE, message), message


def _reconcile_weak_hash(hit: ScanResult, other: ScanResult | None) -> ScanResult:
    """Combine an md5/crc32 hit or a CHD header rawsha1 claim (era set,
    guess) with the suffix dispatch result (detect_chd() for a .chd).

    * Structural evidence with the same era: the structural result is kept
      (method, status, authoritative, container, requires_extraction) and
      gains the index title/platform, the hit's confidence if higher, and a
      "<kind>_index_match" evidence code.
    * Structural evidence with a different era: the structural result wins
      unchanged apart from a CONFLICTING_EVIDENCE issue and warning.
    * Structural candidates (era None) that include the hit's era: the hit
      picks among them and keeps its confidence (guess, not authoritative),
      taking the structural container (chd_cd/chd_dvd for a CHD); a CHD
      claim also gets CLAIM_UNVERIFIED. Candidates that exclude it: the
      structural result wins, with CONFLICTING_EVIDENCE.
    * No structural era evidence: the hit is returned as a weak guess at
      reduced confidence with HASH_WEAK (CLAIM_UNVERIFIED for a CHD claim),
      and the dispatch result's container (None when the dispatch raised).
      A non-structural guess (extension, size) that agrees only lifts the
      confidence to its own value; one that disagrees adds
      CONFLICTING_EVIDENCE but does not overrule the hit.
    """
    kind = _hash_kind(hit)
    match_code = f"{kind}_index_match"
    is_claim = hit.method is Method.CHD_HEADER_CLAIM

    if other is not None and other.method in _STRUCTURAL_METHODS:
        if other.era is not None:
            if other.era == hit.era:
                if other.title is None:
                    other.title = hit.title
                if other.platform is None:
                    other.platform = hit.platform
                other.confidence = max(other.confidence, hit.confidence)
                other.reason = f"{other.reason}; corroborated by {hit.reason}"
                other.evidence += (match_code,)
                return other
            issue, message = _conflict_issue(hit, other, "structural result")
            other.issues += (issue,)
            other.warnings.append(message)
            return other
        if other.candidates:
            candidate_eras = [c.era for c in other.candidates]
            if hit.era in candidate_eras:
                hit.reason = f"{hit.reason}; one of the {other.method} candidates {'/'.join(candidate_eras)}"
                hit.container = other.container
                hit.evidence = other.evidence + (match_code,)
                hit.warnings = list(other.warnings) + hit.warnings
                hit.issues = other.issues + hit.issues
                if is_claim:
                    hit.issues += (_claim_issue(
                        "era picked by the CHD header rawsha1 claim, which was not checked against the image data",
                    ),)
                return hit
            issue, message = _conflict_issue(hit, other, "structural result")
            other.issues += (issue,)
            other.warnings.append(message)
            return other

    hit.confidence = _UNCORROBORATED_HASH_CONFIDENCE[hit.method]
    hit.reason = f"{hit.reason} (no structural corroboration)"
    hit.evidence = (match_code,)
    # The container comes from the dispatch result only: lookup()'s "chd"
    # is not a reading of the CHD metadata.
    hit.container = other.container if other is not None else None
    weak_message = f"{kind} index hit without structural corroboration; era is a weak guess"
    if is_claim:
        hit.issues += (_claim_issue(f"{weak_message}; the claim was not checked against the image data"),)
    else:
        hit.issues += (Issue(IssueCode.HASH_WEAK, weak_message),)
    hit.warnings.append(weak_message)
    if other is not None:
        hit.evidence = other.evidence + hit.evidence
        hit.warnings = list(other.warnings) + hit.warnings
        hit.issues = other.issues + hit.issues
        if other.era == hit.era:
            hit.confidence = max(hit.confidence, other.confidence)
            hit.requires_extraction = other.requires_extraction
        elif other.era is not None:
            issue, message = _conflict_issue(hit, other, "hash result")
            hit.issues += (issue,)
            hit.warnings.append(message)
    return hit


# ── CHD candidate resolution by filename title ──────────────────────────────
# A CHD's raw bytes cannot be hash-matched and its CD/DVD metadata tag does not
# name a platform, so detect_chd() returns container_only with candidate eras.
# An exact normalized match of the filename stem against the index titles of
# exactly one candidate era picks that era, as a guess, at
# constants.TITLE_MATCH_CONFIDENCE: the filename alone, so it scores below the
# era-bearing results read from the file's own bytes.


def _wants_title_resolution(path: Path, result: ScanResult) -> bool:
    return (
        path.suffix.lower() == ".chd"
        and result.status is Status.CONTAINER_ONLY
        and bool(result.candidates)
    )


def _resolve_container_by_title(path: Path, result: ScanResult, index_path: Path) -> ScanResult:
    """*result* resolved to one candidate era by an exact filename-title
    match, or *result* unchanged (no match, or the index could not be read:
    any index issue was already reported by the hash tier), or *result* with
    an AMBIGUOUS_CONTAINER issue when several candidate eras match."""
    eras = tuple(dict.fromkeys(c.era for c in result.candidates))
    try:
        matches = _title_match.exact_title_matches(path.stem, eras, index_path=index_path)
    except Exception as exc:
        log.debug("Title match skipped for '%s': %s", path, exc)
        return result
    if not matches:
        return result
    if len(matches) > 1:
        names = ", ".join(m.era for m in matches)
        result.issues += (Issue(
            IssueCode.AMBIGUOUS_CONTAINER,
            _one_line(f"filename title matches index titles in several candidate eras: {names}", limit=200),
        ),)
        return result
    match = matches[0]
    platform = _one_line(match.platform or match.era, limit=80)
    return ScanResult(
        title=match.title, platform=match.platform, era=match.era, confidence=TITLE_MATCH_CONFIDENCE,
        reason=f"title match in {platform} index (hash lookup unavailable for CHD)",
        warnings=list(result.warnings),
        status=Status.GUESS, method=Method.TITLE_MATCH, authoritative=False,
        container=result.container, candidates=result.candidates,
        evidence=result.evidence + ("filename_title_exact_match",),
        issues=result.issues, platform_hint=result.platform_hint,
    )


# ── Index-failure warning ────────────────────────────────────────────────────

def _index_unavailable_warning(exc: Exception) -> str:
    """One-line ScanResult warning for a hash-tier failure caused by the index
    (not by the input file): offline mode, download backoff or failure, or an
    oversized/corrupt index."""
    return f"hash index unavailable: {_one_line(str(exc))}; heuristics only"


# ── Public entry point ────────────────────────────────────────────────────────

def detect(
    path: Path, dir_cache: dict[Path, list[Path]] | None = None, *, index_path: "Path | str | None" = None,
) -> ScanResult:
    """dir_cache: optional, caller-owned {parent_dir: entries} map threaded down
    to bin_validator._find_cue. Pass one dict across repeated calls in a single
    scan pass (e.g. many .bin files in one directory) to avoid rescanning the
    same directory per file. None (default) preserves prior per-call behavior.

    index_path: keyword-only, the hash index to use instead of the
    FORMATSCOUT_INDEX_PATH / default-cache resolution (see index_path.py). An
    index that cannot be used never makes detect() raise: the hash tier is
    skipped and the result carries a warning plus an INDEX_UNAVAILABLE issue.
    Only a malformed index_path argument (wrong type, empty string) raises
    TypeError/ValueError."""
    explicit_index = coerce_index_path(index_path)
    try:
        return _detect(path, dir_cache, explicit_index)
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
            issues=(Issue("UNEXPECTED_ERROR", _one_line(f"{type(exc).__name__}: {exc}")),),
        )


def _detect(
    path: Path, dir_cache: dict[Path, list[Path]] | None = None, index_path: Path | None = None,
) -> ScanResult:
    if not path.exists():
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="path does not exist",
            status=Status.ERROR, method=Method.NONE,
        )

    # Tier 1: hash lookup. A sha1 hit on the file's own bytes that resolves an
    # era returns immediately. An md5/crc32 hit or a CHD header rawsha1 claim
    # is held back and reconciled with the suffix dispatch below (see
    # _reconcile_weak_hash()). A match with era=None falls through to Tier 2+.
    # Directories are a first-class input (Tier 4), not a hashable file, so
    # skip this tier for them entirely rather than reaching hash_file()'s
    # path.open("rb") only to fail.
    index_warning: str | None = None
    weak_hit: ScanResult | None = None
    resolved_index: Path | None = None  # set only once lookup() ran without error
    if path.is_file():
        try:
            target_index = resolve_index_path(index_path, override=_INDEX_PATH)
            result = _hash_lookup.lookup(path, target_index)
            resolved_index = target_index
            if result is not None and result.era is not None:
                if result.method in _WEAK_HASH_METHODS:
                    weak_hit = result
                else:
                    result.requires_install = _compute_requires_install(path, result.era)
                    return result
        except IndexUnavailable as exc:
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

    if weak_hit is not None:
        # The file was fully read once for hashing; the dispatch below only
        # reads headers/metadata, the same cost as a file with no hash hit.
        result = _reconcile_weak_hash(weak_hit, _structural_for_weak_hit(path, dir_cache))
    elif path.is_file():
        result = _detect_file(path, dir_cache)
        if resolved_index is not None and _wants_title_resolution(path, result):
            result = _resolve_container_by_title(path, result, resolved_index)
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
    if index_warning is not None and all(issue.code != INDEX_UNAVAILABLE for issue in result.issues):
        result.issues += (Issue(INDEX_UNAVAILABLE, index_warning),)
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
