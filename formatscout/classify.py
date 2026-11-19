from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .hashing.title_match import TitleMatch, fuzzy_title_match
from .index_errors import INDEX_UNAVAILABLE, IndexUnavailable
from .index_path import coerce_index_path, resolve_index_path
from .result import ClassifyResult, HashKind, Issue, IssueCode
from .utils.text import one_line
from .validators.chd_validator import extract_embedded_sha1

# Override hook for the index path (None: explicit argument, then
# FORMATSCOUT_INDEX_PATH, then the default cache; see index_path.py). The test
# suite points it at a tmp path; leave it None in application code.
_INDEX_PATH: Path | None = None
_DEFAULT_THRESHOLD = 0.80
# How many title candidates classify() asks for per search (the supplied era
# is searched separately, so this never limits whether its match is found).
_TITLE_CANDIDATES = 5


def classify(
    path: Path, title: str, era: str | None, *, threshold: float = _DEFAULT_THRESHOLD,
    index_path: "Path | str | None" = None, strict: bool = False,
) -> ClassifyResult:
    """Five-state verification classification, see ClassifyResult for what
    each status means. Establishes a classification from scratch (ingest, or
    a from-scratch re-check), unlike verify(), which compares against an
    already-known expected_sha1.

    index_path: keyword-only, the hash index to use instead of the
    FORMATSCOUT_INDEX_PATH / default-cache resolution (see index_path.py).

    status="unchecked" covers two cases, told apart by the issue code: an
    OSError while hashing the file (HASH_FAILED), and an index that cannot be
    obtained or used (INDEX_UNAVAILABLE: offline mode, backoff, a failed
    download, an oversized or corrupt index; computed_sha1 is still set).
    With strict=True the second case raises IndexUnavailable instead. A
    missing index file at a custom path (FileNotFoundError) is neither: it is
    treated as an empty index, with an INDEX_MISSING issue.

    Title fallback (no hash matched): the best title match inside *era* is
    computed on its own (fuzzy_title_match(eras=[era])), separately from the
    cross-era search, so other-era candidates can never push it out. When
    *era* has a match at or above *threshold*, the result is "mismatch" with
    that title and matched_era=era, even if another era scores the same or
    higher (ties and near-ties favour the supplied era). Only when *era* has
    no such match is every other era searched; if one matches, the status is
    still "mismatch" but matched_title/similarity describe that out-of-era
    title, matched_era is its era, and a WRONG_ERA issue is added.
    era=None (or empty) still skips the title fallback entirely (fail closed).
    Numeric tokens must agree for any title match (see fuzzy_title_match()),
    so sequels that differ only by a number no longer produce "mismatch".
    """
    explicit_index = coerce_index_path(index_path)
    try:
        hashes = _hash_lookup.hash_file(path)
    except OSError as exc:
        return ClassifyResult(
            status="unchecked", computed_sha1=None, matched_title=None, similarity=None,
            reason=f"could not hash file: {exc}",
            issues=(Issue("HASH_FAILED", f"could not hash file: {exc}"),),
        )

    computed_sha1 = hashes.sha1
    issues: list[Issue] = []

    try:
        resolved_index = resolve_index_path(explicit_index, override=_INDEX_PATH)
        try:
            index, md5_index, crc32_index = _hash_lookup.load_index(resolved_index)
        except FileNotFoundError:
            index, md5_index, crc32_index = {}, {}, {}
            issues.append(Issue("INDEX_MISSING", "index file not found, treated as an empty index"))
    except IndexUnavailable as exc:
        if strict:
            raise
        return _index_unchecked(path, computed_sha1, exc)

    # CHD containers never match on raw file bytes, chdman compresses and
    # wraps the original track data, so the raw md5/crc32 tiers are also
    # meaningless for them (same reasoning as hash_lookup.lookup()). The
    # embedded rawsha1 is used for the verified-tier lookup only,
    # computed_sha1 above (the file's own real hash) is still what gets
    # persisted and returned, since that is what identifies this exact file
    # for a future re-check.
    is_chd = path.suffix.lower() == ".chd"
    lookup_sha1 = computed_sha1
    sha1_kind: HashKind = "sha1"
    if is_chd:
        embedded = extract_embedded_sha1(path)
        if embedded is not None:
            lookup_sha1 = embedded
            sha1_kind = "chd_rawsha1"
        else:
            issues.append(Issue(
                "CHD_RAWSHA1_MISSING", "no usable embedded rawsha1 in the CHD header, raw file sha1 looked up instead",
            ))

    if lookup_sha1 in index:
        if sha1_kind == "chd_rawsha1":
            # The header rawsha1 is a forgeable claim, never checked against
            # the hunks, so it cannot read as a verification.
            issues.append(Issue(
                IssueCode.CLAIM_UNVERIFIED,
                "the CHD header rawsha1 matched an index entry but was not checked against the image data",
            ))
            return ClassifyResult(
                status="caution", computed_sha1=computed_sha1, matched_title=None, similarity=None,
                reason=f"CHD header rawsha1 claim matches an index entry (unverified): {lookup_sha1}",
                matched_era=_entry_era(index[lookup_sha1]), hash_kind=sha1_kind, issues=tuple(issues),
            )
        return ClassifyResult(
            status="verified", computed_sha1=computed_sha1, matched_title=None, similarity=None,
            reason=f"sha1 match: {lookup_sha1}",
            matched_era=_entry_era(index[lookup_sha1]), hash_kind=sha1_kind, issues=tuple(issues),
        )

    if not is_chd:
        if hashes.md5 in md5_index:
            return ClassifyResult(
                status="caution", computed_sha1=computed_sha1, matched_title=None, similarity=None,
                reason=f"md5 match, no sha1 match: {hashes.md5}",
                matched_era=_entry_era(md5_index[hashes.md5]), hash_kind="md5", issues=tuple(issues),
            )
        if hashes.crc32 in crc32_index:
            return ClassifyResult(
                status="caution", computed_sha1=computed_sha1, matched_title=None, similarity=None,
                reason=f"crc32 match, no sha1 match: {hashes.crc32}",
                matched_era=_entry_era(crc32_index[hashes.crc32]), hash_kind="crc32", issues=tuple(issues),
            )

    match: TitleMatch | None = None
    if era:
        try:
            # The supplied era is searched on its own, so candidates from
            # other eras can never crowd an in-era match out of a top-k.
            in_era = fuzzy_title_match(
                title, index_path=resolved_index, eras=(era,), threshold=threshold, limit=_TITLE_CANDIDATES,
            )
            other = [] if in_era else fuzzy_title_match(
                title, index_path=resolved_index, threshold=threshold, limit=_TITLE_CANDIDATES,
            )
        except IndexUnavailable as exc:
            if strict:
                raise
            return _index_unchecked(path, computed_sha1, exc)
        match = in_era[0] if in_era else _best_other_era_match(other, era)
    if match is not None and match.era == era:
        return ClassifyResult(
            status="mismatch", computed_sha1=computed_sha1, matched_title=match.title, similarity=match.score,
            reason=(
                f"title '{title}' is a {match.score:.0%} match for indexed title "
                f"'{match.title}', but no hash from this file matches any entry for it"
            ),
            matched_era=era, issues=tuple(issues),
        )
    if match is not None:
        wrong_era = one_line(
            f"best title match '{match.title}' is in era '{match.era}', not the supplied era '{era}'", limit=200,
        )
        issues.append(Issue(IssueCode.WRONG_ERA, wrong_era))
        return ClassifyResult(
            status="mismatch", computed_sha1=computed_sha1, matched_title=match.title, similarity=match.score,
            reason=(
                f"title '{title}' is a {match.score:.0%} match for indexed title "
                f"'{match.title}' in era '{match.era}', outside the supplied era '{era}', "
                "and no hash from this file matches any entry"
            ),
            matched_era=match.era, issues=tuple(issues),
        )

    return ClassifyResult(
        status="not_in_index", computed_sha1=computed_sha1, matched_title=None, similarity=None,
        reason="no sha1/md5/crc32 match and no confident title match in hash_index.json",
        issues=tuple(issues),
    )


def _index_unchecked(path: Path, computed_sha1: str, exc: IndexUnavailable) -> ClassifyResult:
    """The "unchecked" result for an unusable index: the file hashed fine, so
    computed_sha1 is kept. Logged once per backoff window like detect()."""
    reason = f"hash index unavailable: {one_line(str(exc))}"
    _hash_lookup._report_index_failure(f"{reason} (while classifying {str(path)!r})")
    return ClassifyResult(
        status="unchecked", computed_sha1=computed_sha1, matched_title=None, similarity=None,
        reason=reason, issues=(Issue(INDEX_UNAVAILABLE, reason),),
    )


def _best_other_era_match(matches: list[TitleMatch], era: str) -> TitleMatch | None:
    """The best of *matches* (sorted best first) outside *era*, or None. Only
    consulted once *era* itself has no match at or above the threshold; the
    filter guards against the index changing between the two searches."""
    return next((candidate for candidate in matches if candidate.era != era), None)


def _entry_era(entry: object) -> str | None:
    """The era of a matched index entry, or None when it is missing or not a
    string (index files can be user-built, so values are not trusted)."""
    era = entry.get("era") if isinstance(entry, dict) else None
    return era if isinstance(era, str) else None
