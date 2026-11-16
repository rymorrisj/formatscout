from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .hashing.title_match import fuzzy_title_match
from .result import ClassifyResult, HashKind, Issue
from .validators.chd_validator import extract_embedded_sha1

_INDEX_PATH = _hash_lookup.default_index_path()
_DEFAULT_THRESHOLD = 0.80


def classify(
    path: Path, title: str, era: str | None, *, threshold: float = _DEFAULT_THRESHOLD,
) -> ClassifyResult:
    """Five-state verification classification, see ClassifyResult for what
    each status means. Establishes a classification from scratch (ingest, or
    a from-scratch re-check), unlike verify(), which compares against an
    already-known expected_sha1.

    Only an OSError while hashing the file becomes status="unchecked", and
    only a missing custom index file (FileNotFoundError) is treated as an
    empty index. Index download errors still escape: a failed or suppressed
    download (offline mode, backoff) or an oversized/corrupt index raises an
    OSError subclass from the index loader instead of returning a result.
    """
    try:
        hashes = _hash_lookup.hash_file(path)
    except OSError as exc:
        return ClassifyResult(
            status="unchecked", computed_sha1=None, matched_title=None, similarity=None,
            reason=f"could not hash file: {exc}",
            issues=(Issue("hash_failed", f"could not hash file: {exc}"),),
        )

    computed_sha1 = hashes.sha1
    issues: list[Issue] = []

    try:
        index, md5_index, crc32_index = _hash_lookup.load_index(_INDEX_PATH)
    except FileNotFoundError:
        index, md5_index, crc32_index = {}, {}, {}
        issues.append(Issue("index_missing", "index file not found, treated as an empty index"))

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
                "chd_rawsha1_missing", "no usable embedded rawsha1 in the CHD header, raw file sha1 looked up instead",
            ))

    if lookup_sha1 in index:
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

    match = fuzzy_title_match(title, era, _INDEX_PATH, threshold=threshold)
    if match is not None:
        matched_title, similarity = match
        return ClassifyResult(
            status="mismatch", computed_sha1=computed_sha1, matched_title=matched_title, similarity=similarity,
            reason=(
                f"title '{title}' is a {similarity:.0%} match for indexed title "
                f"'{matched_title}', but no hash from this file matches any entry for it"
            ),
            # fuzzy_title_match() only searches titles whose entry era == era.
            matched_era=era, issues=tuple(issues),
        )

    return ClassifyResult(
        status="not_in_index", computed_sha1=computed_sha1, matched_title=None, similarity=None,
        reason="no sha1/md5/crc32 match and no confident title match in hash_index.json",
        issues=tuple(issues),
    )


def _entry_era(entry: object) -> str | None:
    """The era of a matched index entry, or None when it is missing or not a
    string (index files can be user-built, so values are not trusted)."""
    era = entry.get("era") if isinstance(entry, dict) else None
    return era if isinstance(era, str) else None
