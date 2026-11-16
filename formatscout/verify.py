from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .index_errors import INDEX_UNAVAILABLE, IndexUnavailable
from .index_path import coerce_index_path, resolve_index_path
from .result import Issue, VerifyResult
from .utils.text import one_line

# Override hook for the index path (None: explicit argument, then
# FORMATSCOUT_INDEX_PATH, then the default cache; see index_path.py). The test
# suite points it at a tmp path; leave it None in application code.
_INDEX_PATH: Path | None = None


def verify(
    path: Path, expected_sha1: str, *, index_path: "Path | str | None" = None, strict: bool = False,
) -> VerifyResult:
    """Re-check a single file against a known-good sha1, hash lookup only.

    Unlike detect(), this never runs the magic-byte/structural/directory/
    fallback tiers, it is a direct hash_file() check against the hash index
    (downloaded and cached on first use). See VerifyResult for what each status means, and classify()
    for the from-scratch equivalent that needs no prior expected_sha1.

    index_path: keyword-only, the hash index to use instead of the
    FORMATSCOUT_INDEX_PATH / default-cache resolution (see index_path.py).

    Note that this does not swallow read errors the way classify() does:
    an unreadable or missing path propagates the OSError from hash_file()
    to the caller rather than returning a result object. An index that cannot
    be obtained or used (offline mode, backoff, a failed download, an
    oversized or corrupt index) returns status="unchecked" with an
    INDEX_UNAVAILABLE issue (computed_sha1 is still set), or raises
    IndexUnavailable with strict=True. A missing custom index file
    (FileNotFoundError) is treated as an empty index.
    """
    explicit_index = coerce_index_path(index_path)
    computed_sha1 = _hash_lookup.hash_file(path).sha1

    try:
        resolved_index = resolve_index_path(explicit_index, override=_INDEX_PATH)
        try:
            index, _md5_index, _crc32_index = _hash_lookup.load_index(resolved_index)
        except FileNotFoundError:
            index = {}
    except IndexUnavailable as exc:
        if strict:
            raise
        reason = f"hash index unavailable: {one_line(str(exc))}"
        _hash_lookup._report_index_failure(f"{reason} (while verifying {str(path)!r})")
        return VerifyResult(
            status="unchecked",
            computed_sha1=computed_sha1,
            expected_sha1=expected_sha1,
            reason=reason,
            issues=(Issue(INDEX_UNAVAILABLE, reason),),
        )

    if computed_sha1 not in index:
        return VerifyResult(
            status="not_in_index",
            computed_sha1=computed_sha1,
            expected_sha1=expected_sha1,
            reason=f"sha1 {computed_sha1} not found in hash_index.json",
        )

    if computed_sha1 == expected_sha1:
        return VerifyResult(
            status="matched",
            computed_sha1=computed_sha1,
            expected_sha1=expected_sha1,
            reason=f"sha1 match: {computed_sha1}",
        )

    return VerifyResult(
        status="mismatched",
        computed_sha1=computed_sha1,
        expected_sha1=expected_sha1,
        reason=f"sha1 mismatch: computed {computed_sha1}, expected {expected_sha1}",
    )
