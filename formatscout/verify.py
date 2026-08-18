from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .result import VerifyResult

_INDEX_PATH = _hash_lookup.default_index_path()


def verify(path: Path, expected_sha1: str) -> VerifyResult:
    """Re-check a single file against a known-good sha1, hash lookup only.

    Unlike detect(), this never runs the magic-byte/structural/directory/
    fallback tiers, it is a direct hash_file() check against the bundled
    hash index. See VerifyResult for what each status means, and classify()
    for the from-scratch equivalent that needs no prior expected_sha1.

    Note that this does not swallow read errors the way classify() does:
    an unreadable or missing path propagates the OSError from hash_file()
    to the caller rather than returning a result object.
    """
    computed_sha1 = _hash_lookup.hash_file(path).sha1

    try:
        index, _md5_index, _crc32_index = _hash_lookup.load_index(_INDEX_PATH)
    except FileNotFoundError:
        index = {}

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
