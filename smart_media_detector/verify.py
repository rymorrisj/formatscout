from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .result import VerifyResult

_INDEX_PATH = Path(__file__).parent / "hashing" / "hash_index.json"


def verify(path: Path, expected_sha1: str) -> VerifyResult:
    """Re-check a single file against a known-good sha1, hash lookup only.

    Unlike detect(), this never runs the magic-byte/structural/directory/
    fallback tiers. It mirrors bios_placement.py's direct use of
    hash_file() for a placed-file check, just against the bundled hash
    index instead of one hardcoded hash.
    """
    computed_sha1 = _hash_lookup.hash_file(path)["sha1"]

    try:
        index, _md5_index, _crc32_index = _hash_lookup._load_cached(_INDEX_PATH)
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
