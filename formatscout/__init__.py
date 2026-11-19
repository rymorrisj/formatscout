from .classify import classify
from .detector import detect
from .hashing.hash_lookup import hash_file
from .index import IndexIntegrityError, IndexUnavailable, ensure_index
from .result import (
    Candidate,
    ClassifyResult,
    Era,
    HashFileResult,
    HashKind,
    Issue,
    IssueCode,
    Method,
    ScanResult,
    Status,
    Tier,
    VerifyResult,
    tier_for_confidence,
)
from .validators.chd_validator import extract_embedded_sha1
from .verify import verify

# Kept in sync manually with [project].version in pyproject.toml, no dynamic
# version tooling.
__version__ = "0.2.0"

__all__ = [
    "detect", "ScanResult", "verify", "VerifyResult", "classify", "ClassifyResult",
    "hash_file", "HashFileResult", "extract_embedded_sha1", "Era",
    "Status", "Method", "Tier", "Candidate", "Issue", "IssueCode", "HashKind", "tier_for_confidence",
    "ensure_index", "IndexUnavailable", "IndexIntegrityError",
]
