from .classify import classify
from .detector import detect
from .hashing.hash_lookup import hash_file
from .result import ClassifyResult, HashFileResult, ScanResult, VerifyResult
from .validators.chd_validator import extract_embedded_sha1
from .verify import verify

# Kept in sync manually with [project].version in pyproject.toml, no dynamic
# version tooling.
__version__ = "0.1.0"

__all__ = [
    "detect", "ScanResult", "verify", "VerifyResult", "classify", "ClassifyResult",
    "hash_file", "HashFileResult", "extract_embedded_sha1",
]
