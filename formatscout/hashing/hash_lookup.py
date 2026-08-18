import hashlib
import json
import os
import tempfile
import urllib.request
import zlib
from pathlib import Path

from ..result import HashFileResult, ScanResult
from ..validators.chd_validator import extract_embedded_sha1

_CHUNK = 65536

# hash_index.json is not shipped in the built distribution (it's ~88MB), so
# it is cached locally on first use instead. See _fetch_default_index().
_CACHE_DIR = Path.home() / ".formatscout"
_DEFAULT_INDEX_PATH = _CACHE_DIR / "hash_index.json"

_INDEX_DOWNLOAD_URL = "https://github.com/rymorrisj/formatscout/releases/download/full_hash_v0.1.0/hash_index.json"
_INDEX_SHA256 = "17fa892b072b4d942ef920eef8bdee034e8e0acdf508ab484f1afefe992dfce2"

# Cached per index_path: (mtime, sha1_index, md5_index, crc32_index). Keyed by mtime
# so a rebuilt hash_index.json (via build_index.py) is picked up without a restart.
_index_cache: dict[Path, tuple[float, dict, dict, dict]] = {}


def default_index_path() -> Path:
    """Local cache location for hash_index.json, fetched here on first use."""
    return _DEFAULT_INDEX_PATH


def _fetch_default_index() -> None:
    """Download, sha256-verify, and cache hash_index.json.

    No offline fallback: a failed download or a hash mismatch raises and
    propagates to the caller rather than degrading to an empty index.
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(_INDEX_DOWNLOAD_URL, timeout=30) as response:
        data = response.read()

    digest = hashlib.sha256(data).hexdigest()
    if digest != _INDEX_SHA256:
        raise ValueError(
            f"hash_index.json download failed sha256 verification: "
            f"expected {_INDEX_SHA256}, got {digest}"
        )

    fd, tmp_name = tempfile.mkstemp(
        dir=_CACHE_DIR, prefix=f".{_DEFAULT_INDEX_PATH.name}.", suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, _DEFAULT_INDEX_PATH)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def hash_file(path: Path) -> HashFileResult:
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    crc = 0

    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            sha1.update(chunk)
            md5.update(chunk)
            crc = zlib.crc32(chunk, crc)

    return HashFileResult(
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
        crc32=format(crc & 0xFFFFFFFF, "08x"),
    )


def lookup(path: Path, index_path: Path) -> ScanResult | None:
    """Tier-1 identification: match a file's hashes against the bundled index.

    Three descending tiers, each with its own confidence:

      sha1  (1.0)  Cryptographic digest. Treat a hit as identification.
      md5   (0.85) Broken against deliberate collisions. A chance
                   collision on real dump data is not a practical concern.
      crc32 (0.75) NOT a cryptographic digest. A 32-bit error-detection
                   checksum, not a hash: collisions exist by the
                   pigeonhole principle at ~2**32 inputs and can be
                   constructed on purpose.

                   A hit is a hint the file is probably the indexed
                   title, never proof. Do not use this tier to
                   authenticate a file or to make an unsafe decision.
    """
    index, md5_index, crc32_index = load_index(index_path)
    if not index:
        return None

    # CHD containers never match on raw file bytes. chdman compresses and
    # wraps the original track data, so hashing the .chd file itself cannot
    # equal a Redump hash of the original dump. Use the header's embedded
    # rawsha1 field instead (the raw, uncompressed hash).
    if path.suffix.lower() == ".chd":
        embedded_sha1 = extract_embedded_sha1(path)
        if embedded_sha1 is None:
            return None
        entry = index.get(embedded_sha1)
        if entry is None:
            return None
        return ScanResult(
            title=entry.get("title"),
            platform=entry.get("platform"),
            era=entry.get("era"),
            confidence=1.0,
            reason=f"sha1 match (CHD embedded rawsha1): {embedded_sha1}",
        )

    hashes = hash_file(path)

    entry = index.get(hashes.sha1)
    if entry is not None:
        return ScanResult(
            title=entry.get("title"),
            platform=entry.get("platform"),
            era=entry.get("era"),
            confidence=1.0,
            reason=f"sha1 match: {hashes.sha1}",
        )

    entry = md5_index.get(hashes.md5)
    if entry is not None:
        return ScanResult(
            title=entry.get("title"),
            platform=entry.get("platform"),
            era=entry.get("era"),
            confidence=0.85,
            reason=f"md5 match: {hashes.md5}",
        )

    entry = crc32_index.get(hashes.crc32)
    if entry is not None:
        return ScanResult(
            title=entry.get("title"),
            platform=entry.get("platform"),
            era=entry.get("era"),
            confidence=0.75,
            reason=f"crc32 match: {hashes.crc32}",
        )

    return None


def load_index(index_path: Path) -> tuple[dict, dict, dict]:
    """Load (and mtime-cache) the sha1/md5/crc32 indices at *index_path*.

    Documented internal API: called across module boundaries by classify.py,
    verify.py, and hashing/title_match.py, not just from within this module,
    so it is not underscore-prefixed despite not being part of the public
    formatscout.__init__ surface. Raises FileNotFoundError if index_path
    does not exist and is not the default cache location (which is fetched
    instead, see _fetch_default_index).
    """
    if not index_path.exists():
        if index_path == _DEFAULT_INDEX_PATH:
            _fetch_default_index()
        else:
            raise FileNotFoundError(
                f"Hash index not found at {index_path}. "
                "Run build_index.py to generate it from your DAT files."
            )

    mtime = index_path.stat().st_mtime
    cached = _index_cache.get(index_path)
    if cached is not None and cached[0] == mtime:
        return cached[1], cached[2], cached[3]

    with index_path.open("r", encoding="utf-8") as fh:
        index = json.load(fh)

    md5_index: dict[str, dict] = {}
    crc32_index: dict[str, dict] = {}
    for entry in index.values():
        md5 = entry.get("md5")
        if md5 and md5 not in md5_index:
            md5_index[md5] = entry
        crc32 = entry.get("crc32")
        if crc32 and crc32 not in crc32_index:
            crc32_index[crc32] = entry

    _index_cache[index_path] = (mtime, index, md5_index, crc32_index)
    return index, md5_index, crc32_index
