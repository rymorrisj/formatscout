import hashlib
import json
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any

from ..result import HashFileResult, ScanResult
from ..validators.chd_validator import extract_embedded_sha1

log = logging.getLogger(__name__)

_CHUNK = 65536

# hash_index.json is not shipped in the built distribution (it's ~88MB), so
# it is downloaded on first use and cached locally instead. See
# _fetch_default_index(). _CACHE_DIR and _DEFAULT_INDEX_PATH must name the
# same directory (the download's temp file lives in _CACHE_DIR and is
# os.replace()d onto _DEFAULT_INDEX_PATH). Both are read at call time, never
# captured, so tests can re-point them.
_CACHE_DIR = Path.home() / ".formatscout"
_DEFAULT_INDEX_PATH = _CACHE_DIR / "hash_index.json"

_INDEX_DOWNLOAD_URL = "https://github.com/rymorrisj/formatscout/releases/download/full_hash_v0.1.0/hash_index.json"
_INDEX_SHA256 = "17fa892b072b4d942ef920eef8bdee034e8e0acdf508ab484f1afefe992dfce2"

# Download limits. The real index is ~88MB: the download cap leaves headroom
# without letting a hostile or broken server stream unbounded data to disk.
# The load cap is larger because a user-built index (build_index.py) is not
# tied to the release asset, but json.load() of a huge file still needs a
# sane ceiling before it allocates.
_MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
_MAX_INDEX_BYTES = 256 * 1024 * 1024
_DOWNLOAD_CHUNK = 1024 * 1024
_SOCKET_TIMEOUT_SECONDS = 30.0  # per socket operation, not for the whole download
_DOWNLOAD_DEADLINE_SECONDS = 600.0  # overall wall budget for one download attempt
_FETCH_BACKOFF_SECONDS = 300.0  # no new download attempt this long after a failure
_STALE_TEMP_SECONDS = 3600.0  # leftover download temp files older than this are removed

_OFFLINE_ENV = "FORMATSCOUT_OFFLINE"
_FAILURE_MARKER_NAME = ".hash_index.fetch_failed"

# Clock seams: tests patch these instead of the global time module.
_monotonic = time.monotonic
_wall_time = time.time

# Monotonic timestamp of this process's last failed download, None if none
# (or the last attempt succeeded). The marker file extends the same backoff
# across processes.
_last_fetch_failure: float | None = None

# Monotonic timestamp of the last index-failure warning emitted by this
# process (see _report_index_failure()); None until one is logged or after a
# successful download. Later failures inside the backoff window log at debug.
_failure_logged_at: float | None = None

# (path, size, mtime_ns) -> "managed" for default-cache files already examined
# in this process, so the sidecar is read (and at most the ~88MB file hashed)
# once per file version, not once per call. managed=True means the file
# carries a valid provenance sidecar (we downloaded it, so it may be
# quarantined if bad); False means user-supplied (never quarantined).
_verified_default: dict[tuple[Path, int, int], bool] = {}

# Provenance sidecar written next to the cache by a successful download:
# "<cache name>.meta", JSON {version, sha256, size, mtime_ns, url}. Its
# presence is what marks the cache as one *we* downloaded and pinned. A cache
# file with no (valid) sidecar is treated as user-supplied, e.g. one built with
# build_index.py and dropped at the cache path, and is never pin-checked,
# hashed or quarantined for failing the pin.
_SIDECAR_SUFFIX = ".meta"
_SIDECAR_VERSION = 1
_MAX_SIDECAR_BYTES = 4096
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

# Quarantine names tried in order: .corrupt, .corrupt.1 ... .corrupt.5.
_QUARANTINE_SLOTS = 6

# Cached per index_path: (mtime, sha1_index, md5_index, crc32_index). Keyed by mtime
# so a rebuilt hash_index.json (via build_index.py) is picked up without a restart.
_index_cache: dict[Path, tuple[float, dict, dict, dict]] = {}


class _IndexUnavailableError(OSError):
    """The hash index cannot be obtained or used (private to the package).

    Raised for: downloads disabled by FORMATSCOUT_OFFLINE, a download attempt
    suppressed by the failure backoff, a failed download (the original error
    is chained as __cause__), and an index file that is too large or corrupt.
    Deliberately not a FileNotFoundError: classify()/verify() treat that as
    "no index built" and degrade to empty, whereas this means the index
    exists or should exist and could not be trusted or fetched.
    """


class _IndexCorruptError(_IndexUnavailableError):
    """An index file exists but is oversized, not valid JSON, or malformed."""


def default_index_path() -> Path:
    """Local cache location for hash_index.json, downloaded here on first use."""
    return _DEFAULT_INDEX_PATH


# ── Download ─────────────────────────────────────────────────────────────────

class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses any redirect whose target is not https (no TLS downgrade)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        if scheme != "https":
            raise urllib.error.URLError(
                f"refusing redirect to non-https URL (scheme {scheme!r})"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_index_url(url: str, timeout: float) -> Any:
    """Open *url* (https only, including every redirect) and return the
    response, usable as a context manager with a read(n) method.

    Module-level seam: tests replace this function with an in-memory stream.
    TLS certificate and hostname verification stay at urllib's defaults and
    are never relaxed here.
    """
    if urllib.parse.urlsplit(url).scheme.lower() != "https":
        raise ValueError("hash index download URL must be https")
    opener = urllib.request.build_opener(_HttpsOnlyRedirectHandler())
    return opener.open(url, timeout=timeout)


def _declared_length(response: Any) -> int | None:
    """Content-Length of *response* as an int, or None if absent/unparseable."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        return int(headers.get("Content-Length"))
    except (TypeError, ValueError):
        return None


def _remove_stale_temp_files() -> None:
    """Best-effort removal of download temp files left by a killed process."""
    try:
        cutoff = _wall_time() - _STALE_TEMP_SECONDS
        for stale in _CACHE_DIR.glob(f".{_DEFAULT_INDEX_PATH.name}.*.tmp"):
            try:
                if stale.stat().st_mtime < cutoff:
                    stale.unlink()
            except OSError:
                pass
    except OSError:
        pass


def _sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + _SIDECAR_SUFFIX)


def _write_sidecar(path: Path, sha256: str, size: int, mtime_ns: int) -> None:
    """Atomically write the provenance sidecar for the cache file at *path*
    (temp file in the same directory, then os.replace). Raises OSError."""
    payload = json.dumps({
        "version": _SIDECAR_VERSION,
        "sha256": sha256,
        "size": size,
        "mtime_ns": mtime_ns,
        "url": _INDEX_DOWNLOAD_URL,
    }).encode("utf-8")
    sidecar = _sidecar_path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=sidecar.parent, prefix=f".{sidecar.name}.", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, sidecar)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _read_sidecar(path: Path) -> tuple[str, int, int] | None:
    """(sha256, size, mtime_ns) from the sidecar next to *path*, or None when
    there is no usable one.

    Absent, unreadable, oversized, non-JSON or wrongly-shaped sidecars all
    return None, i.e. the cache is then treated as user-supplied. A corrupt
    sidecar means provenance cannot be proven either way; we choose not to
    quarantine a file on that evidence alone (it may be someone's own index)
    and log it once per file version. The bad sidecar is left in place (no
    writes on the read path); the next download overwrites it.
    """
    sidecar = _sidecar_path(path)
    try:
        with sidecar.open("rb") as fh:
            raw = fh.read(_MAX_SIDECAR_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        log.warning("ignoring unreadable hash index sidecar %s (%s)", sidecar, type(exc).__name__)
        return None
    try:
        if len(raw) > _MAX_SIDECAR_BYTES:
            raise ValueError("too large")
        meta = json.loads(raw.decode("utf-8"))
        sha256, size, mtime_ns = meta["sha256"], meta["size"], meta["mtime_ns"]
        if not (
            isinstance(sha256, str) and _SHA256_RE.fullmatch(sha256)
            and type(size) is int and size >= 0
            and type(mtime_ns) is int and mtime_ns >= 0
        ):
            raise ValueError("bad field")
    except (ValueError, TypeError, KeyError, RecursionError):
        log.warning("ignoring malformed hash index sidecar %s; treating the cache as user-supplied", sidecar)
        return None
    return sha256, size, mtime_ns


def _download_default_index() -> None:
    """Stream the index to a temp file in the cache dir, verify, and atomically
    install it together with its provenance sidecar (see _write_sidecar()).
    No backoff/offline logic here, see _fetch_default_index().

    Streams in chunks with an incremental sha256 (never holds the whole body
    in memory), enforces _MAX_DOWNLOAD_BYTES and an overall monotonic
    deadline in addition to the per-socket timeout, and deletes the temp file
    on any failure. Raises ValueError for an oversized body or a sha256
    mismatch, TimeoutError past the deadline, and urllib/OS errors as-is.
    The deadline is checked between reads; a stalled read is bounded by the
    per-socket timeout, so the worst-case overrun is one socket timeout.
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _remove_stale_temp_files()

    deadline = _monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    digest = hashlib.sha256()
    total = 0

    fd, tmp_name = tempfile.mkstemp(
        dir=_CACHE_DIR, prefix=f".{_DEFAULT_INDEX_PATH.name}.", suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            with _open_index_url(_INDEX_DOWNLOAD_URL, _SOCKET_TIMEOUT_SECONDS) as response:
                read_some = getattr(response, "read1", None) or response.read
                declared = _declared_length(response)
                if declared is not None and declared > _MAX_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"hash_index.json download declares {declared} bytes, "
                        f"over the {_MAX_DOWNLOAD_BYTES} byte limit"
                    )
                while True:
                    if _monotonic() > deadline:
                        raise TimeoutError(
                            f"hash_index.json download exceeded {_DOWNLOAD_DEADLINE_SECONDS:g}s"
                        )
                    # read1() returns as soon as any data arrives (at most one
                    # underlying socket read), so a slow-drip server cannot hold
                    # the loop inside one read() waiting for a full chunk and
                    # starve the deadline check above. Plain read() is the
                    # fallback for response objects without read1().
                    chunk = read_some(_DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"hash_index.json download exceeded the {_MAX_DOWNLOAD_BYTES} byte limit"
                        )
                    digest.update(chunk)
                    fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())

        actual = digest.hexdigest()
        if actual != _INDEX_SHA256:
            raise ValueError(
                f"hash_index.json download failed sha256 verification: "
                f"expected {_INDEX_SHA256}, got {actual}"
            )
        # Provenance sidecar first, then the index. A crash in between leaves
        # a sidecar that does not match the (absent or older) index, which
        # fails closed: the next load quarantines or refetches. The reverse
        # order would leave a verified index that looks user-supplied. The
        # mtime_ns is read from the temp file; rename keeps it, so it is what
        # stat() reports for the installed file.
        stat = os.stat(tmp_path)
        _write_sidecar(_DEFAULT_INDEX_PATH, actual, stat.st_size, stat.st_mtime_ns)
        try:
            os.replace(tmp_path, _DEFAULT_INDEX_PATH)
        except BaseException:
            _sidecar_path(_DEFAULT_INDEX_PATH).unlink(missing_ok=True)
            raise
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _failure_marker_path() -> Path:
    return _CACHE_DIR / _FAILURE_MARKER_NAME


def _offline_requested() -> bool:
    return os.environ.get(_OFFLINE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _raise_if_fetch_blocked() -> None:
    """Raise _IndexUnavailableError, without touching the network, when
    FORMATSCOUT_OFFLINE is set or a download failed within the backoff window
    (in this process, or in any process via the failure marker file)."""
    if _offline_requested():
        raise _IndexUnavailableError(f"downloads disabled by {_OFFLINE_ENV}")

    if _last_fetch_failure is not None:
        remaining = _FETCH_BACKOFF_SECONDS - (_monotonic() - _last_fetch_failure)
        if remaining > 0:
            raise _IndexUnavailableError(
                f"recent download failed; not retrying for {remaining:.0f}s"
            )

    try:
        age = _wall_time() - _failure_marker_path().stat().st_mtime
    except OSError:
        return
    # A negative age means the clock moved backwards; do not trust the marker.
    if 0 <= age < _FETCH_BACKOFF_SECONDS:
        raise _IndexUnavailableError(
            f"recent download failed; not retrying for {_FETCH_BACKOFF_SECONDS - age:.0f}s"
        )


def _record_fetch_failure() -> None:
    """Start the backoff window: in-process, plus a marker file (errors ignored)."""
    global _last_fetch_failure
    _last_fetch_failure = _monotonic()
    try:
        marker = _failure_marker_path()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        pass


def _report_index_failure(message: str) -> None:
    """Log an index failure once per backoff window per process.

    The first failure in a window is one warning line (no traceback); every
    later one in the same window, such as each file of a large scan hitting
    the same offline/backoff error, is logged at debug. A success or the
    window elapsing re-arms the warning.
    """
    global _failure_logged_at
    now = _monotonic()
    if _failure_logged_at is None or not 0 <= now - _failure_logged_at < _FETCH_BACKOFF_SECONDS:
        _failure_logged_at = now
        log.warning("%s", message)
    else:
        log.debug("%s", message)


def _record_fetch_success() -> None:
    global _last_fetch_failure, _failure_logged_at
    _last_fetch_failure = None
    _failure_logged_at = None
    try:
        _failure_marker_path().unlink(missing_ok=True)
    except OSError:
        pass


def _fetch_default_index() -> None:
    """Download, sha256-verify, and cache hash_index.json.

    Refuses (raising _IndexUnavailableError, no network access) when
    FORMATSCOUT_OFFLINE is set or a recent attempt failed, see
    _raise_if_fetch_blocked(). Any download failure is recorded for the
    backoff and re-raised as _IndexUnavailableError chained from the cause.
    No offline fallback to an empty index: errors propagate to the caller.
    """
    _raise_if_fetch_blocked()
    try:
        _download_default_index()
    except Exception as exc:
        _record_fetch_failure()
        reason = " ".join(f"{type(exc).__name__}: {exc}".split())
        _report_index_failure(f"hash index download failed: {reason}")
        raise _IndexUnavailableError(f"download failed ({reason[:160]})") from exc
    _record_fetch_success()


# ── Hashing and lookup ───────────────────────────────────────────────────────

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
    """Tier-1 identification: match a file's hashes against the hash index
    (downloaded and cached on first use, see _fetch_default_index()).

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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_DOWNLOAD_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _mark_verified(path: Path) -> None:
    """Record the freshly downloaded file at *path* as managed for this process."""
    stat = path.stat()
    _verified_default[(path, stat.st_size, stat.st_mtime_ns)] = True


def _move_no_overwrite(src: Path, dst: Path) -> None:
    """Move *src* to *dst*, raising FileExistsError instead of replacing.

    os.link() refuses to overwrite on every platform, so link-then-unlink is
    an atomic no-overwrite move. Where hard links are unavailable (some
    filesystems) it falls back to exists() + os.rename(); that has a small
    window in which another process could take the same name (POSIX rename
    would then replace it, Windows refuses). The most that race can lose is
    an already-quarantined copy, never the live index.
    """
    try:
        os.link(src, dst)
    except (FileExistsError, FileNotFoundError):
        raise
    except OSError:
        if dst.exists():
            raise FileExistsError(str(dst)) from None
        os.rename(src, dst)
        return
    try:
        os.unlink(src)
    except FileNotFoundError:
        pass  # another process already moved it; our link is one more copy
    except OSError:
        # src could not be removed (e.g. a Windows sharing violation while
        # another process has it open): drop our link again so a failed
        # attempt does not use up a quarantine slot, then report the failure.
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise


def _quarantine(path: Path) -> None:
    """Move a bad default-cache file aside, never overwriting an earlier
    quarantined copy, and forget everything cached about it.

    The destination is the first free of <name>.corrupt, .corrupt.1 ...
    .corrupt.5; if all are taken this raises _IndexUnavailableError asking
    the user to clean up (the file stays where it is). At most six copies are
    kept, which bounds the disk this can consume.

    The stale provenance sidecar is removed only after the data file has
    moved, so a failure part-way never leaves a file that looks user-supplied.
    A file that is already gone (another process quarantined it first) counts
    as done, and then the sidecar is left alone because it may belong to that
    process's refetch. Any other OS error (e.g. a Windows sharing violation)
    raises _IndexUnavailableError. That is deliberately not recorded as a
    download failure: no download was attempted, so it must not start the
    backoff.
    """
    _index_cache.pop(path, None)
    for key in [k for k in _verified_default if k[0] == path]:
        del _verified_default[key]

    for slot in range(_QUARANTINE_SLOTS):
        target = path.with_name(path.name + (".corrupt" if slot == 0 else f".corrupt.{slot}"))
        try:
            _move_no_overwrite(path, target)
        except FileExistsError:
            continue
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _IndexUnavailableError(
                f"cannot quarantine unusable index cache ({type(exc).__name__})"
            ) from exc
        log.warning("quarantined unusable hash index cache: %s -> %s", path, target.name)
        break
    else:
        raise _IndexUnavailableError(
            f"cannot quarantine unusable index cache: {path.name}.corrupt through "
            f"{path.name}.corrupt.{_QUARANTINE_SLOTS - 1} already exist in {path.parent}; "
            "please delete the old quarantined copies"
        )

    try:
        _sidecar_path(path).unlink(missing_ok=True)
    except OSError:
        # A refetch overwrites the sidecar; a stale one next to no index is inert.
        log.debug("could not remove stale hash index sidecar for %s", path)


def _default_cache_matches_pin(path: Path, size: int) -> bool:
    """True if the default cache file is within the size cap and its sha256
    equals _INDEX_SHA256. Oversized files are rejected without being read."""
    if size > _MAX_INDEX_BYTES:
        return False
    try:
        return _sha256_file(path) == _INDEX_SHA256
    except OSError:
        return False


def _cache_provenance_ok(path: Path, stat: os.stat_result, recorded: tuple[str, int, int]) -> bool:
    """Does the file at *path* still match what its sidecar recorded?

    "Matches" means:
      1. the sidecar's sha256 equals the current pin (a different pin means
         the file is from another release and must be replaced); and
      2. the file's (size, mtime_ns) equal the recorded identity. This is the
         cheap path taken on every process start: no hashing; or
      3. only mtime_ns differs (a copy or backup restore), size equals the
         recorded size, and the file hashes to the pin: accepted, and the
         sidecar is refreshed.
    Any other difference (different size, or same size but wrong hash) is a
    modified or foreign file: no match. Content at rest is not re-hashed when
    the identity matches; the download was pin-verified and the JSON parse
    still guards against a truncated or garbled file.
    """
    sha256, size, mtime_ns = recorded
    if sha256 != _INDEX_SHA256:
        return False
    if stat.st_size == size and stat.st_mtime_ns == mtime_ns:
        return True
    if stat.st_size != size or not _default_cache_matches_pin(path, stat.st_size):
        return False
    try:
        _write_sidecar(path, sha256, stat.st_size, stat.st_mtime_ns)
    except OSError:
        pass  # still accepted for this process; just re-hashed next time
    return True


def _parse_index(index_path: Path) -> tuple[dict, dict, dict]:
    """mtime-cached parse of *index_path* into (sha1, md5, crc32) indices.

    Refuses files over _MAX_INDEX_BYTES before json.load(). Raises
    _IndexCorruptError for an oversized, non-JSON, or malformed file.
    """
    stat = index_path.stat()
    mtime = stat.st_mtime
    cached = _index_cache.get(index_path)
    if cached is not None and cached[0] == mtime:
        return cached[1], cached[2], cached[3]

    if stat.st_size > _MAX_INDEX_BYTES:
        raise _IndexCorruptError(
            f"index file is {stat.st_size} bytes, over the {_MAX_INDEX_BYTES} byte limit"
        )

    try:
        with index_path.open("r", encoding="utf-8") as fh:
            index = json.load(fh)
    except (ValueError, RecursionError) as exc:  # JSONDecodeError, UnicodeDecodeError
        raise _IndexCorruptError(f"index file is not valid JSON ({exc})") from exc
    if not isinstance(index, dict):
        raise _IndexCorruptError("index file is not a JSON object")

    md5_index: dict[str, dict] = {}
    crc32_index: dict[str, dict] = {}
    for entry in index.values():
        if not isinstance(entry, dict):
            raise _IndexCorruptError("index file has a non-object entry")
        md5 = entry.get("md5")
        if md5 and md5 not in md5_index:
            md5_index[md5] = entry
        crc32 = entry.get("crc32")
        if crc32 and crc32 not in crc32_index:
            crc32_index[crc32] = entry

    _index_cache[index_path] = (mtime, index, md5_index, crc32_index)
    return index, md5_index, crc32_index


def _load_default_index(path: Path) -> tuple[dict, dict, dict]:
    """Load the default cache, checking provenance only if we downloaded it.

    A file with a valid sidecar (written by our download) is "managed": once
    per process per (path, size, mtime_ns) it is compared with the sidecar
    and the pin (see _cache_provenance_ok); a mismatch quarantines it and
    refetches under the normal backoff rules. A file with no usable sidecar is
    user-supplied (for example one built with build_index.py): it gets only
    the size cap and JSON validity checks, is never hashed for the pin, and is
    never quarantined; if it is unusable the error says to delete it.

    A freshly downloaded file is pin-verified by the download itself. A
    managed file that fails to parse is quarantined and refetched.
    """
    fresh = False
    if not path.exists():
        _fetch_default_index()
        fresh = True
    stat = path.stat()
    key = (path, stat.st_size, stat.st_mtime_ns)

    if fresh:
        managed = True
        _verified_default[key] = True
    elif key in _verified_default:
        managed = _verified_default[key]
    else:
        recorded = _read_sidecar(path)
        if recorded is None:
            managed = False
            _verified_default[key] = False
        elif _cache_provenance_ok(path, stat, recorded):
            managed = True
            _verified_default[key] = True
        else:
            _quarantine(path)
            _fetch_default_index()
            fresh = managed = True
            _mark_verified(path)

    try:
        return _parse_index(path)
    except _IndexCorruptError as exc:
        if not managed:
            raise _IndexCorruptError(
                f"{exc}; {path} has no download record so it is treated as "
                "user-supplied and was left in place: fix it, or delete it to "
                "download the pinned index"
            ) from exc
        _quarantine(path)
        if fresh:
            # A pin-verified download that does not parse would just repeat on
            # refetch; start the backoff so callers do not re-download per call.
            _record_fetch_failure()
            raise
    _fetch_default_index()
    _mark_verified(path)  # the refetch was pin-verified by the download itself
    try:
        return _parse_index(path)
    except _IndexCorruptError:
        _quarantine(path)
        _record_fetch_failure()
        raise


def load_index(index_path: Path) -> tuple[dict, dict, dict]:
    """Load (and mtime-cache) the sha1/md5/crc32 indices at *index_path*.

    Documented internal API: called across module boundaries by classify.py,
    verify.py, and hashing/title_match.py, not just from within this module,
    so it is not underscore-prefixed despite not being part of the public
    formatscout.__init__ surface.

    Raises FileNotFoundError if index_path does not exist and is not the
    default cache location (which is downloaded instead, see
    _fetch_default_index). A FileNotFoundError raised while loading the
    default cache (a race with another process) is converted to
    _IndexUnavailableError. Raises _IndexUnavailableError (an OSError, not a
    FileNotFoundError) if the default index cannot be downloaded (offline mode,
    backoff window, network or integrity failure) or any index file is too
    large or corrupt.

    Only a default cache that carries our download's provenance sidecar is
    checked against the pin. A custom path, or a default-path file with no
    sidecar (e.g. a user-built index), is trusted as-is, subject to the size
    cap and JSON validity.
    """
    if index_path == _DEFAULT_INDEX_PATH:
        try:
            return _load_default_index(index_path)
        except FileNotFoundError as exc:
            # The default cache vanished mid-load (e.g. quarantined by another
            # process). That is an index problem, not "no index built".
            raise _IndexUnavailableError(
                "hash index cache disappeared while loading"
            ) from exc

    if not index_path.exists():
        raise FileNotFoundError(
            f"Hash index not found at {index_path}. "
            "Run build_index.py to generate it from your DAT files."
        )
    return _parse_index(index_path)
