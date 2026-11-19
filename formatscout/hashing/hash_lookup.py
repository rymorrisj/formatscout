import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any

from ..index_errors import IndexIntegrityError, IndexUnavailable
from ..result import HashFileResult, Method, ScanResult, Status
from ..validators.chd_validator import extract_embedded_sha1

log = logging.getLogger(__name__)

_CHUNK = 65536

# hash_index.json is not shipped in the built distribution (it's ~88MB), so
# it is downloaded on first use and cached locally instead. See
# _fetch_default_index().
#
# Nothing here touches the home directory at import time (Path.home() can
# raise, and importing the package must not). _CACHE_DIR and
# _DEFAULT_INDEX_PATH are override hooks, None meaning "compute from the home
# directory when needed": see _cache_dir() and default_index_path(). When both
# are set they must name the same directory (the download's temp file lives in
# the cache dir and is os.replace()d onto the default index path). Both are
# read at call time, never captured, so tests can re-point them.
_CACHE_DIR: Path | None = None
_DEFAULT_INDEX_PATH: Path | None = None
_CACHE_DIR_NAME = ".formatscout"
_INDEX_FILE_NAME = "hash_index.json"

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

# The parsed index of the one path used most recently: {index_path: (mtime,
# sha1_index, md5_index, crc32_index)}. Holds at most ONE entry, because a parsed
# real index is ~88MB on disk and several times that as Python objects. The
# previous entry is kept until its replacement has parsed successfully and is
# dropped only then, so a failed or oversized load never costs the entry that
# still works; the price is that two parsed indexes are alive at once while a
# replacement parses (peak memory is about twice one parsed index). Keyed by
# mtime so a rebuilt hash_index.json (via build_index.py) is picked up without
# a restart. Alternating between two index paths re-parses on every switch; use
# one path per process for the hot path. Guarded by _index_lock, which is held
# across the parse so concurrent callers parse a given file once, not per thread.
_index_cache: dict[Path, tuple[float, dict, dict, dict]] = {}
_index_lock = threading.RLock()


# The 0.1.3/0.1.4 private names, kept as aliases of the public exceptions in
# index_errors.py so existing `except`/`raises` on them see the same classes.
_IndexUnavailableError = IndexUnavailable
_IndexCorruptError = IndexIntegrityError


class _PinMismatchError(ValueError):
    """A download's sha256 differs from the pin (private; surfaces to callers
    as IndexIntegrityError chained from this)."""


def _cache_dir() -> Path:
    """Directory holding the cached index, its sidecar, temp files and the
    failure marker. Raises IndexUnavailable if the home directory is needed
    and cannot be determined."""
    if _CACHE_DIR is not None:
        return _CACHE_DIR
    if _DEFAULT_INDEX_PATH is not None:
        return _DEFAULT_INDEX_PATH.parent
    try:
        home = Path.home()
    except (RuntimeError, KeyError, OSError) as exc:
        raise IndexUnavailable(
            "cannot determine the home directory for the default index cache; "
            "set FORMATSCOUT_INDEX_PATH or pass index_path="
        ) from exc
    return home / _CACHE_DIR_NAME


def default_index_path() -> Path:
    """Local cache location for hash_index.json, downloaded here on first use.

    Computed on each call (never at import). Raises IndexUnavailable if the
    home directory cannot be determined.
    """
    if _DEFAULT_INDEX_PATH is not None:
        return _DEFAULT_INDEX_PATH
    return _cache_dir() / _INDEX_FILE_NAME


def is_default_cache_path(index_path: Path) -> bool:
    """True if *index_path* is the default cache location, the only path the
    download/provenance logic ever manages. False when the default cannot be
    computed (no home directory)."""
    try:
        return index_path == default_index_path()
    except IndexUnavailable:
        return False


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
        for stale in _cache_dir().glob(f".{default_index_path().name}.*.tmp"):
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


def _download_default_index(
    *, timeout: float | None = None, max_download_bytes: int | None = None, displace: bool = False,
) -> None:
    """Stream the index to a temp file in the cache dir, verify, and atomically
    install it together with its provenance sidecar (see _write_sidecar()).
    No backoff/offline logic here, see _fetch_default_index().

    *timeout* is the per-socket-operation timeout and *max_download_bytes* the
    body cap; None means _SOCKET_TIMEOUT_SECONDS / _MAX_DOWNLOAD_BYTES, read
    at call time. *displace* (used by a forced refresh) moves an existing file
    at the cache path that is not a pristine copy of one of our downloads
    aside, with the no-overwrite quarantine naming, after the new body has
    been verified and before it is installed; so a failed download never
    touches what is there.

    Streams in chunks with an incremental sha256 (never holds the whole body
    in memory), enforces _MAX_DOWNLOAD_BYTES and an overall monotonic
    deadline in addition to the per-socket timeout, and deletes the temp file
    on any failure. Raises ValueError for an oversized body or a sha256
    mismatch, TimeoutError past the deadline, and urllib/OS errors as-is.
    The deadline is checked between reads; a stalled read is bounded by the
    per-socket timeout, so the worst-case overrun is one socket timeout.
    """
    target = default_index_path()
    cache_dir = _cache_dir()
    limit = _MAX_DOWNLOAD_BYTES if max_download_bytes is None else max_download_bytes
    socket_timeout = _SOCKET_TIMEOUT_SECONDS if timeout is None else timeout
    cache_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_temp_files()

    deadline = _monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    digest = hashlib.sha256()
    total = 0

    fd, tmp_name = tempfile.mkstemp(
        dir=cache_dir, prefix=f".{target.name}.", suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            with _open_index_url(_INDEX_DOWNLOAD_URL, socket_timeout) as response:
                read_some = getattr(response, "read1", None) or response.read
                declared = _declared_length(response)
                if declared is not None and declared > limit:
                    raise ValueError(
                        f"hash_index.json download declares {declared} bytes, "
                        f"over the {limit} byte limit"
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
                    if total > limit:
                        raise ValueError(
                            f"hash_index.json download exceeded the {limit} byte limit"
                        )
                    digest.update(chunk)
                    fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())

        actual = digest.hexdigest()
        if actual != _INDEX_SHA256:
            raise _PinMismatchError(
                f"hash_index.json download failed sha256 verification: "
                f"expected {_INDEX_SHA256}, got {actual}"
            )
        if displace and not _is_pristine_download(target):
            # Missing (nothing to move), our own modified/older copy, or a
            # user-supplied file: moved aside, never overwritten. A pristine
            # managed copy is simply replaced by the atomic rename below.
            if os.path.lexists(target):
                _quarantine(target)
        # Provenance sidecar first, then the index. A crash in between leaves
        # a sidecar that does not match the (absent or older) index, which
        # fails closed: the next load quarantines or refetches. The reverse
        # order would leave a verified index that looks user-supplied. The
        # mtime_ns is read from the temp file; rename keeps it, so it is what
        # stat() reports for the installed file.
        stat = os.stat(tmp_path)
        _write_sidecar(target, actual, stat.st_size, stat.st_mtime_ns)
        try:
            os.replace(tmp_path, target)
        except BaseException:
            _sidecar_path(target).unlink(missing_ok=True)
            raise
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _failure_marker_path() -> Path:
    return _cache_dir() / _FAILURE_MARKER_NAME


def _offline_requested() -> bool:
    return os.environ.get(_OFFLINE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _raise_if_fetch_blocked(*, ignore_backoff: bool = False) -> None:
    """Raise IndexUnavailable, without touching the network, when
    FORMATSCOUT_OFFLINE is set or a download failed within the backoff window
    (in this process, or in any process via the failure marker file).
    *ignore_backoff* skips the backoff checks only, never the offline one."""
    if _offline_requested():
        raise IndexUnavailable(f"downloads disabled by {_OFFLINE_ENV}")

    if ignore_backoff:
        return

    if _last_fetch_failure is not None:
        remaining = _FETCH_BACKOFF_SECONDS - (_monotonic() - _last_fetch_failure)
        if remaining > 0:
            raise IndexUnavailable(
                f"recent download failed; not retrying for {remaining:.0f}s"
            )

    try:
        age = _wall_time() - _failure_marker_path().stat().st_mtime
    except OSError:
        return
    # A negative age means the clock moved backwards; do not trust the marker.
    if 0 <= age < _FETCH_BACKOFF_SECONDS:
        raise IndexUnavailable(
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


def _fetch_default_index(
    *, timeout: float | None = None, max_download_bytes: int | None = None, force: bool = False,
) -> None:
    """Download, sha256-verify, and cache hash_index.json.

    Refuses (raising IndexUnavailable, no network access) when
    FORMATSCOUT_OFFLINE is set or a recent attempt failed, see
    _raise_if_fetch_blocked(). Any download failure is recorded for the
    backoff and re-raised as IndexUnavailable chained from the cause (a sha256
    mismatch as IndexIntegrityError). A failure that is not a download failure
    (the home directory is unknown, an unusable file could not be moved aside)
    propagates as the IndexUnavailable it already is and does not start the
    backoff. No offline fallback to an empty index: errors propagate.

    *force* is a user-requested refresh: it ignores the backoff window (never
    the offline switch), moves a file at the cache path that is not a
    pristine managed copy aside instead of overwriting it, and on success
    forgets and re-marks everything cached about the path.
    """
    _raise_if_fetch_blocked(ignore_backoff=force)
    try:
        _download_default_index(timeout=timeout, max_download_bytes=max_download_bytes, displace=force)
    except IndexUnavailable:
        raise
    except Exception as exc:
        _record_fetch_failure()
        reason = " ".join(f"{type(exc).__name__}: {exc}".split())
        _report_index_failure(f"hash index download failed: {reason}")
        kind = IndexIntegrityError if isinstance(exc, _PinMismatchError) else IndexUnavailable
        raise kind(f"download failed ({reason[:160]})") from exc
    _record_fetch_success()
    if force:
        target = default_index_path()
        forget_index(target)
        try:
            _mark_verified(target)
        except OSError:
            # Moved or removed by another process since the install; the next
            # load re-checks it (or downloads) under the normal rules.
            pass


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
      md5   (0.85) Broken against deliberate collisions, and the index
                   stores no file sizes yet, so a chance collision cannot be
                   ruled out. Corroboration, not proof.
      crc32 (0.75) NOT a cryptographic digest. A 32-bit error-detection
                   checksum, not a hash: collisions exist by the
                   pigeonhole principle at ~2**32 inputs and can be
                   constructed on purpose.

                   A hit is a hint the file is probably the indexed
                   title, never proof. Do not use this tier to
                   authenticate a file or to make an unsafe decision.

    Result tags (see _hit()): only a sha1 hit on a non-CHD file is
    authoritative (and only when the entry has an era). The CHD embedded
    rawsha1 is a claim read from a forgeable header and is never checked
    against the hunks; md5 is corroboration only (the index stores no file
    sizes yet, so a collision cannot be ruled out); crc32 is a hint. Those
    three yield status "guess". An entry without an era yields status
    "unsupported" (detect() falls through on those).
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
        return _hit(
            entry, 1.0, f"sha1 match (CHD embedded rawsha1): {embedded_sha1}",
            Method.CHD_HEADER_CLAIM, proof=False, container="chd", evidence=("chd_embedded_rawsha1",),
        )

    hashes = hash_file(path)

    entry = index.get(hashes.sha1)
    if entry is not None:
        return _hit(entry, 1.0, f"sha1 match: {hashes.sha1}", Method.HASH_SHA1, proof=True)

    entry = md5_index.get(hashes.md5)
    if entry is not None:
        return _hit(entry, 0.85, f"md5 match: {hashes.md5}", Method.HASH_MD5, proof=False)

    entry = crc32_index.get(hashes.crc32)
    if entry is not None:
        return _hit(entry, 0.75, f"crc32 match: {hashes.crc32}", Method.HASH_CRC32, proof=False)

    return None


def _hit(
    entry: dict, confidence: float, reason: str, method: Method, *,
    proof: bool, container: str | None = None, evidence: tuple[str, ...] = (),
) -> ScanResult:
    """ScanResult for an index hit on *entry*.

    era is the entry's own value, unchanged. *proof* says whether this hash
    kind identifies the file (only a sha1 of the file's own bytes) or is a
    claim or hint (CHD header rawsha1, md5, crc32); it makes the result
    authoritative only when the entry has an era. An era-less entry (e.g. the unmapped "IBM - PC compatible" bucket)
    names a platform this package does not map to an era: "unsupported".
    """
    era = entry.get("era")
    authoritative = proof and era is not None
    if era is None:
        status = Status.UNSUPPORTED
    else:
        status = Status.IDENTIFIED if authoritative else Status.GUESS
    return ScanResult(
        title=entry.get("title"),
        platform=entry.get("platform"),
        era=era,
        confidence=confidence,
        reason=reason,
        status=status,
        method=method,
        authoritative=authoritative,
        container=container,
        evidence=evidence,
    )


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


def forget_index(path: Path) -> None:
    """Drop everything cached in this process about the index at *path*: the
    parsed index and the once-per-file-version provenance verdicts. The next
    load re-parses and re-checks. Documented internal API (used by index.py)."""
    with _index_lock:
        _index_cache.pop(path, None)
    # list() snapshots the keys in one step, so another thread adding a key
    # meanwhile cannot raise "dictionary changed size during iteration".
    for key in [k for k in list(_verified_default) if k[0] == path]:
        _verified_default.pop(key, None)


def _is_pristine_download(path: Path) -> bool:
    """True if *path* is, as far as its sidecar can prove, an unmodified copy
    of the currently pinned download: a valid sidecar for the current pin whose
    identity matches (or whose content hashes to the pin). Anything else
    (absent or malformed sidecar, another release, modified content) is not."""
    recorded = _read_sidecar(path)
    if recorded is None:
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    return _cache_provenance_ok(path, stat, recorded)


def _quarantine(path: Path) -> None:
    """Move a bad default-cache file aside, never overwriting an earlier
    quarantined copy, and forget everything cached about it.

    The destination is the first free of <name>.corrupt, .corrupt.1 ...
    .corrupt.5; if all are taken this raises IndexUnavailable asking
    the user to clean up (the file stays where it is). At most six copies are
    kept, which bounds the disk this can consume.

    The stale provenance sidecar is removed only after the data file has
    moved, so a failure part-way never leaves a file that looks user-supplied.
    A file that is already gone (another process quarantined it first) counts
    as done, and then the sidecar is left alone because it may belong to that
    process's refetch. Any other OS error (e.g. a Windows sharing violation)
    raises IndexUnavailable. That is deliberately not recorded as a
    download failure: no download was attempted, so it must not start the
    backoff.
    """
    forget_index(path)

    for slot in range(_QUARANTINE_SLOTS):
        target = path.with_name(path.name + (".corrupt" if slot == 0 else f".corrupt.{slot}"))
        try:
            _move_no_overwrite(path, target)
        except FileExistsError:
            continue
        except FileNotFoundError:
            return
        except OSError as exc:
            raise IndexUnavailable(
                f"cannot quarantine unusable index cache ({type(exc).__name__})"
            ) from exc
        log.warning("quarantined unusable hash index cache: %s -> %s", path, target.name)
        break
    else:
        raise IndexUnavailable(
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
    The cache holds one entry (see _index_cache): a different path or a
    changed mtime replaces it, but only once the new file has parsed, so a
    failure leaves the previous entry in place.

    Refuses files over _MAX_INDEX_BYTES before json.load(). Raises
    IndexIntegrityError for an oversized, non-JSON, or malformed file.
    """
    with _index_lock:
        stat = index_path.stat()
        mtime = stat.st_mtime
        cached = _index_cache.get(index_path)
        if cached is not None and cached[0] == mtime:
            return cached[1], cached[2], cached[3]

        if stat.st_size > _MAX_INDEX_BYTES:
            raise IndexIntegrityError(
                f"index file is {stat.st_size} bytes, over the {_MAX_INDEX_BYTES} byte limit"
            )

        try:
            with index_path.open("r", encoding="utf-8") as fh:
                index = json.load(fh)
        except (ValueError, RecursionError) as exc:  # JSONDecodeError, UnicodeDecodeError
            raise IndexIntegrityError(f"index file is not valid JSON ({exc})") from exc
        if not isinstance(index, dict):
            raise IndexIntegrityError("index file is not a JSON object")

        md5_index: dict[str, dict] = {}
        crc32_index: dict[str, dict] = {}
        for entry in index.values():
            if not isinstance(entry, dict):
                raise IndexIntegrityError("index file has a non-object entry")
            md5 = entry.get("md5")
            if md5 and md5 not in md5_index:
                md5_index[md5] = entry
            crc32 = entry.get("crc32")
            if crc32 and crc32 not in crc32_index:
                crc32_index[crc32] = entry

        # Replace only now that the new index is complete and valid.
        _index_cache.clear()
        _index_cache[index_path] = (mtime, index, md5_index, crc32_index)
        return index, md5_index, crc32_index


def _prepare_default_index(path: Path, fetch_opts: dict[str, Any] | None = None) -> tuple[bool, bool]:
    """Everything _load_default_index() does before parsing: download a missing
    default cache and decide whether the file there is "managed" (we downloaded
    it, so it is pin-checked and may be quarantined) or user-supplied. Returns
    (managed, fresh). Never parses the index. See _load_default_index() for
    the rules.
    """
    opts = fetch_opts or {}
    fresh = False
    if not path.exists():
        _fetch_default_index(**opts)
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
            _fetch_default_index(**opts)
            fresh = managed = True
            _mark_verified(path)
    return managed, fresh


def _load_default_index(path: Path, fetch_opts: dict[str, Any] | None = None) -> tuple[dict, dict, dict]:
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

    *fetch_opts* (timeout / max_download_bytes) is passed through to every
    download this load triggers.
    """
    opts = fetch_opts or {}
    managed, fresh = _prepare_default_index(path, opts)

    try:
        return _parse_index(path)
    except IndexIntegrityError as exc:
        if not managed:
            raise IndexIntegrityError(
                f"{exc}; {path} has no download record so it is treated as "
                "user-supplied and was left in place: fix it, or delete it and "
                "retry to download the pinned index"
            ) from exc
        _quarantine(path)
        if fresh:
            # A pin-verified download that does not parse would just repeat on
            # refetch; start the backoff so callers do not re-download per call.
            _record_fetch_failure()
            raise
    _fetch_default_index(**opts)
    _mark_verified(path)  # the refetch was pin-verified by the download itself
    try:
        return _parse_index(path)
    except IndexIntegrityError:
        _quarantine(path)
        _record_fetch_failure()
        raise


def load_index(
    index_path: Path, *, timeout: float | None = None, max_download_bytes: int | None = None,
) -> tuple[dict, dict, dict]:
    """Load (and mtime-cache) the sha1/md5/crc32 indices at *index_path*.

    Documented internal API: called across module boundaries by classify.py,
    verify.py, index.py and hashing/title_match.py, not just from within this
    module, so it is not underscore-prefixed despite not being part of the
    public formatscout.__init__ surface.

    Only the default cache location (see default_index_path()) is managed:
    a missing file there is downloaded, and a file with our download's
    provenance sidecar is checked against the pin. Every other path is
    user-supplied: trusted as-is subject to the size cap and JSON validity,
    never downloaded to, never pin-checked, never quarantined, and a sidecar
    next to it is ignored. *timeout* and *max_download_bytes* (per-socket
    timeout and body cap, None for the module defaults) apply only to a
    download of the default cache.

    Raises FileNotFoundError if index_path does not exist and is not the
    default cache location. A FileNotFoundError raised while loading the
    default cache (a race with another process) is converted to
    IndexUnavailable. Raises IndexUnavailable (an OSError, not a
    FileNotFoundError) if the default index cannot be downloaded (offline mode,
    backoff window, network failure), cannot be read, or is too large or
    corrupt (IndexIntegrityError for the last two and for a sha256 mismatch).
    """
    if is_default_cache_path(index_path):
        fetch_opts = {
            key: value for key, value in (("timeout", timeout), ("max_download_bytes", max_download_bytes))
            if value is not None
        }
        try:
            return _load_default_index(index_path, fetch_opts)
        except IndexUnavailable:
            raise
        except FileNotFoundError as exc:
            # The default cache vanished mid-load (e.g. quarantined by another
            # process). That is an index problem, not "no index built".
            raise IndexUnavailable(
                "hash index cache disappeared while loading"
            ) from exc
        except OSError as exc:
            raise IndexUnavailable(
                f"cannot read the hash index cache ({type(exc).__name__})"
            ) from exc

    try:
        if not index_path.exists():
            raise FileNotFoundError(
                f"Hash index not found at {index_path}. "
                "Run build_index.py to generate it from your DAT files."
            )
        return _parse_index(index_path)
    except (IndexUnavailable, FileNotFoundError):
        raise
    except OSError as exc:
        raise IndexUnavailable(
            f"cannot read the hash index at {index_path} ({type(exc).__name__})"
        ) from exc


def validate_index_file(
    index_path: Path, *, timeout: float | None = None, max_download_bytes: int | None = None,
) -> None:
    """Check that a usable index file is at *index_path* without parsing it or
    caching anything: the memory-light counterpart of load_index(), used by
    ensure_index().

    Same path rules as load_index(). The default cache is downloaded when
    missing and, when it carries our sidecar, pin-checked (and quarantined and
    refetched if modified); any other path is user-supplied, never downloaded
    to, pin-checked or moved. Both must exist, be readable and be within the
    256 MiB load cap. JSON validity is NOT checked here: a corrupt or
    non-object file is only found by the first load_index() (so for a managed
    default file that is also when it is quarantined and refetched).

    Raises FileNotFoundError for a missing non-default path, IndexUnavailable
    for everything load_index() maps to it, and IndexIntegrityError for an
    oversized file.
    """
    if is_default_cache_path(index_path):
        fetch_opts = {
            key: value for key, value in (("timeout", timeout), ("max_download_bytes", max_download_bytes))
            if value is not None
        }
        try:
            managed, _fresh = _prepare_default_index(index_path, fetch_opts)
            try:
                _check_readable_within_cap(index_path)
            except IndexIntegrityError as exc:
                if managed:
                    raise
                raise IndexIntegrityError(
                    f"{exc}; {index_path} has no download record so it is treated as "
                    "user-supplied and was left in place: fix it, or delete it and "
                    "retry to download the pinned index"
                ) from exc
        except IndexUnavailable:
            raise
        except FileNotFoundError as exc:
            raise IndexUnavailable("hash index cache disappeared while loading") from exc
        except OSError as exc:
            raise IndexUnavailable(f"cannot read the hash index cache ({type(exc).__name__})") from exc
        return

    try:
        if not index_path.exists():
            raise FileNotFoundError(
                f"Hash index not found at {index_path}. "
                "Run build_index.py to generate it from your DAT files."
            )
        _check_readable_within_cap(index_path)
    except (IndexUnavailable, FileNotFoundError):
        raise
    except OSError as exc:
        raise IndexUnavailable(
            f"cannot read the hash index at {index_path} ({type(exc).__name__})"
        ) from exc


def _check_readable_within_cap(index_path: Path) -> None:
    """stat and open *index_path* for reading (one byte, nothing retained) and
    refuse a file over _MAX_INDEX_BYTES, the same message _parse_index() uses."""
    size = index_path.stat().st_size
    if size > _MAX_INDEX_BYTES:
        raise IndexIntegrityError(f"index file is {size} bytes, over the {_MAX_INDEX_BYTES} byte limit")
    with index_path.open("rb") as fh:
        fh.read(1)
