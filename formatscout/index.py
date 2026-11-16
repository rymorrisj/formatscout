"""Public index API: make sure a usable hash index is on disk.

detect(), classify() and verify() fetch the index implicitly on first use
(downloaded once to ~/.formatscout/hash_index.json, pinned by sha256). That is
still the default. ensure_index() lets an application do it explicitly, up
front, with its own timeout, size cap and error handling.
"""

import math
import os
from pathlib import Path

from .hashing import hash_lookup as _hash_lookup
from .index_errors import INDEX_UNAVAILABLE, IndexIntegrityError, IndexUnavailable
from .index_path import INDEX_PATH_ENV, resolve_index_path

__all__ = ["ensure_index", "IndexUnavailable", "IndexIntegrityError", "INDEX_UNAVAILABLE", "INDEX_PATH_ENV"]


def ensure_index(
    path: "str | os.PathLike[str] | None" = None,
    *,
    force: bool = False,
    timeout: float | None = None,
    max_bytes: int | None = None,
) -> Path:
    """Make sure a usable hash index exists, and return its path.

    *path* is resolved like the ``index_path`` of detect(): the argument, else
    FORMATSCOUT_INDEX_PATH, else the default cache ``~/.formatscout/
    hash_index.json``. On success the index has been loaded and parsed once
    (it stays cached in this process), so a later detect()/classify()/verify()
    on the same path does no further index work.

    One rule decides what happens to the resolved path:

    * It is the default cache location: this is the only path that is ever
      downloaded to. A missing file is downloaded, https only, sha256-checked
      against the pinned value, size-capped, and installed atomically with its
      provenance sidecar. An existing file that has our sidecar is re-checked
      against the pin and, if it was modified, moved aside (``.corrupt``,
      ``.corrupt.1`` ... ``.corrupt.5``, never overwriting an earlier copy)
      and re-downloaded. An existing file with no sidecar is user-supplied
      (for example one built with ``build_index``): it only gets the size cap
      and JSON validity check, and is never replaced.
    * It is anything else (an explicit path, or one from the environment): a
      user-supplied file. ensure_index validates it (exists, within the size
      cap, valid JSON of the expected shape) and returns it. It never
      downloads to it, never pin-checks it, never moves it, and ignores any
      sidecar next to it.

    *force* is a user-requested refresh and only has an effect on the default
    cache location (for any other path it just drops the in-process parse
    cache and re-validates the file). It re-downloads even when a valid index
    exists, and it ignores the failure backoff window (never
    FORMATSCOUT_OFFLINE). The new body is downloaded and pin-verified first,
    so a failed refresh leaves whatever is at the path untouched. Then a
    pristine copy of our own earlier download is replaced atomically, while
    any other file at the path, a modified copy or a user-supplied file
    (including a hand-built index), is moved aside with the same no-overwrite
    ``.corrupt`` naming rather than overwritten; if all six names are taken the
    refresh fails and the file stays where it is.

    *timeout* is the per-socket-operation timeout in seconds (default 30; the
    whole download is separately bounded by a 600 s deadline). *max_bytes* is
    the download size cap (default 128 MiB) and, for a path other than the
    default cache location, an extra size cap checked before parsing. The
    256 MiB load cap applies to every index file regardless, so max_bytes can
    only tighten it, and a no-sidecar file at the default location gets only
    that load cap. Both are for this call only.

    Raises IndexUnavailable (an OSError) when the index cannot be obtained:
    FORMATSCOUT_OFFLINE is set, a recent download failed (backoff), the
    download failed or exceeded a cap, the file at a user-supplied path is
    missing or unreadable, or the home directory is needed and unknown. Raises
    IndexIntegrityError, a subclass of IndexUnavailable, when what was found
    or downloaded cannot be trusted: a sha256 mismatch, or an index file that
    is oversized, not valid JSON, or malformed. Raises ValueError/TypeError
    for a bad argument.
    """
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout) or not timeout > 0
    ):
        raise ValueError("timeout must be a positive, finite number of seconds")
    if max_bytes is not None and (isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0):
        raise ValueError("max_bytes must be a positive integer")

    resolved = resolve_index_path(path)

    if _hash_lookup.is_default_cache_path(resolved):
        if force:
            _hash_lookup._fetch_default_index(timeout=timeout, max_download_bytes=max_bytes, force=True)
        _hash_lookup.load_index(resolved, timeout=timeout, max_download_bytes=max_bytes)
        return resolved

    _validate_user_supplied(resolved, force=force, max_bytes=max_bytes)
    return resolved


def _validate_user_supplied(path: Path, *, force: bool, max_bytes: int | None) -> None:
    """Check the user-supplied index at *path*, raising the public errors."""
    if force:
        _hash_lookup.forget_index(path)
    if max_bytes is not None:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = None  # reported below, with the build hint
        except OSError as exc:
            raise IndexUnavailable(f"cannot read the hash index at {path} ({type(exc).__name__})") from exc
        if size is not None and size > max_bytes:
            raise IndexIntegrityError(f"index file is {size} bytes, over the {max_bytes} byte limit")
    try:
        _hash_lookup.load_index(path)
    except FileNotFoundError as exc:
        raise IndexUnavailable(
            f"no hash index at {path}; ensure_index() only downloads to the default cache location "
            "(build one with `python -m formatscout.hashing.build_index --output <path>`, "
            "or omit the path to use the default)"
        ) from exc
