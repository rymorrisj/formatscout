"""Where the hash index is read from.

Resolution order, first match wins:

1. the explicit ``index_path`` argument of detect()/classify()/verify()/
   ensure_index();
2. a per-module override hook (``detector._INDEX_PATH`` etc., None by
   default), a programmatic seam used by the test suite;
3. the FORMATSCOUT_INDEX_PATH environment variable (empty means unset);
4. the default cache, ``~/.formatscout/hash_index.json``, computed lazily so
   importing the package never touches the home directory.

Only the default cache location is managed (downloaded, pin-checked,
quarantined); every other path is a user-supplied file. See
hashing/hash_lookup.load_index().
"""

import os
from pathlib import Path

from .hashing import hash_lookup as _hash_lookup

INDEX_PATH_ENV = "FORMATSCOUT_INDEX_PATH"


def coerce_index_path(value: "str | os.PathLike[str] | None") -> Path | None:
    """Validate an explicit index_path argument and return it as an absolute
    Path (None stays None). Raises TypeError for a non-path and ValueError for
    an empty string or one containing a NUL byte: programmer errors, not index
    failures, so they are never reported as IndexUnavailable."""
    if value is None:
        return None
    text = os.fspath(value)
    if not isinstance(text, str):
        raise TypeError(f"index_path must be a str or path-like of str, not {type(value).__name__}")
    if not text or "\0" in text:
        raise ValueError("index_path must be a non-empty path without NUL bytes")
    return Path(text).absolute()


def resolve_index_path(
    explicit: "str | os.PathLike[str] | None" = None, *, override: Path | None = None,
) -> Path:
    """The index path to use, per the resolution order in the module docstring.

    *override* is the calling module's hook (None means "no override").
    Raises IndexUnavailable only when the default location is needed and the
    home directory cannot be determined.
    """
    path = coerce_index_path(explicit)
    if path is not None:
        return path
    if override is not None:
        return override
    env_value = os.environ.get(INDEX_PATH_ENV, "")
    if env_value.strip():
        return coerce_index_path(env_value)  # type: ignore[return-value]
    return _hash_lookup.default_index_path()
