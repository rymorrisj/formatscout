"""Shared capped-read line scan for small pointer/manifest files (AUTORUN.INF,
.cue sheets), used by directory_detect.py, iso_detect.py, and
validators/bin_validator.py.
"""

from pathlib import Path

from ..constants import POINTER_FILE_READ_CAP_BYTES


def read_capped_lines(path: Path, cap_bytes: int = POINTER_FILE_READ_CAP_BYTES) -> list[str]:
    """Read up to cap_bytes from *path*, decoded as UTF-8 (undecodable bytes
    replaced), split into lines.

    Raises whatever Path.open()/read() raises rather than swallowing it:
    every current caller wraps this in its own try/except alongside the rest
    of its line-scan logic, since a read failure and a malformed line are
    handled identically (return None).
    """
    with path.open("rb") as fh:
        raw = fh.read(cap_bytes)
    return raw.decode("utf-8", errors="replace").splitlines()
