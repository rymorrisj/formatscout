"""Sparse-file helper for size-dependent detection rules (builder only).

Size rules (4 GiB, 4.7 GB, 800 MiB) cannot be exercised with tiny files.
This writes a small real header and extends the file with a hole, so the
disk cost stays at the header size on filesystems that support sparse files.
The extended region reads back as zeros.

The ceiling matches the largest size the existing detector tests already use
(5_000_000_000). Do not hash a sparse file: with a hash index loaded, detect()
reads the whole logical length.
"""

from pathlib import Path

MAX_SPARSE_BYTES = 5_000_000_000


def write_sparse(path: Path, head: bytes, size: int) -> Path:
    """Write *head* at offset 0 and extend *path* to *size* bytes; return *path*.

    Raises ValueError if size is over MAX_SPARSE_BYTES or smaller than head.
    """
    if size > MAX_SPARSE_BYTES:
        raise ValueError(f"sparse size {size} exceeds the {MAX_SPARSE_BYTES} byte ceiling")
    if size < len(head):
        raise ValueError(f"sparse size {size} is smaller than the {len(head)} byte head")
    with path.open("wb") as fh:
        fh.write(head)
        fh.truncate(size)
    return path
