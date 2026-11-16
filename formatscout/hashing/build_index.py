"""
Usage:
    python -m formatscout.hashing.build_index --dats <dir> [--output <path>] [--rebuild]
"""

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable

from ..index_errors import IndexUnavailable
from ..index_path import INDEX_PATH_ENV, resolve_index_path
from . import hash_lookup
from .dat_parser import parse_dat

logger = logging.getLogger(__name__)

_DEFAULT_OUTPUT = Path(__file__).parent / "hash_index.json"


def _load_existing(output_path: Path) -> dict:
    if not output_path.exists():
        return {}
    with output_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_index_atomically(
    index: dict, output_path: Path, *, before_replace: Callable[[], None] | None = None,
) -> None:
    """Serialise *index* to a sibling temp file, then os.replace() it into place.

    - A crash or full disk during a direct write would leave the index
      truncated and no longer valid JSON. hash_lookup.load_index then
      fails on that.
    - os.replace() is atomic within a filesystem, so readers see either
      the old complete index or the new one.
    - The temp file goes in the destination directory so the rename
      cannot cross a filesystem boundary.
    - *before_replace*, if given, runs after the temp file is complete and
      just before the rename. An exception from it aborts the write and
      leaves the destination untouched.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=output_path.parent, prefix=f".{output_path.name}.", suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(tmp_path, output_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _remove_stale_sidecar(output_path: Path) -> None:
    """Delete the provenance sidecar next to the cache index before it is
    overwritten, so the index built here is not later judged a modified
    managed download and quarantined. Removed before the rename, not after:
    a reader between the two then sees an unrecorded (user-supplied) file
    rather than a changed one with a stale record. Only called for the cache
    path; a sidecar next to any other output is not ours to touch."""
    hash_lookup._sidecar_path(output_path).unlink(missing_ok=True)


def _is_cache_location(output_path: Path) -> bool:
    """True if *output_path* names the default cache file, also when spelled
    differently (relative, "..", a symlinked directory). The runtime treats
    such an alias as user-supplied, but the cache file it reaches would still
    be judged by its stale sidecar when loaded through the default path."""
    if hash_lookup.is_default_cache_path(output_path.absolute()):
        return True
    try:
        return output_path.resolve() == hash_lookup.default_index_path().resolve()
    except (OSError, RuntimeError, IndexUnavailable):
        return False


def _runtime_hint(output_path: Path) -> list[str]:
    """Lines saying where the runtime reads the index and how to use the
    result written to *output_path*."""
    try:
        runtime_path = resolve_index_path()
    except IndexUnavailable as exc:
        return [
            f"Runtime reads:   unknown ({exc})",
            f"To use this index: set {INDEX_PATH_ENV}={output_path} or pass index_path={str(output_path)!r} "
            "to detect()/classify()/verify().",
        ]
    lines = [f"Runtime reads:   {runtime_path}"]
    if output_path.absolute() == runtime_path:
        lines.append("This is the path formatscout reads, so it is already in use.")
    else:
        lines.append(
            f"To use this index: set {INDEX_PATH_ENV}={output_path}, pass "
            f"index_path={str(output_path)!r} to detect()/classify()/verify(), "
            f"or rebuild with --output {runtime_path}."
        )
    return lines


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Build or update the formatscout hash index from DAT files."
    )
    parser.add_argument(
        "--dats",
        required=True,
        type=Path,
        metavar="DIR",
        help="Directory to walk recursively for *.dat and *.xml files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        metavar="PATH",
        help=f"Output path for hash_index.json (default: {_DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Wipe existing index and regenerate from scratch.",
    )
    args = parser.parse_args()

    dats_dir: Path = args.dats
    output_path: Path = args.output

    if not dats_dir.is_dir():
        logger.error("--dats path does not exist or is not a directory: %s", dats_dir)
        sys.exit(1)

    index: dict = {} if args.rebuild else _load_existing(output_path)
    prior_size = len(index)

    dat_files = sorted(
        p for p in dats_dir.rglob("*") if p.suffix.lower() in {".dat", ".xml"}
    )

    if not dat_files:
        logger.warning("No .dat or .xml files found under %s", dats_dir)

    files_parsed = 0
    entries_added = 0
    skipped_no_sha1 = 0

    for dat_path in dat_files:
        try:
            records = parse_dat(dat_path)
        except Exception as exc:
            logger.error("Failed to parse %s: %s", dat_path.name, exc)
            continue

        files_parsed += 1
        file_skipped = 0
        for record in records:
            sha1 = record.get("sha1")
            if not sha1:
                skipped_no_sha1 += 1
                file_skipped += 1
                continue
            if sha1 not in index:
                index[sha1] = {
                    "title": record.get("title"),
                    "platform": record.get("platform"),
                    "era": record.get("era"),
                    "source": record.get("source"),
                    "md5": record.get("md5"),
                    "crc32": record.get("crc32"),
                }
                entries_added += 1

        if file_skipped:
            logger.warning(
                "%s: skipped %d record(s) with no sha1 value (md5/crc32-only "
                "entries are not indexable by this build, since the index is "
                "keyed by sha1)",
                dat_path.name, file_skipped,
            )

    _write_index_atomically(
        index, output_path,
        before_replace=(
            (lambda: _remove_stale_sidecar(output_path))
            if _is_cache_location(output_path) else None
        ),
    )

    print(f"Files parsed:    {files_parsed}")
    print(f"Entries added:   {entries_added}")
    print(f"Records skipped (no sha1): {skipped_no_sha1}")
    print(f"Total index size: {len(index)} (was {prior_size})")
    print(f"Written to:      {output_path}")
    for line in _runtime_hint(output_path):
        print(line)

    if skipped_no_sha1:
        logger.warning(
            "%d total record(s) across all parsed DATs were skipped for lacking "
            "a sha1 value and contributed no entries to the index.",
            skipped_no_sha1,
        )


if __name__ == "__main__":
    main()
