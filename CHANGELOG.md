# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-16

### Added
- `ensure_index(path=None, *, force=False, timeout=None, max_bytes=None)`
  returns the path of a usable hash index, downloading it first when the
  default cache has none. For any other path it only validates the file. With
  `force=True` it re-downloads (ignoring the failure backoff, never offline
  mode); the new file is verified before anything is touched, a pristine copy
  of an earlier download is replaced, and any other file at the cache path is
  moved aside to `.corrupt` / `.corrupt.N` rather than overwritten.
- Public `IndexUnavailable` (an `OSError`) and `IndexIntegrityError` (a
  subclass: sha256 mismatch, corrupt or oversized index). The private 0.1.3 and
  0.1.4 exception names remain as aliases.
- Keyword-only `index_path=` on `detect()`, `classify()` and `verify()`, and an
  optional index path on the title matcher. Resolution order: the argument,
  then `FORMATSCOUT_INDEX_PATH`, then `~/.formatscout/hash_index.json`. Only
  the default cache is downloaded, pin-checked or quarantined; every other path
  is user-supplied and a sidecar next to it is ignored.
- Keyword-only `strict=True` on `classify()` and `verify()` to raise
  `IndexUnavailable` instead of returning `unchecked`.
- `VerifyResult` gains the status `unchecked` and a keyword-only `issues`.
- `build_index` prints the path the runtime reads and how to use the result
  (`--output`, `FORMATSCOUT_INDEX_PATH` or `index_path=`).
- Result contract on `ScanResult`: keyword-only, defaulted `status`, `method`,
  `authoritative`, `container`, `candidates`, `evidence`, `issues` and
  `platform_hint`; `ClassifyResult` gains `matched_era`, `hash_kind` and
  `issues`. New exports `Status`, `Method`, `Tier`, `Candidate`, `Issue`,
  `HashKind` and `tier_for_confidence`. A `ScanResult` with contradictory
  values raises `ValueError`. See the README's Result contract section.

### Changed
- `classify()` and `verify()` no longer raise by default when the index is
  unavailable (offline mode, backoff, failed download, oversized, corrupt or
  unreadable index). They return `status="unchecked"` with an
  `INDEX_UNAVAILABLE` issue and keep `computed_sha1`; pass `strict=True` for
  the old raising behavior (now `IndexUnavailable`). A missing index file at a
  custom path is still an empty index.
- The issue code `index_unavailable` that `detect()` attached is now spelled
  `INDEX_UNAVAILABLE`, the same code `classify()` and `verify()` use.
- The home directory is no longer read at import. The default cache path is
  computed when first needed; if the home directory cannot be determined that
  is an unavailable index (set `FORMATSCOUT_INDEX_PATH` or pass `index_path=`)
  instead of a failure at import time.
- The module-level `_INDEX_PATH`, `_CACHE_DIR` and `_DEFAULT_INDEX_PATH`
  override hooks now default to `None` (default resolution) instead of a
  computed path.
- When `build_index` writes to the default cache path it deletes a stale
  download sidecar just before moving the new index into place, so a
  user-built index there is no longer quarantined as a modified download.
- Implicit download on first use stays the default and is now documented, with
  `FORMATSCOUT_OFFLINE=1`, `index_path=` and `ensure_index()` as the ways to
  control it.

## [0.1.4] - 2026-11-16

### Fixed
- A user-built index at the cache path is no longer quarantined. Pin
  verification now applies only to files this code downloaded, which are
  recorded in a `hash_index.json.meta` sidecar (sha256, size, mtime_ns, source
  URL) written atomically after a successful download. A file with no sidecar
  is treated as user-supplied and only gets the size cap and JSON validity
  check.
- `AUTORUN.INF` `OPEN=` and `RUN=` values with a single leading backslash or
  slash (for example `OPEN=\SETUP.EXE`) are accepted again and resolve against
  the disc root, which is the scanned directory. Doubled leading separators,
  UNC, drive letters, `..`, device names, `:`, control characters and
  overlong values are still rejected, and all checks run on the remainder.
  Cue `FILE` handling is unchanged.

### Added
- Tests only: synthetic builders (sector framing, XDVDFS, CHD, PE, ROM, index)
  and a labeled corpus with strict xfails for known-wrong detections.

### Changed
- Quarantine never overwrites an earlier copy: files move to `.corrupt`, then
  `.corrupt.1` to `.corrupt.5`; when all are taken an index error asks you to
  clean up.
- An offline or backoff failure is logged once per backoff window per process
  as a single warning line without a traceback, then at debug level. The
  per-result `hash index unavailable` warning from `detect()` is unchanged.
- Index failures (download, corruption, offline, backoff) raise a private
  `OSError` subclass instead of `URLError`, `ValueError` or `JSONDecodeError`.
- Supersedes the 0.1.2 note that root-relative autorun values are rejected.

### Known
- Caches downloaded by 0.1.3 or earlier have no sidecar and are treated as
  user-supplied, so they are not re-checked against the pin.

## [0.1.3] - 2026-11-16

### Security
- Index download is hardened: streamed in chunks with an incremental sha256
  checked against the pinned hash, a hard size cap, an overall monotonic
  deadline on top of the socket timeout, https-only (including redirects), a
  temp file in the cache directory and an atomic replace. The temp file is
  removed on any failure.
- The default cached index is re-verified against the pin once per process;
  on a mismatch or corrupt JSON it is quarantined as `.corrupt` and refetched.
  Index files over a size cap are refused before parsing.

### Added
- `FORMATSCOUT_OFFLINE=1` disables index downloads.
- Failed fetches back off for a window (in-process and via a marker file next
  to the cache) instead of retrying on every call.
- `detect()` appends `hash index unavailable: <reason>; heuristics only` when
  the hash tier fails for index reasons and still returns the heuristic result.

### Changed
- Index download, corruption, offline and backoff failures now surface as a
  private `OSError` subclass chained from the original cause.
- Comments and README no longer describe the index as bundled; it is downloaded
  on first use.

## [0.1.2] - 2026-11-16

### Security
- Cue `FILE` targets and `AUTORUN.INF` `OPEN=`/`RUN=` values are now validated
  lexically (no filesystem access) and resolved strictly inside the scanned
  directory before anything is opened. Absolute paths, `..` components, UNC
  prefixes (which could leak NTLM hashes on Windows), drive letters, Windows
  device names, `:` (alternate data streams), control characters and overlong
  paths are rejected, as are symlinks escaping the base and non-regular files.
- A rejected pointer produces no era signal and a `pointer rejected: <reason>`
  warning; the target is never opened or stat-ed.

### Changed
- `AUTORUN.INF` values with a leading slash (for example `OPEN=\SETUP.EXE`) are
  now rejected.
- Autorun warnings are kept when detection falls through to directory heuristics.
