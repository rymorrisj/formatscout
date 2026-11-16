# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
