# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
