# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
