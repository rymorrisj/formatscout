# formatscout

Two standalone, dependency-free format-identification tools for disk images and
directory trees, extracted from the [Peach 1UP](https://github.com/rymorrisj/peach_1up)
preservation launcher:

- **`smart_media_detector`** — multi-tier platform/era/title detector for disk
  images (`.iso`, `.cue`/`.bin`, `.chd`) and installer directory trees. See
  [`smart_media_detector/README.md`](smart_media_detector/README.md) for the full
  detection pipeline (hash lookup, magic bytes, structural validation, directory
  heuristics, extension/size fallback).
- **`xbox_image`** — a small, focused Xbox optical-media identifier. See below.

Both are pure Python 3.11+ stdlib, no third-party runtime dependencies.

## `xbox_image`

Identifies whether an Xbox-era disc image is a redump-style xISO, a raw DVD rip,
a plain ISO 9660 image, or unrecognized, by reading a small number of bytes at
two fixed offsets. Never raises on I/O error or a garbage path.

This module backs the extract-xiso decision in any caller that needs to know
whether a given Xbox image should be converted before use, it is the
caller-facing entry point for that decision, not an internal helper.

### API

```python
from xbox_image import detect_xbox_image_type, is_xiso, XboxDvdRipDetected
```

**`detect_xbox_image_type(path: str | Path) -> str`**

Returns one of:

| Return value | Meaning |
| --- | --- |
| `"xiso"` | Xbox xISO format (`MICROSOFT*XBOX*MEDIA` magic at offset `0x10000`). The image is ready to use as-is. |
| `"dvd_rip"` | A raw DVD rip of an Xbox disc: valid ISO 9660 magic (`CD001` at offset `0x8001`) but larger than the xISO size threshold (4,000,000,000 bytes). Needs conversion via extract-xiso before use. |
| `"iso9660"` | Valid ISO 9660 magic, but under the size threshold, a non-Xbox or non-rip ISO 9660 image. |
| `"unknown"` | Neither magic matched, or the file could not be read. |

Reads only the minimum bytes needed at each offset and never raises: any I/O
error (missing file, permissions, truncated read) is caught and reported as
`"unknown"`.

**`is_xiso(path: str | Path) -> bool`**

Convenience wrapper: `True` only when `detect_xbox_image_type(path) == "xiso"`.

**`XboxDvdRipDetected(ValueError)`**

A `ValueError` subclass a caller can raise (or catch) to distinguish "this is a
DVD rip that needs extract-xiso conversion" from a generic detection failure,
so calling code can offer a conversion action instead of surfacing a plain
error. `xbox_image` itself only defines the exception, it does not raise it,
callers raise it based on `detect_xbox_image_type`'s result.

### Example

```python
from pathlib import Path
from xbox_image import detect_xbox_image_type, XboxDvdRipDetected

kind = detect_xbox_image_type(Path("game.iso"))
if kind == "dvd_rip":
    raise XboxDvdRipDetected("Raw DVD rip detected; convert with extract-xiso first.")
elif kind == "xiso":
    ...  # ready to mount/launch
```

## Status

Private, pre-release. Extracted verbatim from `peach_1up`'s in-tree copies;
`smart_media_detector`'s own README documents its remaining monorepo coupling
(see "Standalone-package intent" there). `xbox_image.py` has no such coupling,
it is pure stdlib with zero external imports.
