# formatscout

`smart_media_detector`, a multi-tier format-identification tool for disk images
and directory trees, extracted from the [Peach 1UP](https://github.com/rymorrisj/peach_1up)
preservation launcher. Pure Python 3.11+ stdlib, no third-party runtime
dependencies.

See [`smart_media_detector/README.md`](smart_media_detector/README.md) for the
full detection pipeline (hash lookup, magic bytes, structural validation,
directory heuristics, extension/size fallback) and the complete `ScanResult`
shape.

## What it does

`detect()` returns a `ScanResult` (`title`, `platform`, `era`, `confidence`,
`reason`, `requires_install`, `requires_extraction`, `warnings`) for a given
path. Every tier reports what a thing is, with a confidence score, through
this one result object, there is no separate per-format entry point.

`requires_extraction` is one of those fields, not a standalone function.
It is set by the ISO tier's Xbox check: a raw Xbox DVD rip (valid ISO 9660
magic, but past the xISO size threshold) comes back as `era="xbox"` with
`requires_extraction=True`, signaling that the caller needs to run
extract-xiso on it before use. A ready-to-use xISO gets the same `era="xbox"`
with the flag left `False`. The byte-level Xbox identification behind this
(`xbox_image.py`) lives inside `smart_media_detector/` as an internal module,
it is not part of this package's public surface and is not meant to be
imported directly, callers get the signal through `ScanResult` like every
other detection fact.

```python
from pathlib import Path
from smart_media_detector import detect

scan = detect(Path("game.iso"))
if scan.era == "xbox" and scan.requires_extraction:
    ...  # run extract-xiso before handing scan's path to xemu
elif scan.era == "xbox":
    ...  # ready to mount/launch as-is
```

## Status

Private, pre-release. Extracted from `peach_1up`'s in-tree copy of
`smart_media_detector`; the package's own README documents its remaining
monorepo coupling (see "Standalone-package intent" there), including the
one-way fork against peach_1up's separate `xbox_image.py` that this
package's internal module was vendored from.
