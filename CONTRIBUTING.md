# Contributing

formatscout is alpha software. This is a short practical guide, not a formal governance document.

## Bugs and detection gaps

Open an issue. Include the file type/platform involved and, if possible, a minimal reproduction (a small synthetic fixture is more useful than a real ROM/ISO, which we cannot accept for copyright reasons).

## Adding a new DAT source or platform

Include a sample of the DAT's `<header><name>` text in your PR description so the `_ERA_MARKERS` mapping in `formatscout/hashing/dat_parser.py` can be verified before merging. For example:

```xml
<datafile>
  <header>
    <name>Sony - PlayStation</name>
    <description>Sony - PlayStation</description>
  </header>
  <game name="Some Game (USA)">
    <rom name="Some Game (USA).bin" size="734003200" crc="..." md5="..." sha1="..."/>
  </game>
</datafile>
```

`_ERA_MARKERS` matches on substrings of that `<name>` text, most-specific first (see the ordering comment above it in `dat_parser.py`). A new platform string needs its own entry in that list, and the entry has to sit above any more general string it's a substring of (the same way `"playstation 3"` sits above the bare `"playstation"` marker).

## Pull request expectations

- Tests must pass: `pytest formatscout/tests/`.
- Don't add a new bare `except Exception`. Narrow to the specific exceptions the code can actually raise (typically `OSError`, and `struct.error`/`UnicodeDecodeError` for byte-parsing code), and log at `logger.debug(...)` when swallowing one, the same pattern used throughout the detection tiers. Silent, unlogged degradation is how a real bug turns permanently into "no signal found".
- Don't hardcode a magic number that already has, or should have, a name. Add it to `formatscout/constants.py` alongside the existing caps/thresholds instead of a bare literal in the module that uses it.
- Keep code comments minimal, only where the *why* is genuinely non-obvious. Well-named identifiers should carry the *what*.
