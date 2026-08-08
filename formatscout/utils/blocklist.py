# Executable-name rules for "this is an installer or a bundled DOS utility,
# not the thing a user actually launches to play". Consumed by detector.py's
# _compute_requires_install(), which flags a directory whose root-level
# executables are *all* blocked.
#
# Every prefix here must be long enough that a real game executable cannot
# plausibly start with it. The earlier list carried "ins" and "set", which
# blocked genuine game and tool names (insanity.exe, instinct.exe,
# inspector.exe, settings.exe) and, because a single false positive is enough
# to make a directory look installer-only, produced a wrong
# requires_install=True. Short, ambiguous stems are matched exactly instead,
# which still catches the real INST.EXE/SET.EXE-style installer names without
# swallowing everything that merely begins with those letters.
BLOCK_PREFIXES: tuple[str, ...] = (
    "instal",   # instal, install, installer, install32, installshield
    "setup",    # setup, setup1, setupex, setupapi
    "iset",     # isetup, Inno Setup's bootstrap name
    "arcinst",
    "uninst",   # uninst, uninstall, uninst000
    "unstall",
    "unwise",   # WISE uninstaller
)

# Exact matches only. Anything here is either too short to be a safe prefix
# (inst, arc, set) or a self-contained DOS tool name with no family of
# variants to cover (pkunzip, smartdrv).
BLOCK_EXACT: frozenset[str] = frozenset({
    "inst",
    "set",
    "deice",
    "pkunzip",
    "pkzip",
    "lzma",
    "expand",
    "mscdex",
    "smartdrv",
    "readme",
    "arj",
    "pkware",
    "lha",
    "zoo",
    "arc",
})

# "_ins" and "_set" were dropped alongside the bare prefixes: game_set.exe is
# far more likely to be a settings editor than an installer, and treating it
# as one is the same false positive in a different position.
BLOCK_SUFFIXES: tuple[str, ...] = (
    "_inst",
    "_setup",
)


def score_executable(stem: str) -> float:
    """Return 0.0 if the stem matches any block rule, 1.0 otherwise."""
    lower = stem.lower()
    if lower in BLOCK_EXACT:
        return 0.0
    if lower.startswith(BLOCK_PREFIXES):
        return 0.0
    if lower.endswith(BLOCK_SUFFIXES):
        return 0.0
    return 1.0


def is_blocked(stem: str) -> bool:
    return score_executable(stem) == 0.0
