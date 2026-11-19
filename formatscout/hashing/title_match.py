import heapq
import re
import threading
from collections.abc import Iterable
from difflib import SequenceMatcher
from pathlib import Path
from typing import NamedTuple

from ..index_path import resolve_index_path
from . import hash_lookup as _hash_lookup

# Redump/No-Intro titles carry region/language/revision tags in brackets
# ("(USA)", "(En,Fr,De,Es,It)", "(Disc 1)", "(Rev 1)") that a user-entered
# title almost never includes. Stripped before comparison so those tags don't
# drag the similarity ratio down for an otherwise-exact title.
_BRACKETED_RE = re.compile(r"[\(\[][^\)\]]*[\)\]]")

# A trailing disc number outside brackets ("Game - Disc 2", "game_disc1",
# "Game CD 2 of 3"), applied after _normalize_title() (lowercase). Bracketed
# "(Disc 1)" is already removed by _BRACKETED_RE.
_DISC_SUFFIX_RE = re.compile(r"(?:^|[\s_.\-]+)(?:disc|disk|cd)[\s_.\-#]*\d{1,2}(?:[\s_]*of[\s_]*\d{1,2})?[\s_.\-]*$")

# Numeric tokens: runs of letters (apostrophes kept inside, so "i'm" is not a
# numeral) and runs of ASCII digits, split apart so "x2" reads as X and 2.
_WORD_RE = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)*|[0-9]+")
# Canonical Roman numerals I..XXXIX (I, V, X only: L/C/D/M collide with real
# words such as "mix", "civ", "dc").
_ROMAN_RE = re.compile(r"x{0,3}(?:ix|iv|v?i{0,3})")
_ROMAN_VALUES = {"i": 1, "v": 5, "x": 10}

# Query cap (normalized characters) and the raw pre-cut applied before
# normalizing, so a huge input is never regex-scanned in full.
MAX_QUERY_CHARS = 256
_MAX_RAW_CHARS = 4 * MAX_QUERY_CHARS
# Index titles whose normalized form is longer than this are left out of the
# title table (no real game title comes close); bounds the per-pair cost.
_MAX_TITLE_CHARS = 512
DEFAULT_LIMIT = 5
_MAX_LIMIT = 50


class TitleMatch(NamedTuple):
    """One fuzzy_title_match() candidate: the index entry's era, its original
    title, and the SequenceMatcher ratio of the normalized titles."""
    era: str
    title: str
    score: float


class ExactTitleMatch(NamedTuple):
    """One exact_title_matches() hit: era, original indexed title, and the
    entry's platform string (None when missing or not a string)."""
    era: str
    title: str
    platform: str | None


class _Title(NamedTuple):
    normalized: str  # _normalize_title(original), what fuzzy matching compares
    original: str
    numbers: tuple[str, ...]  # _numeric_tokens(key)
    key: str  # normalized with a disc suffix removed, what exact matching compares
    platform: str | None


# The title table of the one index used most recently:
# (index_path, mtime, {era: [_Title, ...]}), or None. Built for every era in
# one pass over the index (which hash_lookup.load_index keeps in its own
# single-entry cache). One entry only, replaced once the new table is
# complete, never evicted beforehand, so a failed load keeps the working
# table. Guarded by _title_lock.
_title_cache: tuple[Path, float, dict[str, list[_Title]]] | None = None
_title_lock = threading.Lock()


def _normalize_title(title: str) -> str:
    stripped = _BRACKETED_RE.sub("", title)
    return " ".join(stripped.lower().split())


def _strip_disc_suffix(normalized: str) -> str:
    match = _DISC_SUFFIX_RE.search(normalized)
    if match is None or match.start() == 0:
        return normalized
    return normalized[:match.start()].rstrip(" _.-") or normalized


def _roman_value(token: str) -> int:
    total = 0
    prev = 0
    for ch in reversed(token):
        value = _ROMAN_VALUES[ch]
        if value < prev:
            total -= value
        else:
            total += value
            prev = value
    return total


def _numeric_tokens(text: str) -> tuple[str, ...]:
    """The numbers in *text*, in order, as canonical decimal strings: digit
    runs without leading zeros and Roman numerals I..XXXIX as their value
    ("vii" and "7" both give "7"). Never converts digit runs to int, so a long
    run cannot hit the int-from-str digit limit."""
    out: list[str] = []
    for word in _WORD_RE.findall(text):
        if word.isdigit() and word.isascii():
            out.append(word.lstrip("0") or "0")
        elif word.isascii() and _ROMAN_RE.fullmatch(word):
            out.append(str(_roman_value(word)))
    return tuple(out)


def _title_table(index_path: Path) -> dict[str, list[_Title]]:
    """{era: [_Title, ...]} for every era in the index, cached (see
    _title_cache). A missing index (FileNotFoundError) is an empty table;
    other index failures propagate as IndexUnavailable."""
    global _title_cache
    try:
        index, _md5_index, _crc32_index = _hash_lookup.load_index(index_path)
    except FileNotFoundError:
        # No index present. Degrade to no candidates, the same
        # degrade-to-empty behavior classify() already applies when
        # load_index fails for the sha1/md5/crc32 tiers.
        return {}
    try:
        mtime: float | None = index_path.stat().st_mtime
    except OSError:
        # Replaced or removed since load_index() returned: use the index
        # already in hand, just without caching the title table.
        mtime = None

    with _title_lock:
        cached = _title_cache
        if mtime is not None and cached is not None and cached[0] == index_path and cached[1] == mtime:
            return cached[2]

        by_era: dict[str, list[_Title]] = {}
        seen: dict[str, set[str]] = {}
        for entry in index.values():
            entry_era = entry.get("era")
            original = entry.get("title")
            if not isinstance(entry_era, str) or not isinstance(original, str) or not original:
                continue
            if len(original) > 4 * _MAX_TITLE_CHARS:
                continue
            era_seen = seen.setdefault(entry_era, set())
            if original in era_seen:
                continue
            era_seen.add(original)
            normalized = _normalize_title(original)
            if not normalized or len(normalized) > _MAX_TITLE_CHARS:
                continue
            key = _strip_disc_suffix(normalized)
            platform = entry.get("platform")
            by_era.setdefault(entry_era, []).append(_Title(
                normalized, original, _numeric_tokens(key), key, platform if isinstance(platform, str) else None,
            ))

        # Replace only now that the whole table has been built.
        if mtime is not None:
            _title_cache = (index_path, mtime, by_era)
        return by_era


def fuzzy_title_match(
    title: str, *, index_path: Path | None = None, eras: Iterable[str] | None = None,
    threshold: float = 0.80, limit: int = DEFAULT_LIMIT,
) -> list[TitleMatch]:
    """Approximate title match across every era in the index (or only *eras*).

    Returns up to *limit* (capped at 50) TitleMatch(era, title, score)
    candidates whose score reaches *threshold*, best first (ties by era, then
    title). Empty list (fail closed) when *title* is empty or normalizes to
    nothing, the index has no titles, or nothing clears *threshold*. Index
    entries without a string era are never candidates.

    Matching: both sides are normalized (bracketed tags removed, lowercase,
    whitespace collapsed); the query is cut to MAX_QUERY_CHARS (256)
    normalized characters. A candidate must have the same numeric tokens as
    the query, in order (digit runs, and Roman numerals I..XXXIX normalized to
    their value, so "7" equals "VII" but "2" never equals "3"; a trailing
    disc number is ignored), then pass SequenceMatcher.real_quick_ratio() and
    quick_ratio() before the full ratio() is computed. Cost is one pass over
    the table with O(1)/O(len) prefilters per title; ratio() runs only for
    candidates whose upper bounds reach the current cut-off.

    Signature change from the era-scoped version: the positional *era*
    parameter is gone (use eras=[...] to restrict), *index_path* is now
    keyword-only, *limit* is new, and the result is a list of TitleMatch
    instead of a (title, score) tuple or None.

    index_path=None resolves like detect()'s index_path: FORMATSCOUT_INDEX_PATH,
    else the default cache (see index_path.py). A missing file at a custom
    path is an empty index; other index failures propagate as
    IndexUnavailable.
    """
    if not isinstance(title, str) or not title or limit < 1 or threshold != threshold:  # NaN fails closed
        return []
    limit = min(limit, _MAX_LIMIT)
    query = _normalize_title(title[:_MAX_RAW_CHARS])[:MAX_QUERY_CHARS]
    if not query:
        return []

    if index_path is None:
        index_path = resolve_index_path()
    table = _title_table(index_path)
    if not table:
        return []

    wanted = None if eras is None else frozenset(eras)
    numbers = _numeric_tokens(_strip_disc_suffix(query))
    matcher = SequenceMatcher(None, "", query)
    # Min-heap of (score, arrival, TitleMatch); a new candidate replaces the
    # weakest only when strictly better, so ties keep the earlier entry.
    heap: list[tuple[float, int, TitleMatch]] = []
    arrival = 0
    for era, titles in table.items():
        if wanted is not None and era not in wanted:
            continue
        for entry in titles:
            if entry.numbers != numbers:
                continue
            floor = heap[0][0] if len(heap) >= limit else threshold
            matcher.set_seq1(entry.normalized)
            if matcher.real_quick_ratio() < floor or matcher.quick_ratio() < floor:
                continue
            score = matcher.ratio()
            if score <= 0.0 or score < floor:
                continue
            if len(heap) < limit:
                heapq.heappush(heap, (score, arrival, TitleMatch(era, entry.original, score)))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, arrival, TitleMatch(era, entry.original, score)))
            arrival += 1

    return sorted((item[2] for item in heap), key=lambda m: (-m.score, m.era, m.title))


def exact_title_matches(
    title: str, eras: Iterable[str], *, index_path: Path | None = None,
) -> list[ExactTitleMatch]:
    """Eras among *eras* whose index holds a title equal to *title* after
    normalization (bracketed tags removed, lowercase, whitespace collapsed, a
    trailing disc number removed). At most one ExactTitleMatch per era (the
    first such title in index order), in the order of *eras*.

    Fails closed (empty list) for an empty title, one longer than
    MAX_QUERY_CHARS after normalization (never truncated, so a cut cannot
    create a match), or an index with no titles. Cost is one equality scan
    over the titles of the requested eras. index_path resolution and index
    failures are as in fuzzy_title_match().
    """
    if not isinstance(title, str) or not title or len(title) > _MAX_RAW_CHARS:
        return []
    key = _strip_disc_suffix(_normalize_title(title))
    if not key or len(key) > MAX_QUERY_CHARS:
        return []

    if index_path is None:
        index_path = resolve_index_path()
    table = _title_table(index_path)
    out: list[ExactTitleMatch] = []
    for era in dict.fromkeys(eras):
        for entry in table.get(era, ()):
            if entry.key == key:
                out.append(ExactTitleMatch(era, entry.original, entry.platform))
                break
    return out
