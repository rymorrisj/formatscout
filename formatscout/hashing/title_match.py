import re
import threading
from difflib import SequenceMatcher
from pathlib import Path

from ..index_path import resolve_index_path
from . import hash_lookup as _hash_lookup

# Redump/No-Intro titles carry region/language/revision tags in brackets
# ("(USA)", "(En,Fr,De,Es,It)", "(Disc 1)", "(Rev 1)") that a user-entered
# title almost never includes. Stripped before comparison so those tags don't
# drag the similarity ratio down for an otherwise-exact title.
_BRACKETED_RE = re.compile(r"[\(\[][^\)\]]*[\)\]]")

# The normalized, de-duplicated title lists of the one index used most
# recently: (index_path, mtime, {era: [(normalized_title, original_title), ...]}),
# or None. Built for every era in one pass over the index (which
# hash_lookup.load_index keeps in its own single-entry cache). One entry only,
# replaced once the new table is complete, never evicted beforehand, so a failed
# load keeps the working table. Guarded by _title_lock.
_title_cache: tuple[Path, float, dict[str, list[tuple[str, str]]]] | None = None
_title_lock = threading.Lock()


def _normalize_title(title: str) -> str:
    stripped = _BRACKETED_RE.sub("", title)
    return " ".join(stripped.lower().split())


def _titles_for_era(era: str, index_path: Path) -> list[tuple[str, str]]:
    global _title_cache
    try:
        index, _md5_index, _crc32_index = _hash_lookup.load_index(index_path)
    except FileNotFoundError:
        # No index present. Degrade to no candidates so fuzzy_title_match()
        # returns None, the same degrade-to-empty behavior classify() already
        # applies when load_index fails for the sha1/md5/crc32 tiers.
        return []
    try:
        mtime: float | None = index_path.stat().st_mtime
    except OSError:
        # Replaced or removed since load_index() returned: use the index
        # already in hand, just without caching the title table.
        mtime = None

    with _title_lock:
        cached = _title_cache
        if mtime is not None and cached is not None and cached[0] == index_path and cached[1] == mtime:
            return cached[2].get(era, [])

        by_era: dict[str, list[tuple[str, str]]] = {}
        seen: dict[str, set[str]] = {}
        for entry in index.values():
            entry_era = entry.get("era")
            original = entry.get("title")
            if not isinstance(entry_era, str) or not isinstance(original, str) or not original:
                continue
            era_seen = seen.setdefault(entry_era, set())
            if original in era_seen:
                continue
            era_seen.add(original)
            by_era.setdefault(entry_era, []).append((_normalize_title(original), original))

        # Replace only now that the whole table has been built.
        if mtime is not None:
            _title_cache = (index_path, mtime, by_era)
        return by_era.get(era, [])


def fuzzy_title_match(
    title: str, era: str | None, index_path: Path | None = None, *, threshold: float = 0.80,
) -> tuple[str, float] | None:
    """Best-effort approximate title match, scoped to *era* only.

    era is required, not optional in practice: without it there is no honest
    way to bound the search space, and matching across every platform in the
    index would make an accidental >=threshold collision far more likely.
    Returns None (fail closed) whenever era is missing, the index has no
    entries for it, or nothing clears *threshold*, never a low-confidence
    guess. Returns (matched_original_title, similarity_ratio) on a confident
    match.

    index_path=None resolves like detect()'s index_path: FORMATSCOUT_INDEX_PATH,
    else the default cache (see index_path.py). Index failures other than a
    missing file at a custom path propagate as IndexUnavailable.
    """
    if not title or not era:
        return None

    if index_path is None:
        index_path = resolve_index_path()
    candidates = _titles_for_era(era, index_path)
    if not candidates:
        return None

    query = _normalize_title(title)
    if not query:
        return None

    matcher = SequenceMatcher(None, "", query)
    best_title: str | None = None
    best_score = 0.0
    for normalized, original in candidates:
        matcher.set_seq1(normalized)
        score = matcher.ratio()
        if score > best_score:
            best_score = score
            best_title = original

    if best_title is not None and best_score >= threshold:
        return best_title, best_score
    return None
