import re
from difflib import SequenceMatcher
from pathlib import Path

from . import hash_lookup as _hash_lookup

# Redump/No-Intro titles carry region/language/revision tags in brackets
# ("(USA)", "(En,Fr,De,Es,It)", "(Disc 1)", "(Rev 1)") that a user-entered
# title almost never includes. Stripped before comparison so those tags don't
# drag the similarity ratio down for an otherwise-exact title.
_BRACKETED_RE = re.compile(r"[\(\[][^\)\]]*[\)\]]")

# Cached per (index_path, era): (mtime, [(normalized_title, original_title), ...]).
# Reuses hash_lookup._load_cached's own mtime-keyed cache for the raw index,
# this only adds the era-filtered, normalized, de-duplicated title list on top.
_title_cache: dict[tuple[Path, str], tuple[float, list[tuple[str, str]]]] = {}


def _normalize_title(title: str) -> str:
    stripped = _BRACKETED_RE.sub("", title)
    return " ".join(stripped.lower().split())


def _titles_for_era(era: str, index_path: Path) -> list[tuple[str, str]]:
    index, _md5_index, _crc32_index = _hash_lookup._load_cached(index_path)
    mtime = index_path.stat().st_mtime
    key = (index_path, era)
    cached = _title_cache.get(key)
    if cached is not None and cached[0] == mtime:
        return cached[1]

    seen: set[str] = set()
    titles: list[tuple[str, str]] = []
    for entry in index.values():
        if entry.get("era") != era:
            continue
        original = entry.get("title")
        if not original or original in seen:
            continue
        seen.add(original)
        titles.append((_normalize_title(original), original))

    _title_cache[key] = (mtime, titles)
    return titles


def fuzzy_title_match(
    title: str, era: str | None, index_path: Path, *, threshold: float = 0.80,
) -> tuple[str, float] | None:
    """Best-effort approximate title match, scoped to *era* only.

    era is required, not optional in practice: without it there is no honest
    way to bound the search space, and matching across every platform in the
    index would make an accidental >=threshold collision far more likely.
    Returns None (fail closed) whenever era is missing, the index has no
    entries for it, or nothing clears *threshold*, never a low-confidence
    guess. Returns (matched_original_title, similarity_ratio) on a confident
    match.
    """
    if not title or not era:
        return None

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
