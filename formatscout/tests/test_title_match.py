"""Tests for formatscout.hashing.title_match: cross-era fuzzy matching, the
numeric-token rule, the query cap, exact matching and the single-entry cache."""

from pathlib import Path

import pytest

from formatscout.hashing import title_match
from formatscout.hashing.title_match import TitleMatch, exact_title_matches, fuzzy_title_match
from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.builders import index as index_builder


def _index(tmp_path: Path, entries: list[tuple[str, str | None, str | None]], name: str = "index.json") -> Path:
    """Index of (title, era, platform) entries keyed by unrelated sha1s."""
    records = [
        index_builder.IndexEntry(f"{n:040x}", title, era, platform)
        for n, (title, era, platform) in enumerate(entries, start=1)
    ]
    return index_builder.write_index_v1(tmp_path / name, records)


class TestFuzzyTitleMatch:
    def test_searches_every_era_and_returns_title_matches(self, tmp_path: Path):
        path = _index(tmp_path, [("Ridge Racer (USA)", "ps1", None), ("Ridge Racer (Japan)", "ps2", None)])

        matches = fuzzy_title_match("Ridge Racer", index_path=path)

        assert [(m.era, m.title, m.score) for m in matches] == [
            ("ps1", "Ridge Racer (USA)", 1.0), ("ps2", "Ridge Racer (Japan)", 1.0),
        ]
        assert all(isinstance(m, TitleMatch) for m in matches)

    def test_eras_restricts_the_search(self, tmp_path: Path):
        path = _index(tmp_path, [("Ridge Racer (USA)", "ps1", None), ("Ridge Racer (Japan)", "ps2", None)])

        assert [m.era for m in fuzzy_title_match("Ridge Racer", index_path=path, eras=["ps2"])] == ["ps2"]

    def test_results_are_best_first_and_limited(self, tmp_path: Path):
        path = _index(tmp_path, [
            ("Space Game Deluxe (USA)", "ps1", None),
            ("Space Game (USA)", "ps2", None),
            ("Space Gamer (USA)", "xbox", None),
        ])

        matches = fuzzy_title_match("Space Game", index_path=path, threshold=0.5, limit=2)

        assert len(matches) == 2
        assert matches[0] == TitleMatch("ps2", "Space Game (USA)", 1.0)
        assert matches[0].score >= matches[1].score

    def test_numeric_tokens_must_be_equal(self, tmp_path: Path):
        path = _index(tmp_path, [("Tekken 2 (USA)", "ps1", None), ("Final Fantasy VII (USA)", "ps1", None)])

        assert fuzzy_title_match("Tekken 3", index_path=path) == []
        assert [m.title for m in fuzzy_title_match("Final Fantasy 7", index_path=path)] == ["Final Fantasy VII (USA)"]

    def test_missing_number_does_not_match_a_numbered_title(self, tmp_path: Path):
        path = _index(tmp_path, [("Wipeout 3 (USA)", "ps1", None)])

        assert fuzzy_title_match("Wipeout", index_path=path, threshold=0.5) == []

    def test_era_less_entries_are_never_candidates(self, tmp_path: Path):
        path = _index(tmp_path, [(fx.ERA_NONE_TRAP_TITLE, None, None)])

        assert fuzzy_title_match(fx.ERA_NONE_TRAP_TITLE, index_path=path) == []

    def test_overlong_query_is_capped_not_scanned_in_full(self, tmp_path: Path):
        path = _index(tmp_path, [("A" * 10 + " (USA)", "ps1", None)])

        assert fuzzy_title_match("Q" * 1_000_000, index_path=path) == []

    @pytest.mark.parametrize("bad", ["", "(USA)", "   "])
    def test_empty_or_tag_only_query_is_empty(self, tmp_path: Path, bad: str):
        path = _index(tmp_path, [("(USA)", "ps1", None)])

        assert fuzzy_title_match(bad, index_path=path) == []

    def test_missing_custom_index_is_empty(self, tmp_path: Path):
        assert fuzzy_title_match("Anything", index_path=tmp_path / "absent.json") == []

    def test_old_positional_era_signature_is_rejected(self, tmp_path: Path):
        with pytest.raises(TypeError):
            fuzzy_title_match("Final Fantasy 7", "ps1")  # type: ignore[misc]


class TestExactTitleMatches:
    def test_one_match_per_requested_era_in_request_order(self, tmp_path: Path):
        path = _index(tmp_path, [
            ("Ico (USA)", "ps2", "Sony - PlayStation 2"),
            ("Ico (Europe)", "ps2", "Sony - PlayStation 2"),
            ("Ico (Japan)", "ps1", "Sony - PlayStation"),
        ])

        matches = exact_title_matches("Ico (USA)", ["ps2", "ps1"], index_path=path)

        assert [(m.era, m.title, m.platform) for m in matches] == [
            ("ps2", "Ico (USA)", "Sony - PlayStation 2"), ("ps1", "Ico (Japan)", "Sony - PlayStation"),
        ]

    def test_other_eras_are_ignored(self, tmp_path: Path):
        path = _index(tmp_path, [("Ico (USA)", "dreamcast", None)])

        assert exact_title_matches("Ico", ["ps1", "ps2"], index_path=path) == []

    @pytest.mark.parametrize("stem", ["Ico (USA) (Disc 1)", "Ico - Disc 1", "ico_disc2", "ICO CD 1 of 2"])
    def test_disc_suffixes_are_stripped(self, tmp_path: Path, stem: str):
        path = _index(tmp_path, [("Ico (USA)", "ps2", None)])

        assert [m.era for m in exact_title_matches(stem, ["ps2"], index_path=path)] == ["ps2"]

    def test_near_miss_is_not_exact(self, tmp_path: Path):
        path = _index(tmp_path, [("Ico (USA)", "ps2", None)])

        assert exact_title_matches("Icon", ["ps2"], index_path=path) == []

    def test_overlong_title_fails_closed(self, tmp_path: Path):
        long_title = "A" * 300
        path = _index(tmp_path, [(long_title, "ps2", None)])

        assert exact_title_matches(long_title, ["ps2"], index_path=path) == []


class TestTitleCache:
    def test_one_entry_replaced_by_the_next_index(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(title_match, "_title_cache", None)
        first = _index(tmp_path, [("First Game (USA)", "ps1", None)], name="first.json")
        second = _index(tmp_path, [("Second Game (USA)", "ps2", None)], name="second.json")

        fuzzy_title_match("First Game", index_path=first)
        assert title_match._title_cache is not None and title_match._title_cache[0] == first
        fuzzy_title_match("Second Game", index_path=second)

        assert title_match._title_cache[0] == second
        assert set(title_match._title_cache[2]) == {"ps2"}

    def test_cached_table_is_reused_for_the_same_index(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(title_match, "_title_cache", None)
        path = _index(tmp_path, [("Cached Game (USA)", "ps1", None)])

        fuzzy_title_match("Cached Game", index_path=path)
        table = title_match._title_cache[2]
        exact_title_matches("Cached Game", ["ps1"], index_path=path)

        assert title_match._title_cache[2] is table
