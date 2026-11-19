"""Tests for formatscout.classify."""

from pathlib import Path

from formatscout.tests import smart_media_fixtures as fx


def _classify(path: Path, title: str, era: str | None, **kwargs):
    from formatscout.classify import classify
    return classify(path, title, era, **kwargs)


# ---------------------------------------------------------------------------
# Five dispatch states
# ---------------------------------------------------------------------------

class TestDispatchStates:
    def test_verified_on_sha1_match(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)

        result = _classify(game_file, title="irrelevant for this tier", era="ps1")

        assert result.status == "verified"
        assert result.computed_sha1 == fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]
        assert result.matched_title is None
        assert result.similarity is None

    def test_caution_on_md5_match(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.CAUTION_MD5_CONTENT)

        result = _classify(game_file, title="no title match either", era="ps1")

        assert result.status == "caution"
        assert result.computed_sha1 == fx.hashes_for(fx.CAUTION_MD5_CONTENT)["sha1"]
        assert "md5 match" in result.reason

    def test_caution_on_crc32_match(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.CAUTION_CRC32_CONTENT)

        result = _classify(game_file, title="no title match either", era="ps1")

        assert result.status == "caution"
        assert result.computed_sha1 == fx.hashes_for(fx.CAUTION_CRC32_CONTENT)["sha1"]
        assert "crc32 match" in result.reason

    def test_mismatch_on_title_fuzzy_match_above_threshold(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.UNINDEXED_CONTENT)

        result = _classify(game_file, title=fx.TITLE_QUERY_ABOVE_THRESHOLD, era="ps1")

        assert result.status == "mismatch"
        assert result.matched_title == fx.TITLE_MATCH_INDEXED_TITLE
        assert result.similarity is not None
        assert result.similarity >= 0.80

    def test_not_in_index_below_title_threshold(self, tmp_path: Path, monkeypatch):
        """Doubles as the below-0.80-threshold test: same query is checked
        against the indexed title from the "mismatch" test above, but this
        one lands under the threshold, so it must fall through to
        not_in_index rather than a weak "mismatch".
        """
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.UNINDEXED_CONTENT)

        result = _classify(game_file, title=fx.TITLE_QUERY_BELOW_THRESHOLD, era="ps1")

        assert result.status == "not_in_index"
        assert result.matched_title is None
        assert result.similarity is None

    def test_unchecked_on_unreadable_file(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        missing_file = tmp_path / "does_not_exist.bin"

        result = _classify(missing_file, title="doesn't matter", era="ps1")

        assert result.status == "unchecked"
        assert result.computed_sha1 is None


# ---------------------------------------------------------------------------
# is_chd carve-out, md5/crc32 tiers must be skipped entirely for .chd
# ---------------------------------------------------------------------------

class TestChdCarveOut:
    def test_caution_via_embedded_rawsha1_claim(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        chd_file = tmp_path / "game.chd"
        chd_file.write_bytes(fx.build_synthetic_chd(fx.CHD_EMBEDDED_SHA1))

        result = _classify(chd_file, title="irrelevant for this tier", era="dreamcast")

        # A header rawsha1 is an unchecked claim: caution, never verified.
        assert result.status == "caution"
        assert result.hash_kind == "chd_rawsha1"
        assert [issue.code for issue in result.issues] == ["CLAIM_UNVERIFIED"]
        # computed_sha1 is the file's own real hash, never the embedded one.
        assert result.computed_sha1 != fx.CHD_EMBEDDED_SHA1

    def test_md5_crc32_tiers_skipped_for_chd_even_on_real_collision(self, tmp_path: Path, monkeypatch):
        """A .chd file whose raw bytes are byte-for-byte CAUTION_MD5_CONTENT:
        its real md5 genuinely equals the caution entry's md5 field. Without
        the `if not is_chd:` guard in classify.py, this would return
        "caution". With the guard, the md5/crc32 tiers are skipped outright
        for any .chd (chdman compresses/wraps, so raw-byte md5/crc32 are as
        meaningless as raw-byte sha1 for a CHD, same reasoning as
        hash_lookup.lookup()), so this must fall through past caution.
        """
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        chd_file = tmp_path / "carveout.chd"
        chd_file.write_bytes(fx.CAUTION_MD5_CONTENT)

        # Sanity check the premise: this file's real md5 does equal the
        # caution entry's md5 field, so if the carve-out failed to apply,
        # the assertion below on result.status would catch it.
        assert fx.hashes_for(fx.CAUTION_MD5_CONTENT)["md5"] == fx.build_synthetic_index()[fx.CAUTION_ENTRY_SHA1]["md5"]

        result = _classify(chd_file, title="no title match either", era="ps1")

        assert result.status != "caution"
        assert result.status == "not_in_index"


# ---------------------------------------------------------------------------
# "mismatch must never fire falsely" guarantee, era=None fail-closed
# ---------------------------------------------------------------------------

class TestMismatchNeverFiresFalsely:
    def test_era_none_never_produces_mismatch_even_on_exact_title(self, tmp_path: Path, monkeypatch):
        """era=None with a title that is an *exact* match for an indexed
        title (ERA_NONE_TRAP_TITLE / era=None entry, see fixtures module).
        classify() must fail closed to not_in_index here, not mismatch.

        This is the specific input shape that would start producing a false
        "mismatch" if fuzzy_title_match()'s `if not title or not era: return
        None` guard were ever removed: a None era would then only filter
        hash_index entries down to other era=None records instead of being
        rejected outright, and era=None is a large real bucket in
        production (e.g. the unmapped "IBM - PC compatible" DAT, see the
        package README's Current coverage state section), not a rare edge.
        """
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_classify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.UNINDEXED_CONTENT)

        result = _classify(game_file, title=fx.ERA_NONE_TRAP_TITLE, era=None)

        assert result.status == "not_in_index"
        assert result.matched_title is None


# ---------------------------------------------------------------------------
# Cross-era title fallback: WRONG_ERA, numeric tokens, ties
# ---------------------------------------------------------------------------

def _title_index(tmp_path: Path, titles: list[tuple[str, str]]) -> Path:
    """Index of (title, era) entries keyed by unrelated sha1s, so only the
    title fallback can match."""
    from formatscout.tests.builders import index as index_builder
    entries = [
        index_builder.IndexEntry(f"{n:040x}", title, era, "Synthetic Platform")
        for n, (title, era) in enumerate(titles, start=1)
    ]
    index_dir = tmp_path / "idx"
    index_dir.mkdir()
    return index_builder.write_index_v1(index_dir / "index.json", entries)


def _unindexed_file(tmp_path: Path) -> Path:
    game_file = tmp_path / "game.bin"
    game_file.write_bytes(fx.UNINDEXED_CONTENT)
    return game_file


class TestCrossEraTitleMatch:
    def test_best_match_outside_supplied_era_reports_wrong_era(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        result = _classify(_unindexed_file(tmp_path), title=fx.TITLE_QUERY_ABOVE_THRESHOLD, era="ps2")

        assert result.status == "mismatch"
        assert result.matched_title == fx.TITLE_MATCH_INDEXED_TITLE
        assert result.matched_era == "ps1"
        assert [issue.code for issue in result.issues] == ["WRONG_ERA"]

    def test_best_match_inside_supplied_era_has_no_wrong_era(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        result = _classify(_unindexed_file(tmp_path), title=fx.TITLE_QUERY_ABOVE_THRESHOLD, era="ps1")

        assert (result.status, result.matched_era, result.issues) == ("mismatch", "ps1", ())

    def test_tie_at_the_top_prefers_the_supplied_era(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(
            monkeypatch, _title_index(tmp_path, [("Same Game (USA)", "ps1"), ("Same Game (Europe)", "ps2")]),
        )

        result = _classify(_unindexed_file(tmp_path), title="Same Game", era="ps2")

        assert (result.status, result.matched_era, result.matched_title) == ("mismatch", "ps2", "Same Game (Europe)")
        assert result.issues == ()

    def test_exact_supplied_era_match_survives_five_other_era_variants(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing.title_match import fuzzy_title_match
        regions = ("USA", "Europe", "Japan", "Korea", "Asia")
        index_path = _title_index(
            tmp_path, [(f"Same Game ({region})", "ps1") for region in regions] + [("Same Game (Brazil)", "ps2")],
        )
        fx.patch_classify_index(monkeypatch, index_path)
        # Premise: a single cross-era top-5 is filled by the earlier ps1 ties.
        assert {m.era for m in fuzzy_title_match("Same Game", index_path=index_path, limit=5)} == {"ps1"}

        result = _classify(_unindexed_file(tmp_path), title="Same Game", era="ps2")

        assert (result.status, result.matched_era, result.matched_title) == ("mismatch", "ps2", "Same Game (Brazil)")
        assert result.similarity == 1.0
        assert result.issues == ()

    def test_supplied_era_match_above_threshold_wins_over_a_better_other_era(self, tmp_path: Path, monkeypatch):
        # ratio("same game", "same gamer") == 18/19 ~ 0.947, above 0.80 but below ps1's 1.0.
        fx.patch_classify_index(
            monkeypatch, _title_index(tmp_path, [("Same Game (USA)", "ps1"), ("Same Gamer (USA)", "ps2")]),
        )

        result = _classify(_unindexed_file(tmp_path), title="Same Game", era="ps2")

        assert (result.status, result.matched_era, result.matched_title) == ("mismatch", "ps2", "Same Gamer (USA)")
        assert result.similarity is not None and 0.80 <= result.similarity < 1.0
        assert result.issues == ()

    def test_wrong_era_only_when_supplied_era_is_below_threshold(self, tmp_path: Path, monkeypatch):
        # ratio("same game", "same game collection") == 18/29 ~ 0.62, below 0.80.
        fx.patch_classify_index(
            monkeypatch, _title_index(tmp_path, [("Same Game (USA)", "ps1"), ("Same Game Collection (USA)", "ps2")]),
        )

        result = _classify(_unindexed_file(tmp_path), title="Same Game", era="ps2")

        assert (result.status, result.matched_era, result.matched_title) == ("mismatch", "ps1", "Same Game (USA)")
        assert [issue.code for issue in result.issues] == ["WRONG_ERA"]

    def test_no_wrong_era_when_no_era_matches(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(
            monkeypatch, _title_index(tmp_path, [("Other Thing (USA)", "ps1"), ("Same Game Collection (USA)", "ps2")]),
        )

        result = _classify(_unindexed_file(tmp_path), title="Same Game", era="ps2")

        assert (result.status, result.matched_era, result.issues) == ("not_in_index", None, ())

    def test_sequel_number_must_be_equal(self, tmp_path: Path, monkeypatch):
        # ratio("tekken 2", "tekken 3") == 0.875 would clear 0.80 without the numeric rule.
        fx.patch_classify_index(monkeypatch, _title_index(tmp_path, [("Tekken 2 (USA)", "ps1")]))

        result = _classify(_unindexed_file(tmp_path), title="Tekken 3", era="ps1")

        assert result.status == "not_in_index"

    def test_roman_numeral_equals_digit(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, _title_index(tmp_path, [("Tekken III (USA)", "ps1")]))

        # ratio("tekken iii", "tekken 3") == 14/18 ~ 0.778, so a lower threshold.
        result = _classify(_unindexed_file(tmp_path), title="Tekken 3", era="ps1", threshold=0.75)

        assert (result.status, result.matched_title) == ("mismatch", "Tekken III (USA)")

    def test_era_none_still_skips_the_cross_era_search(self, tmp_path: Path, monkeypatch):
        fx.patch_classify_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        result = _classify(_unindexed_file(tmp_path), title=fx.TITLE_MATCH_INDEXED_TITLE, era=None)

        assert result.status == "not_in_index"
