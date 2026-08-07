"""Tests for backend.service.utils.smart_media_detector.verify.

Trivial three-state dispatch (matched / mismatched / not_in_index), hash-only,
no magic/structural/directory/fallback tiers involved.
"""

from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


def _verify(path: Path, expected_sha1: str):
    from backend.service.utils.smart_media_detector.verify import verify
    return verify(path, expected_sha1)


class TestVerifyDispatch:
    def test_matched_when_computed_sha1_in_index_and_equals_expected(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_verify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)
        computed = fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]

        result = _verify(game_file, expected_sha1=computed)

        assert result.status == "matched"
        assert result.computed_sha1 == computed
        assert result.expected_sha1 == computed

    def test_mismatched_when_computed_sha1_in_index_but_differs_from_expected(self, tmp_path: Path, monkeypatch):
        """The file's real sha1 is present in the index (so it's a known,
        indexed file) but doesn't equal the caller-supplied expected_sha1,
        because the file changed since that value was recorded.
        """
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_verify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)
        computed = fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]
        stale_expected = "b" * 40

        result = _verify(game_file, expected_sha1=stale_expected)

        assert result.status == "mismatched"
        assert result.computed_sha1 == computed
        assert result.expected_sha1 == stale_expected

    def test_not_in_index_when_computed_sha1_absent_regardless_of_expected(self, tmp_path: Path, monkeypatch):
        index_path = fx.write_synthetic_index(tmp_path)
        fx.patch_verify_index(monkeypatch, index_path)

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.UNINDEXED_CONTENT)
        computed = fx.hashes_for(fx.UNINDEXED_CONTENT)["sha1"]

        result = _verify(game_file, expected_sha1=computed)  # even matches its own hash

        assert result.status == "not_in_index"
        assert result.computed_sha1 == computed

    def test_not_in_index_when_index_file_missing_entirely(self, tmp_path: Path, monkeypatch):
        """verify() catches FileNotFoundError from _load_cached() and treats
        a missing index the same as an empty one, rather than raising.
        """
        fx.patch_verify_index(monkeypatch, tmp_path / "does_not_exist.json")

        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)

        result = _verify(game_file, expected_sha1="anything")

        assert result.status == "not_in_index"
