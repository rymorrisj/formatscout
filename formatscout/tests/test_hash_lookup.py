"""Tests for formatscout.hashing.hash_lookup."""

import os
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx


def _hash_lookup_module():
    from formatscout.hashing import hash_lookup
    return hash_lookup


def _lookup(path: Path, index_path: Path):
    return _hash_lookup_module().lookup(path, index_path)


# ---------------------------------------------------------------------------
# hash_file()
# ---------------------------------------------------------------------------

class TestHashFile:
    def test_matches_fixtures_hashes_for_helper(self, tmp_path: Path):
        path = tmp_path / "content.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        result = _hash_lookup_module().hash_file(path)
        expected = fx.hashes_for(fx.VERIFIED_CONTENT)

        assert result.sha1 == expected["sha1"]
        assert result.md5 == expected["md5"]
        assert result.crc32 == expected["crc32"]


# ---------------------------------------------------------------------------
# lookup(), 5-way dispatch: chd path / sha1 / md5 / crc32 / none
# ---------------------------------------------------------------------------

class TestLookupDispatch:
    def test_chd_path_hits_via_embedded_rawsha1(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        chd_file = tmp_path / "game.chd"
        chd_file.write_bytes(fx.build_synthetic_chd(fx.CHD_EMBEDDED_SHA1))

        result = _lookup(chd_file, index_path)

        assert result is not None
        assert result.confidence == 1.0
        assert result.era == "dreamcast"
        assert "CHD embedded rawsha1" in result.reason

    def test_chd_path_with_no_embedded_sha1_returns_none(self, tmp_path: Path):
        """CHD branch taken (suffix == .chd), but extract_embedded_sha1()
        itself returns None (e.g. all-zero rawsha1 field), and must return None
        without falling through to the raw-byte sha1/md5/crc32 tiers, since
        those are meaningless for a compressed CHD container.
        """
        index_path = fx.write_synthetic_index(tmp_path)
        chd_file = tmp_path / "unset.chd"
        buf = bytearray(100)
        buf[0:8] = b"MComprHD"  # magic present, rawsha1 field left all-zero
        chd_file.write_bytes(bytes(buf))

        assert _lookup(chd_file, index_path) is None

    def test_chd_path_with_embedded_sha1_not_in_index_returns_none(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        chd_file = tmp_path / "unmatched.chd"
        unknown_sha1 = "a" * 40
        chd_file.write_bytes(fx.build_synthetic_chd(unknown_sha1))

        assert _lookup(chd_file, index_path) is None

    def test_sha1_hit(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)

        result = _lookup(game_file, index_path)

        assert result is not None
        assert result.confidence == 1.0
        assert result.era == "ps1"
        assert "sha1 match" in result.reason

    def test_md5_hit(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.CAUTION_MD5_CONTENT)

        result = _lookup(game_file, index_path)

        assert result is not None
        assert result.confidence == 0.85
        assert "md5 match" in result.reason

    def test_crc32_hit(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.CAUTION_CRC32_CONTENT)

        result = _lookup(game_file, index_path)

        assert result is not None
        assert result.confidence == 0.75
        assert "crc32 match" in result.reason

    def test_no_match_returns_none(self, tmp_path: Path):
        index_path = fx.write_synthetic_index(tmp_path)
        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.UNINDEXED_CONTENT)

        assert _lookup(game_file, index_path) is None

    def test_empty_index_returns_none(self, tmp_path: Path):
        index_path = tmp_path / "hash_index.json"
        index_path.write_text("{}", encoding="utf-8")
        game_file = tmp_path / "game.bin"
        game_file.write_bytes(fx.VERIFIED_CONTENT)

        assert _lookup(game_file, index_path) is None


# ---------------------------------------------------------------------------
# load_index(), mtime-keyed cache
# ---------------------------------------------------------------------------

class TestLoadIndexMtimeCache:
    def test_same_mtime_reuses_cached_object_no_reparse(self, tmp_path: Path):
        """Confirmed by object identity: a fresh json.load() on a second call
        would build a brand-new dict, so `is` staying true proves the cached
        tuple was returned rather than the file being reparsed.
        """
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()

        index1, md5_1, crc32_1 = hash_lookup.load_index(index_path)
        index2, md5_2, crc32_2 = hash_lookup.load_index(index_path)

        assert index1 is index2
        assert md5_1 is md5_2
        assert crc32_1 is crc32_2

    def test_changed_mtime_triggers_reparse(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()

        index1, _md5_1, _crc32_1 = hash_lookup.load_index(index_path)

        new_mtime = index_path.stat().st_mtime + 5
        os.utime(index_path, (new_mtime, new_mtime))

        index2, _md5_2, _crc32_2 = hash_lookup.load_index(index_path)

        assert index1 is not index2
        assert index1 == index2  # same content, just re-parsed into a new object

    def test_cache_is_keyed_by_path_value_not_identity(self, tmp_path: Path):
        """Verifies the cache dict is actually keyed on the Path (value
        equality, e.g. Path(str(index_path)) == index_path even though they
        are different objects), not on some other identity such as the
        Path's id() or a wrapper object. A second, distinct-but-equal Path
        instance for the same file must hit the same cache entry.
        """
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()

        index1, _, _ = hash_lookup.load_index(index_path)
        equal_but_distinct_path = Path(str(index_path))
        assert equal_but_distinct_path is not index_path
        assert equal_but_distinct_path == index_path

        index2, _, _ = hash_lookup.load_index(equal_but_distinct_path)

        assert index1 is index2

    def test_cache_holds_one_entry_and_loading_another_path_evicts_the_first(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        first = fx.write_synthetic_index(tmp_path / "a")
        second = fx.write_synthetic_index(tmp_path / "b")
        hash_lookup._index_cache.clear()

        index_a, _, _ = hash_lookup.load_index(first)
        assert list(hash_lookup._index_cache) == [first]

        hash_lookup.load_index(second)
        assert list(hash_lookup._index_cache) == [second]  # the count is 1, not 2

        index_a_again, _, _ = hash_lookup.load_index(first)
        assert list(hash_lookup._index_cache) == [first]
        assert index_a_again is not index_a  # re-parsed after eviction
        assert index_a_again == index_a

    def test_changed_mtime_replaces_the_entry_instead_of_adding_one(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()
        hash_lookup.load_index(index_path)

        new_mtime = index_path.stat().st_mtime + 5
        os.utime(index_path, (new_mtime, new_mtime))
        hash_lookup.load_index(index_path)

        assert list(hash_lookup._index_cache) == [index_path]

    def test_failed_parse_of_another_path_leaves_no_stale_entry(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        (tmp_path / "a").mkdir()
        good = fx.write_synthetic_index(tmp_path / "a")
        bad_dir = tmp_path / "b"
        bad_dir.mkdir()
        bad = bad_dir / "hash_index.json"
        bad.write_text("{ not json", encoding="utf-8")
        hash_lookup._index_cache.clear()
        hash_lookup.load_index(good)

        with pytest.raises(hash_lookup.IndexIntegrityError):
            hash_lookup.load_index(bad)

        assert hash_lookup._index_cache == {}

    def test_forget_index_is_safe_for_cached_and_unknown_paths(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()
        hash_lookup.load_index(index_path)

        hash_lookup.forget_index(tmp_path / "never_loaded.json")
        assert list(hash_lookup._index_cache) == [index_path]

        hash_lookup.forget_index(index_path)
        hash_lookup.forget_index(index_path)  # twice is fine
        assert hash_lookup._index_cache == {}

    def test_missing_index_raises_file_not_found(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        missing = tmp_path / "does_not_exist.json"

        with pytest.raises(FileNotFoundError):
            hash_lookup.load_index(missing)
