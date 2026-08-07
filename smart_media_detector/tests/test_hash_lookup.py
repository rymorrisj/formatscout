"""Tests for backend.service.utils.smart_media_detector.hashing.hash_lookup."""

import os
from pathlib import Path

import pytest

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


def _hash_lookup_module():
    from backend.service.utils.smart_media_detector.hashing import hash_lookup
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

        assert result == fx.hashes_for(fx.VERIFIED_CONTENT)


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
# _load_cached(), mtime-keyed cache
# ---------------------------------------------------------------------------

class TestLoadCachedMtimeCache:
    def test_same_mtime_reuses_cached_object_no_reparse(self, tmp_path: Path):
        """Confirmed by object identity: a fresh json.load() on a second call
        would build a brand-new dict, so `is` staying true proves the cached
        tuple was returned rather than the file being reparsed.
        """
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()

        index1, md5_1, crc32_1 = hash_lookup._load_cached(index_path)
        index2, md5_2, crc32_2 = hash_lookup._load_cached(index_path)

        assert index1 is index2
        assert md5_1 is md5_2
        assert crc32_1 is crc32_2

    def test_changed_mtime_triggers_reparse(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        index_path = fx.write_synthetic_index(tmp_path)
        hash_lookup._index_cache.clear()

        index1, _md5_1, _crc32_1 = hash_lookup._load_cached(index_path)

        new_mtime = index_path.stat().st_mtime + 5
        os.utime(index_path, (new_mtime, new_mtime))

        index2, _md5_2, _crc32_2 = hash_lookup._load_cached(index_path)

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

        index1, _, _ = hash_lookup._load_cached(index_path)
        equal_but_distinct_path = Path(str(index_path))
        assert equal_but_distinct_path is not index_path
        assert equal_but_distinct_path == index_path

        index2, _, _ = hash_lookup._load_cached(equal_but_distinct_path)

        assert index1 is index2

    def test_missing_index_raises_file_not_found(self, tmp_path: Path):
        hash_lookup = _hash_lookup_module()
        missing = tmp_path / "does_not_exist.json"

        with pytest.raises(FileNotFoundError):
            hash_lookup._load_cached(missing)
