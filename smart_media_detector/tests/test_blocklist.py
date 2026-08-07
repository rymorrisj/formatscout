"""Tests for backend.service.utils.smart_media_detector.utils.blocklist."""

import pytest

from backend.service.utils.smart_media_detector.utils.blocklist import (
    BLOCK_EXACT,
    BLOCK_PREFIXES,
    BLOCK_SUFFIXES,
    is_blocked,
    score_executable,
)


# ---------------------------------------------------------------------------
# score_executable(), three independent block tiers checked in order
# (exact, prefix, suffix), each case-insensitive since lower() is applied
# before any comparison. A stem matching none of the three scores 1.0.
# ---------------------------------------------------------------------------

class TestScoreExecutableExactTier:
    @pytest.mark.parametrize("stem", sorted(BLOCK_EXACT))
    def test_exact_match_scores_zero(self, stem: str):
        assert score_executable(stem) == 0.0

    @pytest.mark.parametrize("stem", sorted(BLOCK_EXACT))
    def test_exact_match_is_case_insensitive(self, stem: str):
        assert score_executable(stem.upper()) == 0.0


class TestScoreExecutablePrefixTier:
    @pytest.mark.parametrize("prefix", BLOCK_PREFIXES)
    def test_prefix_match_scores_zero(self, prefix: str):
        """Appending harmless characters after the prefix must still match,
        proving this is a startswith() check, not an exact-length one."""
        stem = f"{prefix}XYZ123"
        assert stem.lower() not in BLOCK_EXACT, "fixture stem accidentally collided with BLOCK_EXACT"
        assert score_executable(stem) == 0.0

    @pytest.mark.parametrize("prefix", BLOCK_PREFIXES)
    def test_prefix_match_is_case_insensitive(self, prefix: str):
        stem = f"{prefix}XYZ123".upper()
        assert score_executable(stem) == 0.0


class TestScoreExecutableSuffixTier:
    @pytest.mark.parametrize("suffix", BLOCK_SUFFIXES)
    def test_suffix_match_scores_zero(self, suffix: str):
        stem = f"GAME{suffix}"
        assert stem.lower() not in BLOCK_EXACT, "fixture stem accidentally collided with BLOCK_EXACT"
        assert not stem.lower().startswith(BLOCK_PREFIXES), "fixture stem accidentally collided with BLOCK_PREFIXES"
        assert score_executable(stem) == 0.0

    @pytest.mark.parametrize("suffix", BLOCK_SUFFIXES)
    def test_suffix_match_is_case_insensitive(self, suffix: str):
        stem = f"GAME{suffix}".upper()
        assert score_executable(stem) == 0.0


class TestScoreExecutablePassThrough:
    @pytest.mark.parametrize("stem", ["DOOM", "GAME1", "LAUNCHER", "PLAY", "START_GAME"])
    def test_ordinary_executable_names_score_one(self, stem: str):
        assert score_executable(stem) == 1.0

    def test_empty_stem_scores_one(self):
        """Empty string matches no exact/prefix/suffix rule, this is a
        boundary case, not a rule of its own."""
        assert score_executable("") == 1.0


# ---------------------------------------------------------------------------
# is_blocked(), thin wrapper, score_executable(stem) == 0.0
# ---------------------------------------------------------------------------

class TestIsBlocked:
    def test_blocked_stem_returns_true(self):
        assert is_blocked("setup") is True

    def test_unblocked_stem_returns_false(self):
        assert is_blocked("DOOM") is False

    def test_delegates_to_score_executable_case_insensitively(self):
        assert is_blocked("SETUP") is True
