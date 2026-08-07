"""Tests for backend.service.utils.smart_media_detector.validators.bin_validator.

resolve_bin_cue() actually has 7 distinct reachable outcomes, not 5: no-sibling-cue
(confidence 0.3) and cue-found-but-unparseable (confidence 0.2) are both real
early/late branches in addition to the five documented in-function paths
(magic-confirmed 0.85, MODE2/2352 0.4, MODE1/2352 0.35, AUDIO 0.2, unrecognised
non-None track type 0.25). All seven are covered below.
"""

from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


def _resolve(bin_path: Path, dir_cache=None):
    from backend.service.utils.smart_media_detector.validators.bin_validator import resolve_bin_cue
    return resolve_bin_cue(bin_path, dir_cache)


def _find_cue(bin_path: Path, dir_cache=None):
    from backend.service.utils.smart_media_detector.validators.bin_validator import _find_cue
    return _find_cue(bin_path, dir_cache)


def _make_bin_and_cue(tmp_path: Path, *, bin_content: bytes, cue_text: str | None, bin_name="game.bin", cue_name="game.cue"):
    bin_path = tmp_path / bin_name
    bin_path.write_bytes(bin_content)
    if cue_text is not None:
        (tmp_path / cue_name).write_text(cue_text)
    return bin_path


# ---------------------------------------------------------------------------
# resolve_bin_cue(), 7-way dispatch
# ---------------------------------------------------------------------------

class TestResolveBinCueDispatch:
    def test_no_sibling_cue(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(tmp_path, bin_content=fx.UNINDEXED_CONTENT, cue_text=None)

        result = _resolve(bin_path)

        assert result.confidence == 0.3
        assert result.era is None
        assert "no sibling .cue sheet" in result.reason

    def test_magic_confirmed_takes_precedence_over_track_type(self, tmp_path: Path):
        """Bin content matches the N64 magic signature (applies_to includes
        "bin", offset 0, no SYSTEM.CNF dependency) while the cue sheet
        declares an unrelated track type. Magic must win at confidence 0.85.
        """
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.N64_BIG_ENDIAN_BLOB,
            cue_text="TRACK 01 AUDIO\n",
        )

        result = _resolve(bin_path)

        assert result.era == "n64"
        assert result.confidence == 0.85
        assert "game.cue" in result.reason

    def test_mode2_2352_track_type(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.UNINDEXED_CONTENT,
            cue_text="TRACK 01 MODE2/2352\n  INDEX 01 00:00:00\n",
        )

        result = _resolve(bin_path)

        assert result.confidence == 0.4
        assert result.era is None
        assert "MODE2/2352" in result.reason

    def test_mode1_2352_track_type(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.UNINDEXED_CONTENT,
            cue_text="TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n",
        )

        result = _resolve(bin_path)

        assert result.confidence == 0.35
        assert result.era is None
        assert "MODE1/2352" in result.reason

    def test_audio_track_type(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.UNINDEXED_CONTENT,
            cue_text="TRACK 01 AUDIO\n  INDEX 01 00:00:00\n",
        )

        result = _resolve(bin_path)

        assert result.confidence == 0.2
        assert result.era is None
        assert "AUDIO" in result.reason

    def test_unrecognised_non_none_track_type(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.UNINDEXED_CONTENT,
            cue_text="TRACK 01 MODE1/2048\n  INDEX 01 00:00:00\n",
        )

        result = _resolve(bin_path)

        assert result.confidence == 0.25
        assert result.era is None
        assert "unrecognised track type" in result.reason

    def test_cue_found_but_unparseable(self, tmp_path: Path):
        bin_path = _make_bin_and_cue(
            tmp_path, bin_content=fx.UNINDEXED_CONTENT,
            cue_text="REM some comment with no TRACK line at all\n",
        )

        result = _resolve(bin_path)

        assert result.confidence == 0.2
        assert result.era is None
        assert "no parseable TRACK declaration" in result.reason


# ---------------------------------------------------------------------------
# _find_cue(), case-insensitive stem match
# ---------------------------------------------------------------------------

class TestFindCue:
    def test_matching_stem_different_case_is_found(self, tmp_path: Path):
        bin_path = tmp_path / "Game.BIN"
        bin_path.write_bytes(fx.UNINDEXED_CONTENT)
        cue_path = tmp_path / "GAME.cue"
        cue_path.write_text("TRACK 01 MODE2/2352\n")

        assert _find_cue(bin_path) == cue_path

    def test_non_matching_stem_returns_none(self, tmp_path: Path):
        bin_path = tmp_path / "game.bin"
        bin_path.write_bytes(fx.UNINDEXED_CONTENT)
        (tmp_path / "different_title.cue").write_text("TRACK 01 MODE2/2352\n")

        assert _find_cue(bin_path) is None

    def test_no_cue_in_directory_returns_none(self, tmp_path: Path):
        bin_path = tmp_path / "game.bin"
        bin_path.write_bytes(fx.UNINDEXED_CONTENT)

        assert _find_cue(bin_path) is None


# ---------------------------------------------------------------------------
# _find_cue(), dir_cache param
# ---------------------------------------------------------------------------

class TestFindCueDirCache:
    def test_prepopulated_dir_cache_skips_iterdir_entirely(self, tmp_path: Path, monkeypatch):
        bin_path = tmp_path / "game.bin"
        bin_path.write_bytes(fx.UNINDEXED_CONTENT)
        cue_path = tmp_path / "game.cue"
        cue_path.write_text("TRACK 01 MODE2/2352\n")

        dir_cache = {tmp_path: [cue_path]}

        def _boom(self):
            raise AssertionError("iterdir() must not be called when dir_cache already has this directory")

        monkeypatch.setattr(Path, "iterdir", _boom)

        assert _find_cue(bin_path, dir_cache) == cue_path

    def test_dir_cache_populated_on_first_miss_then_reused(self, tmp_path: Path, monkeypatch):
        """dir_cache starts empty for this directory: the first call must
        fall back to a real iterdir() and populate the cache; a second call
        for a different .bin file in the same directory must then reuse it
        rather than calling iterdir() again.
        """
        cue_path = tmp_path / "game.cue"
        cue_path.write_text("TRACK 01 MODE2/2352\n")
        bin_a = tmp_path / "game.bin"
        bin_a.write_bytes(fx.UNINDEXED_CONTENT)
        bin_b = tmp_path / "game_disc2.bin"
        bin_b.write_bytes(fx.UNINDEXED_CONTENT)

        real_iterdir = Path.iterdir
        call_count = {"n": 0}

        def _counting_iterdir(self):
            call_count["n"] += 1
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", _counting_iterdir)

        dir_cache: dict = {}
        first = _find_cue(bin_a, dir_cache)
        second = _find_cue(bin_b, dir_cache)

        assert first == cue_path
        assert second is None  # "game_disc2" stem has no matching cue, still exercises the cached listing
        assert call_count["n"] == 1

    def test_none_dir_cache_preserves_original_per_call_iterdir_behavior(self, tmp_path: Path, monkeypatch):
        cue_path = tmp_path / "game.cue"
        cue_path.write_text("TRACK 01 MODE2/2352\n")
        bin_path = tmp_path / "game.bin"
        bin_path.write_bytes(fx.UNINDEXED_CONTENT)

        real_iterdir = Path.iterdir
        call_count = {"n": 0}

        def _counting_iterdir(self):
            call_count["n"] += 1
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", _counting_iterdir)

        _find_cue(bin_path, None)
        _find_cue(bin_path, None)

        assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# _parse_cue_track_type()
# ---------------------------------------------------------------------------

class TestParseCueTrackType:
    def _call(self, cue_path: Path):
        from backend.service.utils.smart_media_detector.validators.bin_validator import _parse_cue_track_type
        return _parse_cue_track_type(cue_path)

    def test_returns_first_track_type(self, tmp_path: Path):
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n  INDEX 01 00:00:00\nTRACK 02 AUDIO\n")
        assert self._call(cue) == "MODE2/2352"

    def test_missing_file_returns_none(self, tmp_path: Path):
        assert self._call(tmp_path / "does_not_exist.cue") is None

    def test_no_track_line_returns_none(self, tmp_path: Path):
        cue = tmp_path / "game.cue"
        cue.write_text("REM nothing useful here\n")
        assert self._call(cue) is None
