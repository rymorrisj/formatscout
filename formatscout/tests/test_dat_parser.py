"""Tests for backend.service.utils.smart_media_detector.hashing.dat_parser."""

from pathlib import Path

import pytest

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


class TestParseDat:
    def _call(self, path: Path) -> list[dict]:
        from backend.service.utils.smart_media_detector.hashing.dat_parser import parse_dat
        return parse_dat(path)

    def test_single_game_single_rom(self, tmp_path: Path):
        path = fx.write_dat_xml(
            tmp_path / "my_dat_file.dat",
            header_name="Sony - PlayStation",
            games=[{
                "name": "Final Fantasy VII (USA)",
                "roms": [{"sha1": "A" * 40, "md5": "B" * 32, "crc": "DEADBEEF"}],
            }],
        )
        records = self._call(path)

        assert len(records) == 1
        record = records[0]
        assert record["title"] == "Final Fantasy VII (USA)"
        assert record["platform"] == "Sony - PlayStation"
        assert record["era"] == "ps1"
        assert record["source"] == "my_dat_file"
        assert record["sha1"] == "a" * 40
        assert record["md5"] == "b" * 32
        assert record["crc32"] == "deadbeef"

    def test_hash_values_lowercased_and_stripped(self, tmp_path: Path):
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            games=[{"name": "Some Game", "roms": [{"sha1": "  ABCDEF  "}]}],
        )
        records = self._call(path)
        assert records[0]["sha1"] == "abcdef"

    def test_crc32_attribute_name_also_recognised(self, tmp_path: Path):
        """Redump DATs use "crc"; parse_dat() also accepts the literal
        "crc32" attribute name, verified by reading the rom.get("crc") or
        rom.get("crc32") line directly rather than assumed."""
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            games=[{"name": "Some Game", "roms": [{"crc32": "CAFEBABE"}]}],
        )
        records = self._call(path)
        assert records[0]["crc32"] == "cafebabe"

    def test_game_with_multiple_roms_produces_one_record_per_rom(self, tmp_path: Path):
        """A real multi-track Redump entry: one <game>, several <rom>
        children. Each rom is its own record, sharing the parent game's
        title/platform/era/source."""
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            header_name="Sony - PlayStation 2",
            games=[{
                "name": "Multi-Disc Game (Track 1+2)",
                "roms": [
                    {"sha1": "1" * 40},
                    {"sha1": "2" * 40},
                ],
            }],
        )
        records = self._call(path)

        assert len(records) == 2
        assert {r["sha1"] for r in records} == {"1" * 40, "2" * 40}
        assert all(r["title"] == "Multi-Disc Game (Track 1+2)" for r in records)
        assert all(r["era"] == "ps2" for r in records)

    def test_game_with_no_name_attribute_is_skipped(self, tmp_path: Path, caplog):
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            games=[
                {"roms": [{"sha1": "1" * 40}]},  # no "name" key at all
                {"name": "Real Game", "roms": [{"sha1": "2" * 40}]},
            ],
        )
        with caplog.at_level("WARNING"):
            records = self._call(path)

        assert len(records) == 1
        assert records[0]["title"] == "Real Game"
        assert any("no name attribute" in r.getMessage() for r in caplog.records)

    def test_rom_with_no_hash_fields_is_skipped(self, tmp_path: Path, caplog):
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            games=[{
                "name": "Some Game",
                "roms": [{}, {"sha1": "3" * 40}],  # first rom has no hash attrs at all
            }],
        )
        with caplog.at_level("WARNING"):
            records = self._call(path)

        assert len(records) == 1
        assert records[0]["sha1"] == "3" * 40
        assert any("no hash fields" in r.getMessage() for r in caplog.records)

    def test_no_header_element_platform_and_era_are_none(self, tmp_path: Path):
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            header_name=None,
            games=[{"name": "Some Game", "roms": [{"sha1": "4" * 40}]}],
        )
        records = self._call(path)

        assert records[0]["platform"] is None
        assert records[0]["era"] is None

    @pytest.mark.parametrize(
        "header_name,expected_era",
        [
            ("Sony - PlayStation 3", "ps3"),
            ("Sony - PlayStation 2", "ps2"),
            ("Sony - PlayStation", "ps1"),
            ("Microsoft - Xbox 360", "xbox360"),
            ("Microsoft - Xbox", "xbox"),
            ("Sega - Dreamcast", "dreamcast"),
            ("Nintendo - Super Nintendo Entertainment System", "snes"),
            ("Nintendo - Nintendo Entertainment System", "nes"),
            ("Nintendo - Nintendo 64", "n64"),
            ("IBM PC compatible", None),
        ],
    )
    def test_era_marker_resolution_and_precedence(self, tmp_path: Path, header_name: str, expected_era: str | None):
        """Pins the deliberate most-specific-first ordering in _ERA_MARKERS:
        "PlayStation 3"/"PlayStation 2" must resolve before the bare
        "PlayStation" substring match, "Xbox 360" before bare "Xbox", and
        "Super Nintendo..." before the "Nintendo Entertainment System"
        substring it contains. "IBM PC compatible" is deliberately unmapped
        (see dat_parser.py's own comment) and must resolve to era=None, not
        a wrong-but-confident guess.
        """
        path = fx.write_dat_xml(
            tmp_path / "game.dat",
            header_name=header_name,
            games=[{"name": "Some Game", "roms": [{"sha1": "5" * 40}]}],
        )
        records = self._call(path)
        assert records[0]["era"] == expected_era

    def test_malformed_xml_raises_valueerror_with_path_in_message(self, tmp_path: Path):
        path = tmp_path / "broken.dat"
        path.write_text("<datafile><game name=\"Unclosed\">", encoding="utf-8")

        with pytest.raises(ValueError) as exc_info:
            self._call(path)
        assert "Failed to parse DAT file" in str(exc_info.value)
        assert "broken.dat" in str(exc_info.value)
