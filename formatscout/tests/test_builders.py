"""Structure and round-trip checks for formatscout/tests/builders/.

These verify the builders themselves (and that the existing parsers can read
what they produce), not detection/era behavior. Hostile cue strings are only
inspected with plain string operations, never handed to library code.
"""

from pathlib import Path

import pytest

from formatscout.constants import ISO_LOGICAL_SECTOR_BYTES
from formatscout.tests.builders import cue
from formatscout.tests.builders.iso9660 import (
    build_iso, read_user_sector, sector_size, user_data_offset,
)

FRAMINGS = ["cooked", "mode1", "mode2_form1"]
FILES = {
    "ALPHA.DAT": b"alpha-bytes",
    "BETA_01.BIN": bytes(range(256)) * 20,
    "GAMMA.TXT": b"",
}


def _iter_records(dir_data: bytes) -> dict:
    from formatscout.iso9660_dir import iter_dir_records
    return {r.name: r for r in iter_dir_records(dir_data) if r.name not in ("\x00", "\x01")}


class TestCookedIso:
    def test_round_trip_structure_and_files(self, tmp_path: Path):
        from formatscout import iso_detect
        from formatscout.xbox_image import detect_xbox_image_type

        image = build_iso(
            FILES, volume_id="FSTEST_VOL", system_id="FSTEST_SYS",
            publisher="FSTEST_PUB", preparer="FSTEST_PREP",
        )
        path = tmp_path / "t.iso"
        path.write_bytes(image)

        assert detect_xbox_image_type(path) == "iso9660"

        pvd = image[16 * 2048:17 * 2048]
        assert pvd[1:6] == b"CD001"
        assert pvd[8:40] == b"FSTEST_SYS".ljust(32, b" ")
        assert pvd[40:72] == b"FSTEST_VOL".ljust(32, b" ")
        assert pvd[318:446] == b"FSTEST_PUB".ljust(128, b" ")
        assert pvd[446:574] == b"FSTEST_PREP".ljust(128, b" ")
        assert image[17 * 2048:17 * 2048 + 7] == b"\xffCD001\x01"

        records = _iter_records(iso_detect._read_root_dir(path, pvd))
        assert sorted(records) == sorted(FILES)
        for name, content in FILES.items():
            rec = records[name]
            assert rec.size == len(content)
            start = rec.lba * ISO_LOGICAL_SECTOR_BYTES
            assert image[start:start + rec.size] == content

    def test_extents_are_consecutive_whole_sectors(self):
        image = build_iso(FILES)
        pvd = image[16 * 2048:17 * 2048]
        import struct

        total = struct.unpack_from("<I", pvd, 80)[0]
        assert total * 2048 == len(image)
        assert pvd[80:84] == pvd[84:88][::-1]

    def test_many_files_root_directory_spans_sectors_without_splitting_records(self, tmp_path: Path):
        from formatscout import iso_detect

        files = {f"FSTEST_{i:03d}.BIN": bytes([i]) for i in range(80)}
        image = build_iso(files)
        path = tmp_path / "many.iso"
        path.write_bytes(image)
        pvd = image[16 * 2048:17 * 2048]
        root = iso_detect._read_root_dir(path, pvd)
        assert len(root) > ISO_LOGICAL_SECTOR_BYTES
        assert sorted(_iter_records(root)) == sorted(files)


class TestMode2Form1:
    @pytest.mark.parametrize(
        ("cnf", "expected"),
        [
            ("BOOT2 = cdrom0:\\FSTEST_00.000;1", "ps2"),
            ("BOOT = cdrom:\\FSTEST_00.000;1", "ps1"),
        ],
    )
    def test_system_cnf_round_trip_through_raw_reader(self, tmp_path: Path, cnf: str, expected: str):
        from formatscout.magic import magic_detect

        path = tmp_path / "t.bin"
        path.write_bytes(build_iso({}, system_cnf=cnf, framing="mode2_form1"))
        assert magic_detect._resolve_ps_generation(path) == expected

    def test_root_records_via_raw_reader(self, tmp_path: Path):
        from formatscout.magic import magic_detect

        image = build_iso(FILES, system_cnf="BOOT = x", framing="mode2_form1")
        path = tmp_path / "t.bin"
        path.write_bytes(image)
        pvd = read_user_sector(image, 16, "mode2_form1")
        import struct
        root_lba = struct.unpack_from("<I", pvd, 158)[0]
        root_size = struct.unpack_from("<I", pvd, 166)[0]
        with path.open("rb") as fh:
            dir_data = magic_detect._read_mode2_user_data(fh, root_lba, root_size)
        assert sorted(_iter_records(dir_data)) == sorted([*FILES, "SYSTEM.CNF"])

    def test_header_and_subheader(self):
        image = build_iso(FILES, framing="mode2_form1")
        sector = image[:2352]
        assert sector[:12] == b"\x00" + b"\xff" * 10 + b"\x00"
        assert sector[15] == 2
        assert sector[16:24] == bytes([0, 0, 0x08, 0]) * 2


class TestMode1:
    def test_sync_mode_and_user_data_match_cooked(self):
        cooked = build_iso(FILES, system_cnf="BOOT = x")
        raw = build_iso(FILES, system_cnf="BOOT = x", framing="mode1")
        count = len(cooked) // 2048
        assert len(raw) == count * 2352
        for lba in range(count):
            sector = raw[lba * 2352:(lba + 1) * 2352]
            assert sector[:12] == b"\x00" + b"\xff" * 10 + b"\x00"
            assert sector[15] == 1
            assert read_user_sector(raw, lba, "mode1") == read_user_sector(cooked, lba, "cooked")
            assert sector[2064:] == b"\x00" * 288

    def test_header_msf_is_bcd(self):
        raw = build_iso(FILES, framing="mode1")
        # LBA 0 -> 150 frames -> 00:02:00
        assert raw[12:15] == bytes([0x00, 0x02, 0x00])
        # LBA 16 -> 166 frames -> 00:02:16
        assert raw[16 * 2352 + 12:16 * 2352 + 15] == bytes([0x00, 0x02, 0x16])
        # LBA 17 -> 167 frames -> 00:02:17
        assert raw[17 * 2352 + 12:17 * 2352 + 15] == bytes([0x00, 0x02, 0x17])


class TestAllFramings:
    @pytest.mark.parametrize("framing", FRAMINGS)
    def test_deterministic_and_small(self, framing: str):
        a = build_iso(FILES, system_cnf="BOOT = x", framing=framing)
        b = build_iso(FILES, system_cnf="BOOT = x", framing=framing)
        assert a == b
        assert len(a) < 1024 * 1024

    @pytest.mark.parametrize("framing", FRAMINGS)
    @pytest.mark.parametrize("name", ["lower.dat", "NODOT", "TOO.MANY.DOTS", "A" * 30 + ".B", "BAD-CHAR.DAT", ".HIDDEN"])
    def test_invalid_name_raises(self, framing: str, name: str):
        with pytest.raises(ValueError):
            build_iso({name: b"x"}, framing=framing)

    def test_oversized_image_raises(self):
        with pytest.raises(ValueError):
            build_iso({"BIG.BIN": bytes(1024 * 1024)})

    def test_duplicate_system_cnf_raises(self):
        with pytest.raises(ValueError):
            build_iso({"SYSTEM.CNF": b"x"}, system_cnf="y")

    @pytest.mark.parametrize(("framing", "offset", "size"), [("cooked", 0, 2048), ("mode1", 16, 2352), ("mode2_form1", 24, 2352)])
    def test_geometry_helpers(self, framing: str, offset: int, size: int):
        assert user_data_offset(framing) == offset
        assert sector_size(framing) == size


class TestCueBuilder:
    def test_single_file_quoted(self):
        text = cue.build_cue([("disc.bin", [(1, "MODE2/2352")])])
        assert text.splitlines() == [
            'FILE "disc.bin" BINARY',
            "  TRACK 01 MODE2/2352",
            "    INDEX 01 00:00:00",
        ]

    def test_unquoted_form(self):
        assert cue.cue_file_line("disc.bin", quoted=False) == "FILE disc.bin BINARY"
        assert cue.cue_file_line("disc.bin") == 'FILE "disc.bin" BINARY'
        assert cue.cue_file_line("a.wav", file_type="WAVE") == 'FILE "a.wav" WAVE'
        assert cue.build_cue([("d.bin", [(1, "MODE1/2352")])], quoted=False).startswith("FILE d.bin BINARY\n")

    def test_multi_file_ordering(self):
        text = cue.build_cue([
            ("t1.bin", [(1, "MODE1/2352")]),
            ("t2.bin", [(2, "AUDIO"), (3, "AUDIO")]),
        ])
        lines = [ln.strip() for ln in text.splitlines()]
        assert lines == [
            'FILE "t1.bin" BINARY', "TRACK 01 MODE1/2352", "INDEX 01 00:00:00",
            'FILE "t2.bin" BINARY', "TRACK 02 AUDIO", "INDEX 01 00:00:00",
            "TRACK 03 AUDIO", "INDEX 01 00:00:00",
        ]

    @pytest.mark.parametrize(
        ("builder", "expected"),
        [
            (cue.hostile_cue_absolute_posix, "/formatscout-test-nonexistent/track.bin"),
            (cue.hostile_cue_parent_traversal, "../../formatscout-test-nonexistent/track.bin"),
            (cue.hostile_cue_parent_traversal_backslash, "..\\..\\formatscout-test-nonexistent\\track.bin"),
            (cue.hostile_cue_unc, "\\\\example.invalid\\share\\track.bin"),
            (cue.hostile_cue_drive_letter, "Z:\\formatscout-test-nonexistent\\track.bin"),
            (cue.hostile_cue_embedded_nul, "track\x00.bin"),
        ],
    )
    def test_hostile_variant_has_one_file_line_with_intended_target(self, builder, expected: str):
        text = builder()
        assert isinstance(text, str)
        file_lines = [ln for ln in text.split("\n") if ln.startswith("FILE ")]
        assert len(file_lines) == 1
        line = file_lines[0]
        assert line.endswith('" BINARY')
        assert line[len('FILE "'):-len('" BINARY')] == expected
