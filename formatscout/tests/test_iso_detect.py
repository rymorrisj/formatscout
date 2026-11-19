"""Tests for formatscout.iso_detect."""

import os
import textwrap
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx


# ---------------------------------------------------------------------------
# _cue_bin_path, multi-FILE fallthrough
# ---------------------------------------------------------------------------

class TestCueBinPath:
    """Unit tests for the internal _cue_bin_path() helper."""

    def _call(self, cue_path: Path) -> Path | None:
        from formatscout.iso_detect import _cue_bin_path
        return _cue_bin_path(cue_path)

    def test_returns_none_when_no_file_lines(self, tmp_path: Path):
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n  INDEX 01 00:00:00\n")
        assert self._call(cue) is None

    def test_returns_first_file_when_it_exists(self, tmp_path: Path):
        bin_file = tmp_path / "game.bin"
        bin_file.write_bytes(b"\x00" * 16)
        cue = tmp_path / "game.cue"
        cue.write_text(f'FILE "{bin_file.name}" BINARY\n  TRACK 01 MODE2/2352\n')
        result = self._call(cue)
        # _cue_bin_path() returns the strictly resolved target (see
        # utils/safe_path.py), not the raw join.
        assert result == bin_file.resolve()

    def test_falls_through_to_second_file_when_first_missing(self, tmp_path: Path):
        """The primary regression test: first FILE entry points to a nonexistent
        path; _cue_bin_path() must continue and return the second entry."""
        real_bin = tmp_path / "game_track02.bin"
        real_bin.write_bytes(b"\x00" * 16)

        cue_content = textwrap.dedent(f"""\
            FILE "MISSING_track01.bin" BINARY
              TRACK 01 MODE2/2352
                INDEX 01 00:00:00
            FILE "{real_bin.name}" BINARY
              TRACK 02 MODE2/2352
                INDEX 01 03:27:00
        """)
        cue = tmp_path / "game.cue"
        cue.write_text(cue_content)

        result = self._call(cue)
        assert result == real_bin.resolve(), (
            "_cue_bin_path() must return the second FILE entry when the first "
            "does not exist on disk"
        )

    def test_returns_none_when_all_files_missing(self, tmp_path: Path):
        cue_content = textwrap.dedent("""\
            FILE "missing_track01.bin" BINARY
              TRACK 01 MODE2/2352
            FILE "also_missing_track02.bin" BINARY
              TRACK 02 AUDIO
        """)
        cue = tmp_path / "game.cue"
        cue.write_text(cue_content)
        assert self._call(cue) is None

    def test_handles_unreadable_cue_gracefully(self, tmp_path: Path):
        """Non-existent .cue path must return None, not raise."""
        ghost = tmp_path / "nonexistent.cue"
        assert self._call(ghost) is None


# ---------------------------------------------------------------------------
# _root_dir_entry_names, raw ISO 9660 directory record parsing
# ---------------------------------------------------------------------------

class TestRootDirEntryNames:
    def _call(self, dir_data: bytes) -> list[str]:
        from formatscout.iso_detect import _root_dir_entry_names
        return _root_dir_entry_names(dir_data)

    def test_empty_bytes_returns_empty_list(self):
        assert self._call(b"") == []

    def test_parses_multiple_entries_and_uppercases(self):
        dir_data = fx._dir_record(b"game.dat", 0, 0) + fx._dir_record(b"README.TXT", 0, 0)
        assert self._call(dir_data) == ["GAME.DAT", "README.TXT"]

    def test_strips_version_suffix(self):
        dir_data = fx._dir_record(b"GAME.DAT;1", 0, 0)
        assert self._call(dir_data) == ["GAME.DAT"]

    def test_skips_zero_padding_to_next_sector_boundary(self):
        """rec_len == 0 mid-buffer means padding to the next 2048-byte sector,
        not end of data, the record right after the boundary must still be
        parsed, matching how a real multi-sector root directory read behaves.
        """
        first = fx._dir_record(b"FIRST.DAT", 0, 0)
        padded = first + b"\x00" * (fx.ISO_SECTOR - len(first))
        second = fx._dir_record(b"SECOND.DAT", 0, 0)
        dir_data = padded + second
        assert self._call(dir_data) == ["FIRST.DAT", "SECOND.DAT"]

    def test_truncated_record_header_stops_cleanly(self):
        """A record whose declared length would read past the end of
        dir_data must stop parsing rather than raise or read garbage."""
        dir_data = fx._dir_record(b"OK.DAT", 0, 0) + bytes([50]) + b"\x00" * 5
        assert self._call(dir_data) == ["OK.DAT"]


# ---------------------------------------------------------------------------
# _xbe_result_from_names(_root_dir_entry_names(dir_data)), takes pre-read
# dir_data, no file access. detect_from_pvd() composes these two directly
# rather than through a wrapper, since that is its only production caller.
# ---------------------------------------------------------------------------

class TestDetectFromXbeScan:
    def _call(self, dir_data: bytes):
        from formatscout.iso_detect import _root_dir_entry_names, _xbe_result_from_names
        return _xbe_result_from_names(_root_dir_entry_names(dir_data))

    def test_finds_xbe_case_insensitively(self):
        dir_data = fx._dir_record(b"default.xbe", 0, 0)
        result = self._call(dir_data)
        assert result.era == "xbox"
        assert result.confidence == 0.8

    def test_no_xbe_present_returns_null(self):
        dir_data = fx._dir_record(b"GAME.DAT", 0, 0)
        result = self._call(dir_data)
        assert result.era is None

    def test_empty_dir_data_returns_null(self):
        result = self._call(b"")
        assert result.era is None


# ---------------------------------------------------------------------------
# Regression: iso_detect reopen dedupe (perf pass, commit 98ce932).
# _root_dir_entry_names()/_xbe_result_from_names() take pre-read dir_data
# bytes, not a Path, they must never touch the filesystem themselves, and
# detect_from_pvd() must read the root directory exactly once and reuse it
# for both the PS3_DISC.SFB check and the .xbe scan.
# ---------------------------------------------------------------------------

class TestIsoDetectReopenAvoidance:
    def test_root_dir_entry_names_and_xbe_scan_never_touch_the_filesystem(self, monkeypatch):
        from formatscout.iso_detect import (
            _root_dir_entry_names,
            _xbe_result_from_names,
        )

        def _boom(self, *a, **kw):
            raise AssertionError(
                "_root_dir_entry_names()/_xbe_result_from_names() must not open any file "
                "themselves, they must operate purely on pre-read dir_data bytes"
            )

        monkeypatch.setattr(Path, "open", _boom)

        dir_data = fx._dir_record(b"GAME.XBE", 0, 0) + fx._dir_record(b"OTHER.DAT", 0, 0)
        names = _root_dir_entry_names(dir_data)
        assert names == ["GAME.XBE", "OTHER.DAT"]
        assert _xbe_result_from_names(names).era == "xbox"

    def test_detect_from_pvd_opens_the_file_exactly_twice(self, tmp_path: Path, monkeypatch):
        """One open for the PVD sector read, one for the root directory read
        inside _read_root_dir(), not one more per downstream helper that
        consumes the resulting dir_data.
        """
        from formatscout.iso_detect import detect_from_pvd

        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", root_entries=["GAME.XBE"])

        open_calls = {"n": 0}
        original_open = Path.open

        def _counting_open(self, *args, **kwargs):
            if self == iso_path:
                open_calls["n"] += 1
            return original_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", _counting_open)

        result = detect_from_pvd(iso_path)

        assert result.era == "xbox"
        assert open_calls["n"] == 2, (
            f"expected exactly 2 opens of the ISO (PVD sector + root directory), "
            f"got {open_calls['n']}, a helper may be reopening the file redundantly"
        )


# ---------------------------------------------------------------------------
# detect_from_pvd, structural checks (PS3_DISC.SFB, .xbe scan), volume-label
# keyword matching, publisher/preparer DOS matching, PS1/PS2 disambiguation
# ---------------------------------------------------------------------------

class TestDetectFromPvd:
    def _call(self, iso_path: Path):
        from formatscout.iso_detect import detect_from_pvd
        return detect_from_pvd(iso_path)

    def test_ps3_disc_sfb_root_entry(self, tmp_path: Path):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", root_entries=["PS3_DISC.SFB"])
        result = self._call(iso_path)
        assert result.era == "ps3"
        assert result.confidence == 0.9
        assert "PS3_DISC.SFB" in result.reason

    def test_xbe_root_entry(self, tmp_path: Path):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", root_entries=["DEFAULT.XBE"])
        result = self._call(iso_path)
        assert result.era == "xbox"
        assert result.confidence == 0.8

    def test_structural_check_wins_over_volume_label_keyword_match(self, tmp_path: Path):
        """PS3_DISC.SFB must win even when the volume label would otherwise
        match a DOS keyword outright, pins the ordering the source comment
        calls out explicitly (structural checks run before the loose
        volume-label keyword loop).
        """
        iso_path = fx.write_pvd_iso(
            tmp_path / "game.iso", volume_id="MSDOS", root_entries=["PS3_DISC.SFB"],
        )
        result = self._call(iso_path)
        assert result.era == "ps3"

    @pytest.mark.parametrize("keyword", fx.WINXP_VOLUME_KEYWORDS)
    def test_winxp_volume_label_keywords(self, tmp_path: Path, keyword: str):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id=keyword)
        result = self._call(iso_path)
        assert result.era == "winxp"
        assert result.confidence == 0.75

    @pytest.mark.parametrize("keyword", fx.WIN98_VOLUME_KEYWORDS)
    def test_win98_volume_label_keywords(self, tmp_path: Path, keyword: str):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id=keyword)
        result = self._call(iso_path)
        assert result.era == "win98"
        assert result.confidence == 0.75

    @pytest.mark.parametrize("keyword", fx.WIN95_VOLUME_KEYWORDS)
    def test_win95_volume_label_keywords(self, tmp_path: Path, keyword: str):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id=keyword)
        result = self._call(iso_path)
        assert result.era == "win95"
        assert result.confidence == 0.75

    @pytest.mark.parametrize("keyword", fx.DOS_VOLUME_KEYWORDS)
    def test_dos_volume_label_keywords(self, tmp_path: Path, keyword: str):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id=keyword)
        result = self._call(iso_path)
        assert result.era == "dos"
        assert result.confidence == 0.75

    @pytest.mark.parametrize("publisher", fx.DOS_PUBLISHERS)
    def test_dos_publisher_field_keywords(self, tmp_path: Path, publisher: str):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", publisher=publisher)
        result = self._call(iso_path)
        assert result.era == "dos"
        assert result.confidence == 0.7
        assert "publisher" in result.reason

    @pytest.mark.parametrize("publisher", fx.DOS_PUBLISHERS[:2])
    def test_dos_preparer_field_keywords(self, tmp_path: Path, publisher: str):
        """Same _DOS_PUBLISHERS set is checked against the preparer field too
        (the second iteration of the (publisher, preparer) loop), spot-check
        two rather than all 11 since the loop body is identical either way.
        """
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", preparer=publisher)
        result = self._call(iso_path)
        assert result.era == "dos"
        assert "preparer" in result.reason

    def test_ps_serial_label_without_system_cnf_is_ambiguous_not_ps1(self, tmp_path: Path):
        """A serial-shaped volume label with no readable SYSTEM.CNF narrows
        the answer to PS1 or PS2 but names neither (no PS1 default)."""
        from formatscout.result import Status

        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLUS_123.45")
        result = self._call(iso_path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]
        assert "pvd_ps_serial_label" in result.evidence

    def test_ps_serial_label_dvd_size_only_orders_candidates(self, tmp_path: Path):
        """Over 4.7 GB the size puts ps2 first, at a higher tier, but still
        names no era. A sparse-truncated file is used so the test doesn't
        actually write gigabytes to disk.
        """
        from formatscout.result import Method, Status, Tier

        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLES_123.45")
        with iso_path.open("r+b") as fh:
            fh.truncate(4_800_000_000)
        result = self._call(iso_path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert result.method == Method.SIZE_HEURISTIC
        assert [(c.era, c.tier) for c in result.candidates] == [("ps2", Tier.MODERATE), ("ps1", Tier.WEAK)]
        assert "size_over_dvd5" in result.evidence

    def test_sony_publisher_with_cdrom_system_id_is_ambiguous_regardless_of_size(self, tmp_path: Path):
        """sys_id == 'CD-ROM' + 'SONY' in publisher is a PlayStation hint even
        without a serial-shaped label, but without SYSTEM.CNF it is never
        called ps1, at any size.
        """
        from formatscout.result import Status

        iso_path = fx.write_pvd_iso(
            tmp_path / "game.iso", system_id="CD-ROM",
            publisher="SONY COMPUTER ENTERTAINMENT", volume_id="RANDOMTITLE",
        )
        with iso_path.open("r+b") as fh:
            fh.truncate(4_800_000_000)
        result = self._call(iso_path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert {c.era for c in result.candidates} == {"ps1", "ps2"}
        assert "pvd_sony_cdrom" in result.evidence

    def test_stat_failure_never_defaults_to_ps1(self, tmp_path: Path, monkeypatch):
        """The size lookup failing used to fall back to size 0 and so to ps1.
        It now only leaves the candidate order at its default."""
        from formatscout.result import Status

        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SCUS_942.34")
        original_stat = Path.stat

        def _stat(self, *args, **kwargs):
            if self == iso_path:
                raise OSError("stat failed")
            return original_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _stat)
        result = self._call(iso_path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_dos_publisher_rule_runs_after_playstation_checks(self, tmp_path: Path):
        """A serial-shaped label wins over a DOS publisher keyword, so a
        PlayStation disc published by e.g. Activision is not called dos."""
        from formatscout.result import Status

        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLUS_008.67", publisher="ACTIVISION")
        result = self._call(iso_path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS

    def test_type_code_1_without_cd001_returns_null(self, tmp_path: Path):
        """Type code 1 alone is not a PVD: the standard identifier CD001 must
        follow it."""
        image = bytearray(fx.build_pvd_iso(volume_id="WINXP"))
        image[16 * fx.ISO_SECTOR + 1:16 * fx.ISO_SECTOR + 6] = b"XXXXX"
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(bytes(image))
        result = self._call(iso_path)
        assert result.era is None
        assert result.confidence == 0.0

    def test_no_signal_returns_null(self, tmp_path: Path):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="RANDOMTITLE")
        result = self._call(iso_path)
        assert result.era is None
        assert result.confidence == 0.0

    def test_invalid_pvd_type_code_returns_null(self, tmp_path: Path):
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(b"\x00" * 40000)
        result = self._call(iso_path)
        assert result.era is None

    def test_too_short_for_a_pvd_returns_null(self, tmp_path: Path):
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(b"\x00" * 100)
        result = self._call(iso_path)
        assert result.era is None

    def test_read_error_is_caught_and_reported(self, tmp_path: Path):
        ghost = tmp_path / "does_not_exist.iso"
        result = self._call(ghost)
        assert result.era is None
        assert "ISO PVD read error" in result.reason


# ---------------------------------------------------------------------------
# detect_from_pvd, SYSTEM.CNF read from the ISO 9660 root (strict BOOT/BOOT2
# key match). Built with builders.iso9660.build_iso, which stores SYSTEM.CNF
# at a real extent the root record points to.
# ---------------------------------------------------------------------------

PS1_CNF = "BOOT = cdrom:\\SLUS_000.01;1\r\nTCB = 4\r\nEVENT = 10\r\n"
PS2_CNF = "BOOT2 = cdrom0:\\SLUS_200.62;1\r\nVER = 1.00\r\nVMODE = NTSC\r\n"


class TestDetectFromPvdSystemCnf:
    def _call(self, tmp_path: Path, cnf, **kwargs):
        from formatscout.iso_detect import detect_from_pvd
        from formatscout.tests.builders.iso9660 import build_iso

        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(build_iso({}, system_cnf=cnf, **kwargs))
        return detect_from_pvd(iso_path)

    @pytest.mark.parametrize("cnf, era", [(PS1_CNF, "ps1"), (PS2_CNF, "ps2")])
    @pytest.mark.parametrize("volume_id", ["FSTITLE", "SLUS_200.62"])
    def test_boot_key_names_the_era_authoritatively(self, tmp_path: Path, cnf: str, era: str, volume_id: str):
        """Any volume label, serial-shaped or not: the key decides, and a
        CD-sized BOOT2 image is ps2 (no size rule)."""
        from formatscout.result import Method, Status

        result = self._call(tmp_path, cnf, volume_id=volume_id)
        assert result.era == era
        assert result.method == Method.SYSTEM_CNF
        assert result.authoritative is True
        assert result.status == Status.IDENTIFIED
        assert result.container == "iso9660"
        assert "pvd_root_system_cnf" in result.evidence

    def test_system_cnf_wins_over_volume_label_keyword(self, tmp_path: Path):
        result = self._call(tmp_path, PS2_CNF, volume_id="MSDOS")
        assert result.era == "ps2"

    @pytest.mark.parametrize(
        "cnf",
        [
            "",
            "garbage without any key\r\n",
            b"\x00\x01\x02\xff",
            "VER = BOOT2\r\n",
            "XBOOT2 = cdrom0:\\SLUS_200.62;1\r\n",
            "BOOTX = cdrom:\\SLUS_000.01;1\r\n",
            "BOOT2 cdrom0:\\SLUS_200.62;1\r\n",
        ],
    )
    def test_no_boot_key_names_no_era(self, tmp_path: Path, cnf: str | bytes):
        """No BOOT or BOOT2 key (empty, garbage, the token only inside a value
        or as part of a longer key, no "=") is no era. SYSTEM.CNF being there
        at all still makes it a PS1-or-PS2 ambiguous result."""
        from formatscout.result import Status

        result = self._call(tmp_path, cnf, volume_id="FSTITLE")
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]
        assert "pvd_root_system_cnf_no_boot_key" in result.evidence

    def test_system_cnf_record_at_lba_zero_is_not_read(self, tmp_path: Path):
        """fx.build_pvd_iso writes root records with LBA 0, which is the
        system area, never a file extent."""
        from formatscout.iso_detect import detect_from_pvd
        from formatscout.result import Status

        result = detect_from_pvd(fx.write_pvd_iso(tmp_path / "game.iso", root_entries=["SYSTEM.CNF"]))
        assert result.era is None
        assert result.status == Status.AMBIGUOUS

    def test_system_cnf_read_is_capped(self, tmp_path: Path):
        """A BOOT2 line past the read cap is never seen."""
        from formatscout.magic.magic_detect import SYSTEM_CNF_READ_CAP_BYTES

        cnf = "VER = 1.00\r\n" * (SYSTEM_CNF_READ_CAP_BYTES // 12 + 1) + PS2_CNF
        result = self._call(tmp_path, cnf, volume_id="FSTITLE")
        assert result.era is None


# ---------------------------------------------------------------------------
# detect_iso, dispatch order: detect_from_magic -> detect_from_pvd ->
# xbox_image.probe_xbox_image (XDVDFS) -> ambiguous PVD -> size fallback.
#
# With no XDVDFS layout (probe_xbox_image() returns None), the size fallback
# is reached either with the ISO 9660 magic confirmed
# (xbox_image.has_iso9660_magic() True, "iso9660" below) or without it
# ("unknown" below), so the size-fallback tests are parametrized over both.
# No size rule ever names an Xbox era.
#
# NOTE: magic_signatures.toml has zero signatures with "iso" in applies_to
# today, so detect_from_magic(path, "iso") can never return a non-None era
# for a real .iso file. That branch is exercised here via monkeypatch
# (dependency injection on the wiring), not a real magic-byte fixture.
# ---------------------------------------------------------------------------

NON_XBOX_IMAGE_TYPES = ("iso9660", "unknown")


def _no_xbox_layout(monkeypatch, image_type: str) -> None:
    """No XDVDFS layout; the ISO 9660 magic is present only for "iso9660"."""
    from formatscout import iso_detect

    monkeypatch.setattr(iso_detect, "probe_xbox_image", lambda path: None)
    monkeypatch.setattr(iso_detect, "has_iso9660_magic", lambda path: image_type == "iso9660")


class TestDetectIso:
    def test_magic_match_short_circuits_before_pvd(self, tmp_path: Path, monkeypatch):
        from formatscout import iso_detect

        def _fake_magic(path, extension):
            assert extension == "iso"
            return "ps2", "fake magic match"

        monkeypatch.setattr(iso_detect, "detect_from_magic", _fake_magic)
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(b"\x00" * 100)  # too short for a real PVD too

        result = iso_detect.detect_iso(iso_path)
        assert result.era == "ps2"
        assert result.confidence == 0.9
        assert result.reason == "fake magic match"

    def test_falls_through_to_pvd_when_no_magic_match(self, tmp_path: Path, monkeypatch):
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="WINXP")

        result = iso_detect.detect_iso(iso_path)
        assert result.era == "winxp"

    def test_ambiguous_playstation_pvd_is_returned_not_the_size_fallback(self, tmp_path: Path):
        """A serial-shaped label without SYSTEM.CNF reaches detect_iso as an
        ambiguous ps1/ps2 result, which must not be replaced by the weaker
        size fallback. Nothing mocked."""
        from formatscout import iso_detect
        from formatscout.result import Status

        result = iso_detect.detect_iso(fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLUS_123.45"))
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_iso9660_over_4gib_is_not_an_xbox_rip(self, tmp_path: Path):
        """The removed "CD001 plus over 4 GiB is an Xbox DVD rip" rule: an
        ISO 9660 image that size with no other signal has no era and does
        not require extraction. Nothing mocked.

        Layout: "CD001" at 0x8001 (byte 0x8000 left zero so detect_from_pvd()
        sees no valid PVD type code), nothing at any XDVDFS offset, and a
        sparse-truncated size past 4 GiB.
        """
        from formatscout import iso_detect
        from formatscout.result import Status

        iso_path = tmp_path / "game.iso"
        with iso_path.open("wb") as fh:
            fh.seek(0x8001)
            fh.write(b"CD001")
            fh.truncate(4_400_000_000)

        result = iso_detect.detect_iso(iso_path)
        assert result.era is None
        assert result.requires_extraction is False
        assert result.status == Status.AMBIGUOUS
        assert result.container == "iso9660"


# ---------------------------------------------------------------------------
# detect_iso, XDVDFS (xbox_image.probe_xbox_image): xISO at 0x10000 told
# apart by DEFAULT.XBE / DEFAULT.XEX, other XGD layouts unsupported.
# Built with tests/builders/xdvdfs.py (UNVERIFIED against real media).
# ---------------------------------------------------------------------------

def _write_xdvdfs(tmp_path: Path, executable: str = "DEFAULT.XBE", **kwargs) -> Path:
    from formatscout.tests.builders.xdvdfs import build_xdvdfs

    path = tmp_path / "game.iso"
    path.write_bytes(build_xdvdfs(executable, **kwargs).data)
    return path


class TestDetectIsoXdvdfs:
    def _call(self, path: Path):
        from formatscout.iso_detect import detect_iso
        return detect_iso(path)

    @pytest.mark.parametrize("executable, era", [("DEFAULT.XBE", "xbox"), ("DEFAULT.XEX", "xbox360")])
    def test_default_executable_names_the_era(self, tmp_path: Path, executable: str, era: str):
        from formatscout.result import Method, Status

        result = self._call(_write_xdvdfs(tmp_path, executable, extra_files={"MEDIA.BIN": b"m"}))
        assert result.era == era
        assert result.method == Method.MAGIC
        assert result.status == Status.GUESS
        assert result.authoritative is False
        assert result.container == "xdvdfs"
        assert result.requires_extraction is False
        assert f"xdvdfs_root_{executable.lower().replace('.', '_')}" in result.evidence

    def test_lowercase_root_name_still_matches(self, tmp_path: Path):
        result = self._call(_write_xdvdfs(tmp_path, "default.xex"))
        assert result.era == "xbox360"

    @pytest.mark.parametrize(
        "executable, extra",
        [("GAME.XBE", {}), ("DEFAULT.XBE", {"DEFAULT.XEX": b"XEX2"})],
        ids=["neither", "both"],
    )
    def test_no_single_default_executable_is_container_only(self, tmp_path: Path, executable: str, extra: dict):
        from formatscout.result import Status

        result = self._call(_write_xdvdfs(tmp_path, executable, extra_files=extra))
        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == "xdvdfs"
        assert [c.era for c in result.candidates] == ["xbox", "xbox360"]
        assert result.requires_extraction is False

    def test_magic_with_zero_root_fields_is_ambiguous(self, tmp_path: Path):
        from formatscout.result import Status
        from formatscout.tests.builders.xdvdfs import build_xdvdfs

        image = build_xdvdfs("DEFAULT.XBE")
        data = bytearray(image.data)
        data[image.magic_offset + 20:image.magic_offset + 28] = bytes(8)
        path = tmp_path / "game.iso"
        path.write_bytes(bytes(data))

        result = self._call(path)
        assert result.era is None
        assert result.status == Status.AMBIGUOUS
        assert result.container is None
        assert result.requires_extraction is False

    @pytest.mark.parametrize("cut", ["before_root", "mid_root"])
    def test_truncated_image_never_names_an_era(self, tmp_path: Path, cut: str):
        from formatscout.tests.builders.xdvdfs import build_xdvdfs

        image = build_xdvdfs("DEFAULT.XBE")
        end = image.root_offset if cut == "before_root" else image.root_offset + 8
        path = tmp_path / "game.iso"
        path.write_bytes(image.data[:end])
        assert self._call(path).era is None

    def test_xgd_partition_layout_is_unsupported(self, tmp_path: Path):
        """Magic plus usable root fields past an XGD partition offset: the
        layout is recognised but not parsed. Sparse file, nothing mocked."""
        from formatscout.result import IssueCode, Status
        from formatscout.tests.builders.xdvdfs import build_xdvdfs
        from formatscout.xbox_image import XDVDFS_DESCRIPTOR_OFFSET, XGD_PARTITION_OFFSETS

        layout, partition = XGD_PARTITION_OFFSETS[-1]
        image = build_xdvdfs("DEFAULT.XEX")
        path = tmp_path / "game.iso"
        with path.open("wb") as fh:
            fh.seek(partition)
            fh.write(image.data)
        assert image.magic_offset == XDVDFS_DESCRIPTOR_OFFSET

        result = self._call(path)
        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == "xdvdfs"
        assert [c.era for c in result.candidates] == ["xbox", "xbox360"]
        assert [issue.code for issue in result.issues] == [IssueCode.UNSUPPORTED_LAYOUT]
        assert f"{layout}_partition" in result.evidence
        assert result.requires_extraction is True

    def test_xgd_magic_without_root_fields_does_not_require_extraction(self, tmp_path: Path, monkeypatch):
        from formatscout import iso_detect
        from formatscout.xbox_image import XboxProbe

        monkeypatch.setattr(iso_detect, "probe_xbox_image", lambda path: XboxProbe("xgd2", 0x0FD90000, False))
        path = tmp_path / "game.iso"
        path.write_bytes(b"\x00" * 100)
        result = self._call(path)
        assert result.era is None
        assert result.requires_extraction is False


# ---------------------------------------------------------------------------
# xbox_image._walk_root_names: the XDVDFS root-directory tree walk must stay
# bounded on hostile tables (cycles, deep chains, huge entry counts).
# ---------------------------------------------------------------------------

def _xdvdfs_entry(left: int, right: int, name: bytes) -> bytes:
    import struct

    body = struct.pack("<HHIIBB", left, right, 40, 1, 0x20, len(name)) + name
    return body + b"\xff" * (-len(body) % 4)


class TestXdvdfsRootWalk:
    def _call(self, table: bytes):
        from formatscout.xbox_image import _walk_root_names
        return _walk_root_names(table)

    def test_self_and_mutual_cycles_terminate(self):
        # E0 -> E1 (right); E1 -> itself (left) and E2 (right); E2 -> E1 (left).
        off1 = len(_xdvdfs_entry(0, 0, b"DEFAULT.XBE"))
        off2 = off1 + len(_xdvdfs_entry(0, 0, b"B.BIN"))
        table = (
            _xdvdfs_entry(0, off1 // 4, b"DEFAULT.XBE")
            + _xdvdfs_entry(off1 // 4, off2 // 4, b"B.BIN")
            + _xdvdfs_entry(off1 // 4, 0, b"C.BIN")
        )
        names, truncated = self._call(table)
        assert names == {"DEFAULT.XBE", "B.BIN", "C.BIN"}
        assert truncated is False

    def test_child_offset_past_the_table_is_ignored(self):
        names, _ = self._call(_xdvdfs_entry(0x7FFF, 0x1234, b"DEFAULT.XEX"))
        assert names == {"DEFAULT.XEX"}

    def test_padding_and_short_tables_yield_nothing(self):
        assert self._call(b"\xff" * 2048) == (frozenset(), False)
        assert self._call(b"") == (frozenset(), False)
        assert self._call(b"\x00" * 10) == (frozenset(), False)

    def test_name_running_past_the_table_is_skipped(self):
        entry = _xdvdfs_entry(0, 0, b"DEFAULT.XBE")
        assert self._call(entry[:16]) == (frozenset(), False)

    def test_depth_cap_stops_a_long_chain(self):
        from formatscout.xbox_image import XDVDFS_MAX_DEPTH

        count = XDVDFS_MAX_DEPTH + 10
        size = len(_xdvdfs_entry(0, 0, b"F0000.BIN"))
        table = b"".join(
            _xdvdfs_entry(0, ((i + 1) * size) // 4 if i + 1 < count else 0, f"F{i:04d}.BIN".encode())
            for i in range(count)
        )
        names, truncated = self._call(table)
        assert truncated is True
        assert len(names) == XDVDFS_MAX_DEPTH + 1

    def test_entry_cap_bounds_a_wide_tree(self):
        from formatscout.xbox_image import XDVDFS_MAX_ENTRIES

        # Every entry links to the next two: a tree far wider than the cap.
        count = XDVDFS_MAX_ENTRIES + 50
        size = len(_xdvdfs_entry(0, 0, b"F00000.B"))
        table = b"".join(
            _xdvdfs_entry(
                ((2 * i + 1) * size) // 4 if 2 * i + 1 < count else 0,
                ((2 * i + 2) * size) // 4 if 2 * i + 2 < count else 0,
                f"F{i:05d}.B".encode(),
            )
            for i in range(count)
        )
        names, truncated = self._call(table)
        assert truncated is True
        assert len(names) == XDVDFS_MAX_ENTRIES


# ---------------------------------------------------------------------------
# detect_iso, size fallback with no XDVDFS layout (see _no_xbox_layout).
# ---------------------------------------------------------------------------

class TestDetectIsoSizeFallback:
    @pytest.mark.parametrize("image_type", NON_XBOX_IMAGE_TYPES)
    def test_falls_through_to_size_fallback_over_4gb(self, tmp_path: Path, monkeypatch, image_type: str):
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        _no_xbox_layout(monkeypatch, image_type)
        iso_path = tmp_path / "game.iso"
        iso_path.touch()
        os.truncate(iso_path, 5_000_000_000)

        result = iso_detect.detect_iso(iso_path)
        assert result.era is None
        assert result.confidence == 0.2
        assert result.requires_extraction is False
        assert result.warnings

    @pytest.mark.parametrize("image_type", NON_XBOX_IMAGE_TYPES)
    def test_falls_through_to_size_fallback_under_800mb(self, tmp_path: Path, monkeypatch, image_type: str):
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        _no_xbox_layout(monkeypatch, image_type)
        iso_path = tmp_path / "game.iso"
        iso_path.touch()
        os.truncate(iso_path, 500 * 1024 * 1024)

        result = iso_detect.detect_iso(iso_path)
        assert result.era is None
        assert result.confidence == 0.2
        assert result.requires_extraction is False
        assert result.warnings

    def test_unknown_image_type_in_normal_size_range_is_no_signal(self, tmp_path: Path, monkeypatch):
        """"unknown" means not even the ISO 9660 magic was found, so at an
        unremarkable size there is genuinely nothing to report.
        """
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        _no_xbox_layout(monkeypatch, "unknown")
        iso_path = tmp_path / "game.iso"
        iso_path.touch()
        os.truncate(iso_path, 1_000_000_000)

        result = iso_detect.detect_iso(iso_path)
        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "no signal found"
        assert result.requires_extraction is False

    def test_iso9660_confirmation_is_not_discarded_in_normal_size_range(self, tmp_path: Path, monkeypatch):
        """"iso9660" is a real signal even at an unremarkable size: the
        container format is confirmed, only the platform is unknown. It must
        not collapse into the same zero-confidence "no signal found" an
        unrecognisable file gets, since the two call for different handling.
        era still stays None, a filesystem signature names no platform.
        """
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        _no_xbox_layout(monkeypatch, "iso9660")
        iso_path = tmp_path / "game.iso"
        iso_path.touch()
        os.truncate(iso_path, 1_000_000_000)

        result = iso_detect.detect_iso(iso_path)
        assert result.era is None
        assert result.confidence == 0.2
        assert result.reason != "no signal found"
        assert "ISO 9660 magic confirmed" in result.reason
        assert result.warnings
        assert result.requires_extraction is False

    @pytest.mark.parametrize("image_type", NON_XBOX_IMAGE_TYPES)
    def test_size_fallback_reason_reflects_whether_iso9660_was_confirmed(
        self, tmp_path: Path, monkeypatch, image_type: str,
    ):
        """Both fall to the same size branch at the same confidence, but the
        reason string must still say which of the two situations it was.
        """
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        _no_xbox_layout(monkeypatch, image_type)
        iso_path = tmp_path / "game.iso"
        iso_path.touch()
        os.truncate(iso_path, 500 * 1024 * 1024)

        result = iso_detect.detect_iso(iso_path)
        assert result.confidence == 0.2
        if image_type == "iso9660":
            assert "ISO 9660 magic confirmed" in result.reason
        else:
            assert "no PVD signal" in result.reason


# ---------------------------------------------------------------------------
# detect_cue, resolves the .bin sibling, then re-runs the same magic-byte
# and PVD checks detect_iso() runs, falling back to
# bin_validator.resolve_bin_cue() when neither finds a signal.
# _cue_bin_path()'s own FILE-line parsing is already covered above
# (TestCueBinPath); these tests use a cue with no FILE line throughout, so
# the bin is resolved via the cue.with_suffix(".bin") fallback branch
# instead, and exercise detect_cue()'s own downstream dispatch, not that
# helper. No mocking anywhere below, every check is the real dependency.
# ---------------------------------------------------------------------------

class TestDetectCue:
    def _call(self, cue_path: Path, dir_cache=None):
        from formatscout.iso_detect import detect_cue
        return detect_cue(cue_path, dir_cache)

    def test_no_resolvable_bin_returns_zero_confidence_with_warning(self, tmp_path: Path):
        """Neither a FILE line in the cue nor a same-stem sibling .bin exists."""
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n")

        result = self._call(cue)
        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "no .bin file found for .cue sheet"
        assert result.warnings and "game.cue" in result.warnings[0]

    def test_magic_byte_match_on_bin_resolved_via_with_suffix_fallback(self, tmp_path: Path):
        """Cue has no FILE line, so the bin is resolved via
        cue.with_suffix(".bin") rather than _cue_bin_path(). The bin's real
        Dreamcast IP.BIN magic must still be found and win immediately.
        """
        (tmp_path / "game.bin").write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n")

        result = self._call(cue)
        assert result.era == "dreamcast"
        assert result.confidence == 0.9

    def test_pvd_fallback_when_no_magic_match(self, tmp_path: Path):
        """No magic-byte signature present, but the resolved bin has a valid
        ISO9660 PVD with a recognisable DOS volume label.
        """
        (tmp_path / "game.bin").write_bytes(fx.build_pvd_iso(volume_id="MSDOS"))
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n")

        result = self._call(cue)
        assert result.era == "dos"
        assert result.confidence == 0.75
        assert "MSDOS" in result.reason

    def test_falls_through_to_bin_validator_when_no_magic_or_pvd_signal(self, tmp_path: Path):
        """No magic match, no PVD (all-zero bin), cue declares MODE2/2352.
        resolve_bin_cue()'s own re-derived cue lookup (by matching stem, not
        the FILE line, see _find_cue in bin_validator.py) must find this
        exact cue file and read its track type from it.
        """
        (tmp_path / "game.bin").write_bytes(b"\x00" * 4096)
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 MODE2/2352\n")

        result = self._call(cue)
        assert result.era is None
        assert result.confidence == 0.4
        assert "MODE2/2352" in result.reason
        assert "platform ambiguous" in result.reason

    def test_dir_cache_is_threaded_through_to_bin_validator(self, tmp_path: Path, monkeypatch):
        """dir_cache is detect_cue()'s second parameter purely to hand off to
        bin_validator.resolve_bin_cue()'s own dir_cache-aware _find_cue, not
        used directly by detect_cue() itself. Proven decisively, not just by
        checking the result is correct (a correct result alone wouldn't rule
        out a fresh iterdir() ignoring the cache and re-deriving the same
        answer): Path.iterdir() is broken outright, so the test only passes
        if resolution genuinely comes from the pre-populated cache entry.
        """
        bin_path = tmp_path / "game.bin"
        bin_path.write_bytes(b"\x00" * 4096)
        cue = tmp_path / "game.cue"
        cue.write_text("TRACK 01 AUDIO\n")
        dir_cache = {tmp_path: [bin_path, cue]}

        def _boom(self):
            raise AssertionError("iterdir() must not be called when dir_cache already has this directory")

        monkeypatch.setattr(Path, "iterdir", _boom)

        result = self._call(cue, dir_cache)
        assert result.confidence == 0.2
        assert "AUDIO" in result.reason


# ---------------------------------------------------------------------------
# detect_chd, delegation to validators.chd_validator.detect_chd_platform()
# plus the CHD contract mapping (iso_detect._reconcile_chd_result). Full CHD
# parsing logic is covered by test_chd_validator.py; these confirm the wiring
# and the mapping from both the current validator result shape and the
# contract shape the validator is moving to.
# ---------------------------------------------------------------------------

def _fake_chd(monkeypatch, result):
    from formatscout.validators import chd_validator

    monkeypatch.setattr(chd_validator, "detect_chd_platform", lambda path: result)


def _chd_scan(**kwargs):
    from formatscout.result import ScanResult

    base = dict(title=None, platform=None, era=None, confidence=0.0, reason="validator")
    base.update(kwargs)
    return ScanResult(**base)


class TestDetectChdContract:
    def _call(self, tmp_path: Path):
        from formatscout.iso_detect import detect_chd

        path = tmp_path / "game.chd"
        path.write_bytes(b"\x00")
        return detect_chd(path)

    @pytest.mark.parametrize("logical_size_era", ["ps1", "ps2"])
    def test_current_cd_size_guess_becomes_chd_cd_candidates(self, tmp_path: Path, monkeypatch, logical_size_era):
        """The validator's CHTR/CHT2 logical-size era guess is dropped."""
        from formatscout.result import Method, Status

        _fake_chd(monkeypatch, _chd_scan(
            era=logical_size_era, confidence=0.3, warnings=["not authoritative: size heuristic"],
            method=Method.SIZE_HEURISTIC, container="chd", evidence=("chd_meta_chtr_cht2", "chd_logical_size"),
        ))
        result = self._call(tmp_path)
        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.method == Method.STRUCTURAL
        assert result.container == "chd_cd"
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]
        assert "chd_logical_size" not in result.evidence
        assert not any("size heuristic" in w for w in result.warnings)

    @pytest.mark.parametrize(
        "evidence, container, eras",
        [
            (("chd_meta_cht2",), "chd_cd", ["ps1", "ps2"]),
            (("chd_meta_chtr",), "chd_cd", ["ps1", "ps2"]),
            (("chd_meta_chcd",), "chd_cd", ["ps1", "ps2"]),
            (("chd_meta_dvd",), "chd_dvd", ["ps2", "xbox", "xbox360"]),
        ],
    )
    def test_tag_evidence_maps_to_container_and_candidates(
        self, tmp_path: Path, monkeypatch, evidence, container, eras,
    ):
        from formatscout.result import Method, Status

        _fake_chd(monkeypatch, _chd_scan(
            status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container="chd", evidence=evidence,
        ))
        result = self._call(tmp_path)
        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == container
        assert [c.era for c in result.candidates] == eras

    @pytest.mark.parametrize("evidence", [("chd_meta_chgd",), ("chd_meta_chgt",)])
    def test_gd_rom_tag_is_dreamcast_guess(self, tmp_path: Path, monkeypatch, evidence):
        from formatscout.result import Method, Status

        _fake_chd(monkeypatch, _chd_scan(
            status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container="chd", evidence=evidence,
        ))
        result = self._call(tmp_path)
        assert result.era == "dreamcast"
        assert result.status == Status.GUESS
        assert result.authoritative is False
        assert result.container == "chd_gd"

    def test_contract_shaped_result_is_passed_through(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Candidate, Method, Status, Tier

        already = _chd_scan(
            status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container="chd_dvd",
            candidates=(Candidate("ps2", Tier.WEAK), Candidate("xbox", Tier.WEAK), Candidate("xbox360", Tier.WEAK)),
        )
        _fake_chd(monkeypatch, already)
        assert self._call(tmp_path) is already

    def test_version_unsupported_never_carries_an_era(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Issue, IssueCode, Method

        _fake_chd(monkeypatch, _chd_scan(
            era="dreamcast", confidence=0.85, method=Method.STRUCTURAL, container="chd",
            evidence=("chd_meta_chgd",), issues=(Issue(IssueCode.CHD_VERSION_UNSUPPORTED, "v4"),),
        ))
        result = self._call(tmp_path)
        assert result.era is None
        assert [i.code for i in result.issues] == [IssueCode.CHD_VERSION_UNSUPPORTED]

    def test_era_less_version_unsupported_is_passed_through(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Issue, IssueCode, Method, Status

        already = _chd_scan(
            status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container="chd",
            issues=(Issue(IssueCode.CHD_VERSION_UNSUPPORTED, "v4"),),
        )
        _fake_chd(monkeypatch, already)
        assert self._call(tmp_path) is already

    def test_size_era_without_a_tag_is_dropped(self, tmp_path: Path, monkeypatch):
        from formatscout.result import Method

        _fake_chd(monkeypatch, _chd_scan(
            era="ps2", confidence=0.3, method=Method.SIZE_HEURISTIC, container="chd", evidence=("chd_logical_size",),
        ))
        result = self._call(tmp_path)
        assert result.era is None
        assert result.container == "chd"

    @pytest.mark.parametrize("logical_bytes", [0, 664_710_336, 4_400_000_000])
    def test_real_cht2_chd_end_to_end_has_no_size_era(self, tmp_path: Path, logical_bytes: int):
        """Through the real validator, whatever shape it returns: a CHT2 CHD
        is chd_cd with candidates ps1/ps2 at every declared logical size."""
        from formatscout.iso_detect import detect_chd
        from formatscout.tests.builders import chd

        path = tmp_path / "game.chd"
        path.write_bytes(chd.build_chd(version=5, metadata=(chd.track_entry(chd.TAG_CHT2),), logical_bytes=logical_bytes).data)
        result = detect_chd(path)
        assert result.era is None
        assert result.container == "chd_cd"
        assert [c.era for c in result.candidates] == ["ps1", "ps2"]

    def test_real_chgd_chd_end_to_end_is_chd_gd(self, tmp_path: Path):
        from formatscout.iso_detect import detect_chd
        from formatscout.tests.builders import chd

        path = tmp_path / "game.chd"
        path.write_bytes(chd.build_chd(version=5, metadata=(chd.track_entry(chd.TAG_CHGD, track_type="MODE1_RAW"),)).data)
        result = detect_chd(path)
        assert result.era == "dreamcast"
        assert result.authoritative is False
        assert result.container == "chd_gd"


class TestDetectChd:
    def test_delegates_to_chd_validator_detect_chd_platform(self, tmp_path: Path, monkeypatch):
        from formatscout import iso_detect
        from formatscout.result import ScanResult
        from formatscout.validators import chd_validator

        sentinel = ScanResult(title=None, platform=None, era="dreamcast", confidence=1.0, reason="sentinel")
        captured = {}

        def _fake_detect(path):
            captured["path"] = path
            return sentinel

        monkeypatch.setattr(chd_validator, "detect_chd_platform", _fake_detect)
        chd_path = tmp_path / "game.chd"
        chd_path.write_bytes(b"\x00")

        result = iso_detect.detect_chd(chd_path)
        assert result is sentinel
        assert captured["path"] == chd_path
