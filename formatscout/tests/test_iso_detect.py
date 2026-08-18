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
        assert result == bin_file

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
        assert result == real_bin, (
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

    def test_ps1_volume_prefix_small_size(self, tmp_path: Path):
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLUS_123.45")
        result = self._call(iso_path)
        assert result.era == "ps1"
        assert result.confidence == 0.75

    def test_ps2_volume_prefix_dvd_size(self, tmp_path: Path):
        """Same SLES/SLUS/etc. prefix, but a file over 4.7 GB resolves to PS2
        instead of PS1, a sparse-truncated file is used so the test doesn't
        actually write gigabytes to disk.
        """
        iso_path = fx.write_pvd_iso(tmp_path / "game.iso", volume_id="SLES_123.45")
        with iso_path.open("r+b") as fh:
            fh.truncate(4_800_000_000)
        result = self._call(iso_path)
        assert result.era == "ps2"
        assert "DVD size" in result.reason

    def test_sony_publisher_with_cdrom_system_id_is_ps1_regardless_of_size(self, tmp_path: Path):
        """sys_id == 'CD-ROM' + 'SONY' in publisher resolves to ps1 even
        without a recognised SLUS/SCES/etc. volume-label prefix, and even at
        a large size, only a vol_starts_ps volume label triggers the PS2
        DVD-size branch.
        """
        iso_path = fx.write_pvd_iso(
            tmp_path / "game.iso", system_id="CD-ROM",
            publisher="SONY COMPUTER ENTERTAINMENT", volume_id="RANDOMTITLE",
        )
        with iso_path.open("r+b") as fh:
            fh.truncate(4_800_000_000)
        result = self._call(iso_path)
        assert result.era == "ps1"

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
# detect_iso, dispatch order: detect_from_magic -> detect_from_pvd ->
# xbox_image.detect_xbox_image_type -> size fallback.
#
# detect_xbox_image_type(path) takes a single path argument and returns one
# of exactly four strings: "xiso", "dvd_rip", "iso9660", "unknown". detect_iso()
# branches on only the first two ("xiso" -> era=xbox 0.9; "dvd_rip" -> era=xbox
# 0.9 plus requires_extraction=True). "iso9660" and "unknown" are both
# unhandled by detect_iso() and fall through to _iso_size_fallback(), so the
# size-fallback tests below are parametrized over both rather than assuming
# only one of them reaches that tier.
#
# NOTE: magic_signatures.toml has zero signatures with "iso" in applies_to
# today, so detect_from_magic(path, "iso") can never return a non-None era
# for a real .iso file. That branch is exercised here via monkeypatch
# (dependency injection on the wiring), not a real magic-byte fixture.
# ---------------------------------------------------------------------------

# The two detect_xbox_image_type() return values detect_iso() does not
# special-case, both of which must reach _iso_size_fallback().
NON_XBOX_IMAGE_TYPES = ("iso9660", "unknown")


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

    def test_falls_through_to_xbox_image_type_when_no_pvd_signal(self, tmp_path: Path, monkeypatch):
        """detect_xbox_image_type() == "xiso": a ready-to-use Original Xbox
        disc image. requires_extraction must stay False, only the dvd_rip
        branch below sets it.
        """
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: "xiso")
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(b"\x00" * 100)  # no valid PVD

        result = iso_detect.detect_iso(iso_path)
        assert result.era == "xbox"
        assert result.confidence == 0.9
        assert "XDVDFS" in result.reason
        assert result.requires_extraction is False

    def test_dvd_rip_sets_requires_extraction(self, tmp_path: Path, monkeypatch):
        """detect_xbox_image_type() == "dvd_rip": ISO 9660 magic present but
        the file is past the xISO size threshold, a raw Xbox DVD rip. Same
        era/confidence as the xiso branch, distinguished only by
        requires_extraction=True, the signal that extract-xiso must run
        before the image is usable.
        """
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: "dvd_rip")
        iso_path = tmp_path / "game.iso"
        iso_path.write_bytes(b"\x00" * 100)  # no valid PVD

        result = iso_detect.detect_iso(iso_path)
        assert result.era == "xbox"
        assert result.confidence == 0.9
        assert result.requires_extraction is True
        assert "raw Xbox DVD rip" in result.reason

    def test_real_dvd_rip_image_resolves_end_to_end(self, tmp_path: Path):
        """The same dvd_rip outcome with nothing mocked at all, the only test
        that exercises the real iso_detect -> xbox_image wiring rather than a
        monkeypatched stand-in for it.

        Layout: "CD001" at 0x8001 (the ISO 9660 standard identifier, which
        also leaves byte 0x8000 zero so detect_from_pvd() sees no valid PVD
        type code and falls through), nothing at 0x10000 so the XDVDFS magic
        check misses, and a sparse-truncated size past xbox_image's
        4,294,967,296-byte (binary 4 GiB) dvd_rip threshold.
        """
        from formatscout import iso_detect

        iso_path = tmp_path / "game.iso"
        with iso_path.open("wb") as fh:
            fh.seek(0x8001)
            fh.write(b"CD001")
            fh.truncate(4_400_000_000)

        result = iso_detect.detect_iso(iso_path)
        assert result.era == "xbox"
        assert result.confidence == 0.9
        assert result.requires_extraction is True

    @pytest.mark.parametrize("image_type", NON_XBOX_IMAGE_TYPES)
    def test_falls_through_to_size_fallback_over_4gb(self, tmp_path: Path, monkeypatch, image_type: str):
        from formatscout import iso_detect

        monkeypatch.setattr(iso_detect, "detect_from_magic", lambda path, extension: (None, ""))
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: image_type)
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
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: image_type)
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
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: "unknown")
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
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: "iso9660")
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
        monkeypatch.setattr(iso_detect, "detect_xbox_image_type", lambda path: image_type)
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
# detect_chd, thin delegation to validators.chd_validator.detect_chd_platform().
# Full CHD parsing logic already covered by test_chd_validator.py; this only
# confirms the wiring.
# ---------------------------------------------------------------------------

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
