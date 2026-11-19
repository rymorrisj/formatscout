"""Tests for formatscout.validators.chd_validator."""

import struct
from pathlib import Path

import pytest

from formatscout.result import IssueCode, Method, Status
from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.builders import chd


def _extract_embedded_sha1(path: Path):
    from formatscout.validators.chd_validator import extract_embedded_sha1
    return extract_embedded_sha1(path)


def _detect(path: Path):
    from formatscout.validators.chd_validator import detect_chd_platform
    return detect_chd_platform(path)


def _write_image(tmp_path: Path, image: chd.ChdImage, *, version_field: int | None = None) -> Path:
    """Write a built CHD, optionally overwriting the header's version field."""
    data = bytearray(image.data)
    if version_field is not None:
        struct.pack_into(">I", data, 12, version_field)
    path = tmp_path / "game.chd"
    path.write_bytes(bytes(data))
    return path


def _eras(result) -> list[str]:
    return [candidate.era for candidate in result.candidates]


# ---------------------------------------------------------------------------
# extract_embedded_sha1()
# ---------------------------------------------------------------------------

class TestExtractEmbeddedSha1:
    def test_real_rawsha1_returned_as_hex(self, tmp_path: Path):
        raw = bytes.fromhex(fx.CHD_EMBEDDED_SHA1)
        buf = fx.build_chd_header(rawsha1=raw)
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        assert _extract_embedded_sha1(path) == fx.CHD_EMBEDDED_SHA1

    def test_built_v5_image_returns_rawsha1(self, tmp_path: Path):
        raw = bytes.fromhex(fx.CHD_EMBEDDED_SHA1)
        path = _write_image(tmp_path, chd.build_chd(version=5, rawsha1=raw))

        assert _extract_embedded_sha1(path) == fx.CHD_EMBEDDED_SHA1

    def test_v4_header_returns_none_even_with_bytes_at_the_v5_offset(self, tmp_path: Path):
        """A v4 header keeps rawsha1 at a different offset, so nothing is read."""
        raw = bytes.fromhex(fx.CHD_EMBEDDED_SHA1)
        image = chd.build_chd(version=4, rawsha1=raw)
        data = bytearray(image.data)
        data[64:84] = raw  # plant a plausible value where a v5 parser would look
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(data))

        assert _extract_embedded_sha1(path) is None

    @pytest.mark.parametrize("version", [0, 1, 3, 4, 6, 0xFFFFFFFF])
    def test_non_v5_version_field_returns_none(self, tmp_path: Path, version: int):
        raw = bytes.fromhex(fx.CHD_EMBEDDED_SHA1)
        path = _write_image(tmp_path, chd.build_chd(version=5, rawsha1=raw), version_field=version)

        assert _extract_embedded_sha1(path) is None

    def test_v5_with_wrong_header_length_returns_none(self, tmp_path: Path):
        buf = fx.build_chd_header(rawsha1=bytes.fromhex(fx.CHD_EMBEDDED_SHA1))
        struct.pack_into(">I", buf, 8, 100)
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        assert _extract_embedded_sha1(path) is None

    def test_all_zero_rawsha1_treated_as_unset_not_a_real_hash(self, tmp_path: Path):
        """rawsha1 field present but all-zero (some chdman versions omit it
        for non-CD types) must return None, distinct from a real 40-hex value.
        """
        buf = fx.build_chd_header(rawsha1=None)  # leaves the field all-zero
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        assert _extract_embedded_sha1(path) is None

    def test_wrong_magic_returns_none(self, tmp_path: Path):
        buf = fx.build_chd_header(rawsha1=bytes.fromhex(fx.CHD_EMBEDDED_SHA1))
        buf[0:8] = b"NOTACHD!"
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        assert _extract_embedded_sha1(path) is None

    def test_truncated_header_before_rawsha1_field_returns_none(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MComprHD" + struct.pack(">II", 124, 5) + b"\x00" * 10)  # nowhere near offset 64+20

        assert _extract_embedded_sha1(path) is None

    def test_header_shorter_than_version_field_returns_none(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MComprHD" + b"\x00" * 3)

        assert _extract_embedded_sha1(path) is None


# ---------------------------------------------------------------------------
# detect_chd_platform(), magic and header checks
# ---------------------------------------------------------------------------

class TestDetectMagicCheck:
    def test_wrong_magic_returns_zero_confidence(self, tmp_path: Path):
        buf = fx.build_chd_header()
        buf[0:8] = b"NOTACHD!"
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.era is None
        assert result.status == Status.NO_SIGNAL
        assert "magic" in result.reason.lower()

    def test_file_shorter_than_magic_is_no_signal(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MCompr")

        assert _detect(path).status == Status.NO_SIGNAL

    def test_truncated_header_before_version_field(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MComprHD")  # magic only, no length or version

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.status == Status.CONTAINER_ONLY
        assert "truncated" in result.reason.lower()
        assert [issue.code for issue in result.issues] == ["CHD_HEADER_TRUNCATED"]

    def test_truncated_v5_header_before_meta_offset_field(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MComprHD" + struct.pack(">II", 124, 5) + b"\x00" * 20)  # ends before offset 48

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert "truncated" in result.reason.lower()
        assert [issue.code for issue in result.issues] == ["CHD_HEADER_TRUNCATED"]

    def test_v5_with_wrong_header_length_is_invalid(self, tmp_path: Path):
        image = chd.build_chd(version=5, metadata=(chd.track_entry(chd.TAG_CHGD),))
        data = bytearray(image.data)
        struct.pack_into(">I", data, 8, 108)
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(data))

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert [issue.code for issue in result.issues] == ["CHD_HEADER_INVALID"]


# ---------------------------------------------------------------------------
# detect_chd_platform(), header version
# ---------------------------------------------------------------------------

class TestDetectVersion:
    @pytest.mark.parametrize("tag", [chd.TAG_CHGD, chd.TAG_CHT2])
    def test_v4_image_is_unsupported_and_its_chain_is_not_read(self, tmp_path: Path, tag: bytes):
        path = _write_image(tmp_path, chd.build_chd(version=4, metadata=(chd.track_entry(tag),)))

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == "chd"
        assert result.candidates == ()
        assert [issue.code for issue in result.issues] == [IssueCode.CHD_VERSION_UNSUPPORTED]

    def test_v4_dvd_tag_is_unsupported_too(self, tmp_path: Path):
        path = _write_image(tmp_path, chd.build_chd(version=4, metadata=(chd.dvd_entry(),)))

        result = _detect(path)

        assert result.container == "chd"
        assert result.candidates == ()
        assert result.issues[0].code == IssueCode.CHD_VERSION_UNSUPPORTED

    @pytest.mark.parametrize("version", [0, 1, 3, 6, 0xFFFFFFFF])
    def test_any_other_version_is_unsupported(self, tmp_path: Path, version: int):
        image = chd.build_chd(version=5, metadata=(chd.track_entry(chd.TAG_CHGD),))
        path = _write_image(tmp_path, image, version_field=version)

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.method == Method.STRUCTURAL
        assert result.authoritative is False
        assert [issue.code for issue in result.issues] == [IssueCode.CHD_VERSION_UNSUPPORTED]


# ---------------------------------------------------------------------------
# detect_chd_platform(), metadata tag dispatch
# ---------------------------------------------------------------------------

class TestDetectMetadataTagDispatch:
    def _build_with_single_entry(self, tag: bytes, *, logical_bytes: int = 0, next_offset: int = 0) -> bytes:
        meta_offset = fx.CHD_HEADER_SIZE
        buf = fx.build_chd_header(
            logical_bytes=logical_bytes, meta_offset=meta_offset,
            size=meta_offset + fx.CHD_META_ENTRY_LEN,
        )
        fx.place_chd_metadata_entry(buf, meta_offset, tag, next_offset)
        return bytes(buf)

    @pytest.mark.parametrize("tag", [b"CHGD", b"CHGT"])
    def test_gd_tags_resolve_dreamcast_as_a_non_authoritative_guess(self, tmp_path: Path, tag: bytes):
        path = tmp_path / "game.chd"
        path.write_bytes(self._build_with_single_entry(tag))

        result = _detect(path)

        assert result.era == "dreamcast"
        assert result.confidence == 0.85
        assert result.status == Status.GUESS
        assert result.method == Method.STRUCTURAL
        assert result.authoritative is False
        assert result.container == "chd_gd"
        assert "chd_meta_" + tag.decode().lower() in result.evidence

    @pytest.mark.parametrize("tag", [chd.TAG_CHT2, chd.TAG_CHTR, chd.TAG_CHCD])
    @pytest.mark.parametrize("logical_bytes", [0, 700 * 1024 * 1024, 4 * 1024 * 1024 * 1024])
    def test_cd_tags_give_candidates_never_an_era_whatever_the_logical_size(
        self, tmp_path: Path, tag: bytes, logical_bytes: int,
    ):
        """The old size guess (ps1 under 800 MiB or zero, ps2 above) is gone."""
        entry = chd.MetaEntry(tag, b"") if tag == chd.TAG_CHCD else chd.track_entry(tag)
        path = _write_image(tmp_path, chd.build_chd(metadata=(entry,), logical_bytes=logical_bytes))

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.status == Status.CONTAINER_ONLY
        assert result.method == Method.STRUCTURAL
        assert result.authoritative is False
        assert result.container == "chd_cd"
        assert _eras(result) == ["ps1", "ps2"]
        assert result.issues == ()

    def test_dvd_tag_gives_ps2_xbox_xbox360_candidates(self, tmp_path: Path):
        path = _write_image(tmp_path, chd.build_chd(metadata=(chd.dvd_entry(),), logical_bytes=4 * 1024**3))

        result = _detect(path)

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.method == Method.STRUCTURAL
        assert result.container == "chd_dvd"
        assert _eras(result) == ["ps2", "xbox", "xbox360"]
        assert "chd_meta_dvd" in result.evidence

    def test_unrecognised_tag_terminates_cleanly_with_zero_confidence(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(self._build_with_single_entry(b"XXXX"))

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == "chd"
        assert result.candidates == ()
        assert "no CHT2/CHTR/CHCD/CHGD/CHGT/DVD tag" in result.warnings[0]

    def test_v5_without_metadata_is_container_only(self, tmp_path: Path):
        result = _detect(_write_image(tmp_path, chd.build_chd()))

        assert result.era is None
        assert result.status == Status.CONTAINER_ONLY
        assert result.container == "chd"
        assert result.issues == ()

    def test_unrecognised_entry_is_skipped_to_reach_a_later_tag(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.MetaEntry(b"ABCD", b"x\x00"), chd.track_entry(chd.TAG_CHGD)))

        result = _detect(_write_image(tmp_path, image))

        assert result.era == "dreamcast"
        assert result.container == "chd_gd"

    def test_first_recognised_tag_wins(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.track_entry(chd.TAG_CHT2), chd.track_entry(chd.TAG_CHGD)))

        result = _detect(_write_image(tmp_path, image))

        assert result.era is None
        assert result.container == "chd_cd"


# ---------------------------------------------------------------------------
# detect_chd_platform(), CHT2 text payload
# ---------------------------------------------------------------------------

class TestDetectCht2Payload:
    def _detect_payload(self, tmp_path: Path, payload: bytes):
        image = chd.build_chd(metadata=(chd.MetaEntry(chd.TAG_CHT2, payload),))
        return _detect(_write_image(tmp_path, image))

    def test_track_type_and_subtype_become_evidence_only(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.track_entry(chd.TAG_CHT2, track_type="MODE2_RAW"),))

        result = _detect(_write_image(tmp_path, image))

        assert "chd_cht2_type_mode2_raw" in result.evidence
        assert "chd_cht2_subtype_none" in result.evidence
        assert result.era is None
        assert _eras(result) == ["ps1", "ps2"]

    def test_mode1_raw_type(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.track_entry(chd.TAG_CHT2, track_type="MODE1_RAW"),))

        assert "chd_cht2_type_mode1_raw" in _detect(_write_image(tmp_path, image)).evidence

    def test_unknown_values_are_reported_as_other_never_echoed(self, tmp_path: Path):
        result = self._detect_payload(tmp_path, b"TRACK:1 TYPE:EVIL\\n<x> SUBTYPE:%s%s FRAMES:1\x00")

        assert "chd_cht2_type_other" in result.evidence
        assert "chd_cht2_subtype_other" in result.evidence
        assert not any("evil" in code.lower() for code in result.evidence)

    def test_first_occurrence_of_a_key_wins(self, tmp_path: Path):
        result = self._detect_payload(tmp_path, b"TYPE:AUDIO TYPE:MODE1 SUBTYPE:NONE\x00")

        assert "chd_cht2_type_audio" in result.evidence
        assert "chd_cht2_type_mode1" not in result.evidence

    @pytest.mark.parametrize("payload", [b"", b"\x00", b"garbage with no keys\x00", b"\xff\xfe\x00TYPE", b"TRACK:1 FRAMES:5\x00"])
    def test_payload_without_a_type_is_unparsed_not_an_error(self, tmp_path: Path, payload: bytes):
        result = self._detect_payload(tmp_path, payload)

        assert "chd_cht2_unparsed" in result.evidence
        assert result.container == "chd_cd"

    def test_payload_is_capped_at_4_kb(self, tmp_path: Path):
        """A TYPE token that starts after the 4096-byte cap is never read."""
        result = self._detect_payload(tmp_path, b"A" * 4100 + b" TYPE:AUDIO\x00")

        assert "chd_cht2_unparsed" in result.evidence
        assert "chd_cht2_type_audio" not in result.evidence

    def test_type_inside_the_cap_is_still_read_when_the_payload_is_huge(self, tmp_path: Path):
        result = self._detect_payload(tmp_path, b"TYPE:AUDIO " + b"A" * 100_000)

        assert "chd_cht2_type_audio" in result.evidence

    def test_length_field_larger_than_the_file_does_not_crash(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.track_entry(chd.TAG_CHT2),))
        data = bytearray(image.data)
        struct.pack_into(">I", data, image.meta_offsets[0] + 4, 0x01FFFFFF)  # flags 1, length 16 MiB - 1
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(data))

        result = _detect(path)

        assert result.container == "chd_cd"
        assert "chd_cht2_type_mode2_raw" in result.evidence

    def test_entry_header_cut_short_after_the_tag_is_not_a_crash(self, tmp_path: Path):
        image = chd.build_chd(metadata=(chd.track_entry(chd.TAG_CHT2),))
        path = tmp_path / "game.chd"
        path.write_bytes(image.data[: image.meta_offsets[0] + 8])

        result = _detect(path)

        assert result.era is None
        assert result.container == "chd"


# ---------------------------------------------------------------------------
# detect_chd_platform(), metadata chain cycle/bounds protection
# ---------------------------------------------------------------------------

class TestDetectMetadataChainProtection:
    def test_self_referencing_cycle_halts_instead_of_looping(self, tmp_path: Path):
        """Entry's own next_offset points back at itself. visited_offsets must
        catch this on the second visit and break out, rather than spinning
        forever. If it looped, this test would hang rather than fail cleanly.
        """
        meta_offset = fx.CHD_HEADER_SIZE
        buf = fx.build_chd_header(meta_offset=meta_offset, size=meta_offset + fx.CHD_META_ENTRY_LEN)
        fx.place_chd_metadata_entry(buf, meta_offset, b"XXXX", meta_offset)  # next == self
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.era is None
        assert "no recognised platform metadata tag" in result.reason

    def test_two_entry_cycle_halts_instead_of_looping(self, tmp_path: Path):
        """A -> B -> A chain: neither entry alone repeats an offset on its
        first pass, so this exercises the visited-offsets set across more
        than one hop, not just the trivial self-loop case above.
        """
        entry_len = fx.CHD_META_ENTRY_LEN
        offset_a = fx.CHD_HEADER_SIZE
        offset_b = offset_a + entry_len
        buf = fx.build_chd_header(meta_offset=offset_a, size=offset_b + entry_len)
        fx.place_chd_metadata_entry(buf, offset_a, b"XXXX", offset_b)
        fx.place_chd_metadata_entry(buf, offset_b, b"YYYY", offset_a)
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.era is None

    def test_next_offset_beyond_end_of_file_halts_instead_of_crashing(self, tmp_path: Path):
        meta_offset = fx.CHD_HEADER_SIZE
        buf = fx.build_chd_header(meta_offset=meta_offset, size=meta_offset + fx.CHD_META_ENTRY_LEN)
        far_out_of_bounds = len(buf) + 10_000
        fx.place_chd_metadata_entry(buf, meta_offset, b"XXXX", far_out_of_bounds)
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.era is None

    def test_meta_offset_itself_beyond_end_of_file_halts_instead_of_crashing(self, tmp_path: Path):
        buf = fx.build_chd_header(meta_offset=10_000_000)  # far beyond this tiny file's length
        path = tmp_path / "game.chd"
        path.write_bytes(bytes(buf))

        result = _detect(path)

        assert result.confidence == 0.0
        assert result.era is None

    def test_missing_file_is_an_error_result_not_an_exception(self, tmp_path: Path):
        result = _detect(tmp_path / "missing.chd")

        assert result.status == Status.ERROR
        assert result.method == Method.NONE
