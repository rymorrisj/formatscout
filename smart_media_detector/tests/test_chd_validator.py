"""Tests for backend.service.utils.smart_media_detector.validators.chd_validator."""

from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


def _extract_embedded_sha1(path: Path):
    from backend.service.utils.smart_media_detector.validators.chd_validator import extract_embedded_sha1
    return extract_embedded_sha1(path)


def _detect(path: Path):
    from backend.service.utils.smart_media_detector.validators.chd_validator import detect
    return detect(path)


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
        path.write_bytes(b"MComprHD" + b"\x00" * 10)  # magic present, nowhere near offset 64+20

        assert _extract_embedded_sha1(path) is None


# ---------------------------------------------------------------------------
# detect(), magic check
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
        assert "magic" in result.reason.lower()

    def test_truncated_header_before_meta_offset_field(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(b"MComprHD")  # magic only, nothing at offset 48

        result = _detect(path)

        assert result.confidence == 0.0
        assert "truncated" in result.reason.lower()


# ---------------------------------------------------------------------------
# detect(), metadata tag dispatch
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

    def test_chgd_tag_resolves_dreamcast(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(self._build_with_single_entry(b"CHGD"))

        result = _detect(path)

        assert result.era == "dreamcast"
        assert result.confidence == 0.85

    def test_chtr_tag_with_cd_sized_logical_bytes_resolves_ps1(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        cd_size = 700 * 1024 * 1024  # under the 800MB threshold
        path.write_bytes(self._build_with_single_entry(b"CHTR", logical_bytes=cd_size))

        result = _detect(path)

        assert result.era == "ps1"
        assert result.confidence == 0.3
        assert "not authoritative" in result.warnings[0]

    def test_cht2_tag_with_dvd_sized_logical_bytes_resolves_ps2(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        dvd_size = 4 * 1024 * 1024 * 1024  # well over the 800MB CD threshold
        path.write_bytes(self._build_with_single_entry(b"CHT2", logical_bytes=dvd_size))

        result = _detect(path)

        assert result.era == "ps2"
        assert result.confidence == 0.3

    def test_unrecognised_tag_terminates_cleanly_with_zero_confidence(self, tmp_path: Path):
        path = tmp_path / "game.chd"
        path.write_bytes(self._build_with_single_entry(b"XXXX"))

        result = _detect(path)

        assert result.era is None
        assert result.confidence == 0.0
        assert "no CHGD/CHTR/CHT2 tag" in result.warnings[0]


# ---------------------------------------------------------------------------
# detect(), metadata chain cycle/bounds protection
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
