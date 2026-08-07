"""Tests for backend.service.utils.smart_media_detector.exe_detect.

Covers the Bug 3 fix from the prior session: a Subsystem gate must be applied
before the era branches run, and every DOS-fallback branch must report the
same 0.65 confidence regardless of which condition (too-short header vs. no
PE signature) produced it.
"""

from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


def _detect_exe(path: Path):
    from backend.service.utils.smart_media_detector.exe_detect import detect_exe
    return detect_exe(path)


class TestNotAnExecutable:
    def test_no_mz_magic_returns_zero_confidence(self, tmp_path: Path):
        path = tmp_path / "not_an_exe.bin"
        path.write_bytes(fx.build_pe_header(mz=False))

        result = _detect_exe(path)

        assert result.confidence == 0.0
        assert result.era is None


class TestDosFallbackUniformConfidence:
    def test_mz_header_too_short_for_pe_offset(self, tmp_path: Path):
        """len(header) < 0x40, meaning the file is smaller than where e_lfanew would be."""
        path = tmp_path / "tiny.exe"
        path.write_bytes(fx.build_pe_header(total_len=0x20, pe_offset=None))

        result = _detect_exe(path)

        assert result.era == "dos"
        assert result.confidence == 0.65
        assert "too short for a PE offset" in result.reason

    def test_mz_header_with_no_pe_signature_at_offset(self, tmp_path: Path):
        """pe_offset points within the file (room for the fields), but the
        4 bytes there are not the "PE\\0\\0" signature, meaning a real DOS .exe.
        """
        path = tmp_path / "real_dos.exe"
        path.write_bytes(fx.build_pe_header(pe_offset=0x40, pe_signature=b"\x00\x00\x00\x00"))

        result = _detect_exe(path)

        assert result.era == "dos"
        assert result.confidence == 0.65
        assert "no PE signature" in result.reason

    def test_both_dos_fallback_branches_report_identical_confidence(self, tmp_path: Path):
        too_short = tmp_path / "too_short.exe"
        too_short.write_bytes(fx.build_pe_header(total_len=0x20, pe_offset=None))
        no_pe_sig = tmp_path / "no_pe_sig.exe"
        no_pe_sig.write_bytes(fx.build_pe_header(pe_offset=0x40, pe_signature=b"\x00\x00\x00\x00"))

        assert _detect_exe(too_short).confidence == _detect_exe(no_pe_sig).confidence == 0.65


class TestGarbagePeOffset:
    def test_pe_offset_leaves_no_room_for_header_fields_returns_zero_confidence(self, tmp_path: Path):
        """pe_offset + 96 > len(header), a distinct branch from both the
        too-short-MZ-header and no-PE-signature cases: the MZ header itself
        is a normal length, but e_lfanew points somewhere with no room left
        for the fields this function needs to read.
        """
        path = tmp_path / "garbage_offset.exe"
        path.write_bytes(fx.build_pe_header(total_len=256, pe_offset=5000))

        result = _detect_exe(path)

        assert result.confidence == 0.0
        assert result.era is None
        assert result.reason == ""


class TestSubsystemGate:
    def test_subsystem_not_in_gui_or_cui_returns_zero_confidence(self, tmp_path: Path):
        """Subsystem gate (Bug 3 fix): a PE with a valid signature and a
        plausible OS version but a Subsystem outside (2, 3), i.e. not GUI or
        CUI, must be rejected outright, not fall through to an era guess.
        """
        path = tmp_path / "native_driver.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=1))  # 1 = IMAGE_SUBSYSTEM_NATIVE

        result = _detect_exe(path)

        assert result.confidence == 0.0
        assert result.era is None

    def test_subsystem_gui_2_is_accepted(self, tmp_path: Path):
        path = tmp_path / "gui.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=2))

        result = _detect_exe(path)

        assert result.era == "winxp"

    def test_subsystem_cui_3_is_accepted(self, tmp_path: Path):
        path = tmp_path / "cui.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))

        result = _detect_exe(path)

        assert result.era == "winxp"


class TestEraByMajorOsVersion:
    def test_major_os_version_5_or_above_is_winxp(self, tmp_path: Path):
        path = tmp_path / "xp.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=2))

        result = _detect_exe(path)

        assert result.era == "winxp"
        assert result.confidence == 0.75

    def test_major_os_version_6_is_also_winxp(self, tmp_path: Path):
        path = tmp_path / "vista_plus.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=6, subsystem=2))

        result = _detect_exe(path)

        assert result.era == "winxp"

    def test_major_os_version_4_is_win98(self, tmp_path: Path):
        path = tmp_path / "win98.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=4, subsystem=2))

        result = _detect_exe(path)

        assert result.era == "win98"
        assert result.confidence == 0.75

    def test_major_os_version_below_4_returns_zero_confidence(self, tmp_path: Path):
        """major_os < 4 with a valid Subsystem falls past both era branches
        with no further fallback, and must not default to any era.
        """
        path = tmp_path / "ancient.exe"
        path.write_bytes(fx.build_pe_header(major_os_version=3, subsystem=2))

        result = _detect_exe(path)

        assert result.confidence == 0.0
        assert result.era is None


class TestReadError:
    def test_missing_file_returns_zero_confidence_with_error_reason(self, tmp_path: Path):
        result = _detect_exe(tmp_path / "does_not_exist.exe")

        assert result.confidence == 0.0
        assert "detection error" in result.reason
