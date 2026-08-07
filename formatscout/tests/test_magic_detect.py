"""Tests for backend.service.utils.smart_media_detector.magic.magic_detect."""

import shutil
import subprocess
import sys
from pathlib import Path

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


# ---------------------------------------------------------------------------
# detect_from_magic(), continue-vs-return for cdrom_sync_ambiguous
# ---------------------------------------------------------------------------

class TestDetectFromMagicContinueVsReturn:
    def test_unresolved_ambiguous_sync_falls_through_to_dreamcast(self, tmp_path: Path):
        """File matches the cdrom_sync_ambiguous signature at offset 0 AND
        the Dreamcast IP.BIN magic at offset 0x10. The file is far too short
        for _resolve_ps_generation() to find a PVD, so it deterministically
        resolves "unknown" for the ambiguous signature. detect_from_magic()
        must `continue` past that unresolved match rather than returning
        (None, ""), so the still-untested Dreamcast signature further down
        the same applies_to=["bin"] list gets checked and matches.

        If the ambiguous branch incorrectly `return`ed on "unknown" instead
        of `continue`ing, this test would see (None, "") instead.
        """
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        blob = bytearray(64)
        sync = fx.CDROM_SYNC_AMBIGUOUS_BLOB
        dreamcast = fx.DREAMCAST_IP_BIN_BLOB
        blob[0:len(sync)] = sync[0:len(sync)]
        blob[0x10:0x10 + 15] = dreamcast[0x10:0x10 + 15]

        path = tmp_path / "ambiguous_then_dreamcast.bin"
        path.write_bytes(bytes(blob))

        era, reason = detect_from_magic(path, "bin")

        assert era == "dreamcast"
        assert reason != ""

    def test_pure_ambiguous_sync_with_no_further_match_returns_none(self, tmp_path: Path):
        """Same short-file "unknown" resolution, but with no other signature
        present afterward, confirms the fall-through correctly exhausts the
        list and returns (None, ""), not a false positive.
        """
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "ambiguous_only.bin"
        path.write_bytes(fx.CDROM_SYNC_AMBIGUOUS_BLOB)

        era, reason = detect_from_magic(path, "bin")

        assert era is None
        assert reason == ""


class TestDetectFromMagicPerSignature:
    def test_n64_big_endian(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "game.bin"
        path.write_bytes(fx.N64_BIG_ENDIAN_BLOB)
        era, _ = detect_from_magic(path, "bin")
        assert era == "n64"

    def test_n64_byteswapped(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "game.bin"
        path.write_bytes(fx.N64_BYTESWAPPED_BLOB)
        era, _ = detect_from_magic(path, "bin")
        assert era == "n64"

    def test_n64_little_endian(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "game.bin"
        path.write_bytes(fx.N64_LITTLE_ENDIAN_BLOB)
        era, _ = detect_from_magic(path, "bin")
        assert era == "n64"

    def test_nes(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "game.bin"
        path.write_bytes(fx.NES_HEADER_BLOB)
        era, _ = detect_from_magic(path, "bin")
        assert era == "nes"

    def test_dreamcast(self, tmp_path: Path):
        from backend.service.utils.smart_media_detector.magic.magic_detect import detect_from_magic

        path = tmp_path / "game.bin"
        path.write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        era, _ = detect_from_magic(path, "bin")
        assert era == "dreamcast"


# ---------------------------------------------------------------------------
# resolve_ps_generation_from_file(), SYSTEM.CNF already extracted to disk
# ---------------------------------------------------------------------------

class TestResolvePsGenerationFromFile:
    def _call(self, cnf_path: Path) -> str:
        from backend.service.utils.smart_media_detector.magic.magic_detect import resolve_ps_generation_from_file
        return resolve_ps_generation_from_file(cnf_path)

    def test_boot_key_resolves_ps1(self, tmp_path: Path):
        cnf = tmp_path / "SYSTEM.CNF"
        cnf.write_bytes(b"BOOT = cdrom:\\SLUS_000.01;1\r\nTCB = 4\r\n")
        assert self._call(cnf) == "ps1"

    def test_boot2_key_resolves_ps2(self, tmp_path: Path):
        cnf = tmp_path / "SYSTEM.CNF"
        cnf.write_bytes(b"BOOT2 = cdrom0:\\SLUS_200.01;1\r\nVER = 1.00\r\n")
        assert self._call(cnf) == "ps2"

    def test_unreadable_file_resolves_unknown_not_ps1_default(self, tmp_path: Path):
        ghost = tmp_path / "does_not_exist.cnf"
        assert self._call(ghost) == "unknown"


# ---------------------------------------------------------------------------
# _resolve_ps_generation(), raw CD sector read (Part 1.2 builder)
# ---------------------------------------------------------------------------

class TestResolvePsGenerationFromSector:
    def _call(self, path: Path) -> str:
        from backend.service.utils.smart_media_detector.magic.magic_detect import _resolve_ps_generation
        return _resolve_ps_generation(path)

    def test_pvd_present_system_cnf_present_boot_resolves_ps1(self, tmp_path: Path):
        data = fx.build_ps_disc_bin(boot_line="BOOT = cdrom:\\SLUS_000.01;1\r\n")
        path = tmp_path / "disc.bin"
        path.write_bytes(data)
        assert self._call(path) == "ps1"

    def test_pvd_present_system_cnf_present_boot2_resolves_ps2(self, tmp_path: Path):
        data = fx.build_ps_disc_bin(boot_line="BOOT2 = cdrom0:\\SLUS_200.01;1\r\n")
        path = tmp_path / "disc.bin"
        path.write_bytes(data)
        assert self._call(path) == "ps2"

    def test_pvd_present_no_system_cnf_resolves_unknown(self, tmp_path: Path):
        """PVD is valid and the root directory is readable, but it contains
        no SYSTEM.CNF entry at all. Must resolve "unknown", never a ps1
        default, this is the already-fixed behavior the docstring calls out.
        """
        data = fx.build_ps_disc_bin(boot_line=None, include_system_cnf=False)
        path = tmp_path / "disc.bin"
        path.write_bytes(data)
        assert self._call(path) == "unknown"

    def test_no_pvd_at_all_resolves_unknown(self, tmp_path: Path):
        data = fx.build_ps_disc_bin(boot_line=None, include_pvd=False)
        path = tmp_path / "disc.bin"
        path.write_bytes(data)
        assert self._call(path) == "unknown"


# ---------------------------------------------------------------------------
# _classify_system_cnf(), BOOT= vs BOOT2= distinction
# ---------------------------------------------------------------------------

class TestClassifySystemCnf:
    def _call(self, content: str) -> str:
        from backend.service.utils.smart_media_detector.magic.magic_detect import _classify_system_cnf
        return _classify_system_cnf(content)

    def test_boot_only_is_ps1(self):
        assert self._call("BOOT = cdrom:\\SLUS_000.01;1\r\nTCB = 4\r\n") == "ps1"

    def test_boot2_is_ps2(self):
        assert self._call("BOOT2 = cdrom0:\\SLUS_200.01;1\r\nVER = 1.00\r\n") == "ps2"

    def test_boot2_takes_priority_when_both_substrings_present(self):
        """BOOT2 contains "BOOT" as a literal substring, so content with a
        real BOOT2 line necessarily also "contains BOOT". The function must
        still resolve ps2 (its check is specifically for the "BOOT2" token),
        not fall to the ps1 branch because "BOOT" also matched.
        """
        assert self._call("BOOT2 = cdrom0:\\SLUS_200.01;1\r\n") == "ps2"


# ---------------------------------------------------------------------------
# Malformed magic_signatures.toml at import time
#
# magic_detect.py parses its TOML at module level (`_TOML_PATH =
# Path(__file__).parent / "magic_signatures.toml"`, then `tomllib.load()`
# called directly in the module body, not inside any function). A malformed
# TOML file therefore fails the moment the module is imported, not on any
# later function call. A normal monkeypatch of _TOML_PATH can't reproduce
# this, since by the time a test could patch that attribute the module has
# already imported successfully against the real, well-formed file.
#
# Reproducing the failure means putting a malformed magic_signatures.toml
# next to a copy of magic_detect.py *before* it is ever imported, then
# importing that copy in a subprocess so the already-cached, successfully
# imported real module in this test process's sys.modules is never touched.
# ---------------------------------------------------------------------------

class TestMalformedTomlAtImportTime:
    def test_malformed_toml_raises_at_import_not_at_call(self, tmp_path: Path):
        import backend.service.utils.smart_media_detector.magic.magic_detect as _real_module

        real_source = Path(_real_module.__file__)
        copied_module = tmp_path / "magic_detect_import_test.py"
        shutil.copy(real_source, copied_module)

        malformed_toml = tmp_path / "magic_signatures.toml"
        malformed_toml.write_text("this is [ not valid toml ===\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, "-c", "import magic_detect_import_test"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode != 0
        assert "TOMLDecodeError" in proc.stderr

    def test_wellformed_toml_sibling_still_imports_cleanly(self, tmp_path: Path):
        """Control case: the same copy-and-subprocess-import mechanism, but
        with the real magic_signatures.toml alongside the copied module, to
        confirm the failure above is caused by the malformed content and not
        by some artifact of running magic_detect.py as a standalone copy.
        """
        import backend.service.utils.smart_media_detector.magic.magic_detect as _real_module

        real_source = Path(_real_module.__file__)
        real_toml = real_source.parent / "magic_signatures.toml"
        copied_module = tmp_path / "magic_detect_import_test.py"
        shutil.copy(real_source, copied_module)
        shutil.copy(real_toml, tmp_path / "magic_signatures.toml")

        proc = subprocess.run(
            [sys.executable, "-c", "import magic_detect_import_test"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, proc.stderr
