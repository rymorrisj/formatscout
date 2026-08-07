"""Tests for backend.service.utils.smart_media_detector.hashing.build_index.

build_index.py is a CLI entry point (python -m ...build_index --dats <dir>),
so main() reads argparse args from sys.argv directly rather than taking
parameters, these tests monkeypatch sys.argv to drive it the same way a real
invocation would. Basic smoke coverage only, per the scoping for this file,
not exhaustive CLI-argument-parsing coverage.

One real, worth-knowing side effect found while writing this: build_index.py
calls logging.basicConfig(...) at module import time (not inside main()), so
merely importing this module is enough to attach a StreamHandler to the root
logger, a no-op if root already has one, but otherwise a process-global change
that would outlive this test file if left in place. Each test below saves and
restores logging.root.handlers around the call so this file doesn't leak that
state into whatever other test happens to run later in the same pytest process.
"""

import json
import logging
import sys
from pathlib import Path

import pytest

from backend.service.utils.smart_media_detector.tests import smart_media_fixtures as fx


class TestBuildIndexMain:
    def _run(self, monkeypatch, argv: list[str]) -> None:
        from backend.service.utils.smart_media_detector.hashing import build_index

        monkeypatch.setattr(sys, "argv", argv)
        root_handlers_before = list(logging.root.handlers)
        try:
            build_index.main()
        finally:
            logging.root.handlers[:] = root_handlers_before

    def test_smoke_builds_a_valid_index_from_a_synthetic_dat(self, tmp_path: Path, monkeypatch):
        dats_dir = tmp_path / "dats"
        dats_dir.mkdir()
        fx.write_dat_xml(
            dats_dir / "sample.dat",
            header_name="Sony - PlayStation",
            games=[{
                "name": "Sample Game (USA)",
                "roms": [{"sha1": "A" * 40, "md5": "B" * 32, "crc": "DEADBEEF"}],
            }],
        )
        # Deliberately a tmp_path output, never the module's real
        # _DEFAULT_OUTPUT (the production ~88MB hash_index.json).
        output_path = tmp_path / "hash_index.json"

        self._run(monkeypatch, [
            "build_index.py", "--dats", str(dats_dir), "--output", str(output_path),
        ])

        assert output_path.exists()
        index = json.loads(output_path.read_text(encoding="utf-8"))
        assert list(index.keys()) == ["a" * 40]
        entry = index["a" * 40]
        assert entry["title"] == "Sample Game (USA)"
        assert entry["platform"] == "Sony - PlayStation"
        assert entry["era"] == "ps1"
        assert entry["source"] == "sample"
        assert entry["md5"] == "b" * 32
        assert entry["crc32"] == "deadbeef"

    def test_rom_with_no_sha1_is_not_indexed(self, tmp_path: Path, monkeypatch):
        """md5/crc32-only records parse cleanly (dat_parser.py's own job)
        but contribute zero entries to the index, since the index is keyed
        by sha1 only, main()'s own "skipped_no_sha1" accounting."""
        dats_dir = tmp_path / "dats"
        dats_dir.mkdir()
        fx.write_dat_xml(
            dats_dir / "sample.dat",
            games=[{
                "name": "Some Game",
                "roms": [
                    {"md5": "C" * 32},  # no sha1 at all
                    {"sha1": "D" * 40},
                ],
            }],
        )
        output_path = tmp_path / "hash_index.json"

        self._run(monkeypatch, [
            "build_index.py", "--dats", str(dats_dir), "--output", str(output_path),
        ])

        index = json.loads(output_path.read_text(encoding="utf-8"))
        assert list(index.keys()) == ["d" * 40]

    def test_nonexistent_dats_dir_exits_nonzero(self, tmp_path: Path, monkeypatch):
        output_path = tmp_path / "hash_index.json"
        with pytest.raises(SystemExit) as exc_info:
            self._run(monkeypatch, [
                "build_index.py", "--dats", str(tmp_path / "does_not_exist"), "--output", str(output_path),
            ])
        assert exc_info.value.code == 1
        assert not output_path.exists()
