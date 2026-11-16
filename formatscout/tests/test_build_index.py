"""Tests for formatscout.hashing.build_index.

build_index.py is a CLI entry point (python -m ...build_index --dats <dir>),
so main() reads argparse args from sys.argv directly rather than taking
parameters, these tests monkeypatch sys.argv to drive it the same way a real
invocation would. Basic smoke coverage only, per the scoping for this file,
not exhaustive CLI-argument-parsing coverage.

One real, worth-knowing side effect: main() calls logging.basicConfig(...) as
its very first statement, so every invocation attaches a StreamHandler to the
root logger, a no-op if root already has one, but otherwise a process-global
change that would outlive this test file if left in place. Each test below
saves and restores logging.root.handlers around the call so this file doesn't
leak that state into whatever other test happens to run later in the same
pytest process.
"""

import json
import logging
import sys
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx


class TestBuildIndexMain:
    def _run(self, monkeypatch, argv: list[str]) -> None:
        from formatscout.hashing import build_index

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


def _run_main(monkeypatch, argv: list[str]) -> None:
    from formatscout.hashing import build_index

    monkeypatch.setattr(sys, "argv", argv)
    root_handlers_before = list(logging.root.handlers)
    try:
        build_index.main()
    finally:
        logging.root.handlers[:] = root_handlers_before


def _dats(tmp_path: Path) -> Path:
    dats_dir = tmp_path / "dats"
    dats_dir.mkdir()
    fx.write_dat_xml(
        dats_dir / "sample.dat",
        header_name="Sony - PlayStation",
        games=[{"name": "Sample Game (USA)", "roms": [{"sha1": "A" * 40}]}],
    )
    return dats_dir


class TestBuildIndexRuntimeHint:
    """build_index keeps its default output but says where the runtime reads
    and how to use what it wrote."""

    def test_names_the_runtime_path_and_both_ways_to_use_a_custom_output(self, tmp_path: Path, monkeypatch, capsys):
        from formatscout.hashing import hash_lookup

        output = tmp_path / "mine" / "hash_index.json"

        _run_main(monkeypatch, ["build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(output)])

        out = capsys.readouterr().out
        assert f"Written to:      {output}" in out
        assert f"Runtime reads:   {hash_lookup.default_index_path()}" in out
        assert "FORMATSCOUT_INDEX_PATH" in out
        assert "index_path=" in out
        assert "--output" in out

    def test_runtime_path_follows_the_environment_variable(self, tmp_path: Path, monkeypatch, capsys):
        output = tmp_path / "mine.json"
        monkeypatch.setenv("FORMATSCOUT_INDEX_PATH", str(output))

        _run_main(monkeypatch, ["build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(output)])

        out = capsys.readouterr().out
        assert f"Runtime reads:   {output}" in out
        assert "already in use" in out

    def test_default_output_location_is_unchanged(self):
        from formatscout.hashing import build_index

        assert build_index._DEFAULT_OUTPUT == Path(build_index.__file__).parent / "hash_index.json"

    def test_hint_survives_an_unknown_home_directory(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import build_index, hash_lookup

        def _no_home(cls):
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.setattr(hash_lookup, "_CACHE_DIR", None)
        monkeypatch.setattr(hash_lookup, "_DEFAULT_INDEX_PATH", None)
        monkeypatch.setattr(Path, "home", classmethod(_no_home))

        lines = build_index._runtime_hint(tmp_path / "x.json")

        assert lines[0].startswith("Runtime reads:   unknown")
        assert "FORMATSCOUT_INDEX_PATH" in lines[1]


class TestBuildIndexCacheSidecar:
    """Writing to the cache path must not leave the stale download sidecar
    behind, or the user-built index would be quarantined as a modified
    managed file."""

    def _stale_managed_cache(self) -> Path:
        from formatscout.hashing import hash_lookup

        cache = hash_lookup.default_index_path()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text("{}", encoding="utf-8")
        stat = cache.stat()
        hash_lookup._write_sidecar(cache, "0" * 64, stat.st_size, stat.st_mtime_ns)
        assert hash_lookup._sidecar_path(cache).exists()
        return cache

    def test_stale_sidecar_is_removed_and_the_built_index_is_not_quarantined(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import hash_lookup

        cache = self._stale_managed_cache()

        _run_main(monkeypatch, [
            "build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(cache), "--rebuild",
        ])

        assert not hash_lookup._sidecar_path(cache).exists()
        # Loads as a user-supplied file: no quarantine, and (conftest's fetch
        # stub would fail the test) no download.
        index, _md5, _crc = hash_lookup.load_index(cache)
        assert list(index) == ["a" * 40]
        assert not cache.with_name(cache.name + ".corrupt").exists()

    def test_without_a_sidecar_nothing_extra_happens(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import hash_lookup

        cache = hash_lookup.default_index_path()

        _run_main(monkeypatch, [
            "build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(cache), "--rebuild",
        ])

        assert cache.exists()
        assert not hash_lookup._sidecar_path(cache).exists()

    def test_a_sidecar_next_to_any_other_output_is_not_touched(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import hash_lookup

        output = tmp_path / "other.json"
        output.write_text("{}", encoding="utf-8")
        hash_lookup._write_sidecar(output, "0" * 64, 2, 1)

        _run_main(monkeypatch, [
            "build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(output), "--rebuild",
        ])

        assert hash_lookup._sidecar_path(output).exists()

    def test_failed_build_keeps_the_cache_and_its_sidecar(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import hash_lookup

        cache = self._stale_managed_cache()

        with pytest.raises(SystemExit):
            _run_main(monkeypatch, [
                "build_index.py", "--dats", str(tmp_path / "missing"), "--output", str(cache),
            ])

        assert hash_lookup._sidecar_path(cache).exists()
        assert cache.read_text(encoding="utf-8") == "{}"

    def test_sidecar_removal_failure_aborts_before_the_index_is_replaced(self, tmp_path: Path, monkeypatch):
        from formatscout.hashing import build_index

        cache = self._stale_managed_cache()

        def _fail(output_path):
            raise PermissionError("sidecar is locked")

        monkeypatch.setattr(build_index, "_remove_stale_sidecar", _fail)

        with pytest.raises(PermissionError):
            _run_main(monkeypatch, [
                "build_index.py", "--dats", str(_dats(tmp_path)), "--output", str(cache), "--rebuild",
            ])

        assert cache.read_text(encoding="utf-8") == "{}"
        assert not list(cache.parent.glob("*.tmp"))
