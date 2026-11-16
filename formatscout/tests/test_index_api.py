"""Tests for the index API: path resolution, ensure_index(), the public
exception types, and the "unchecked" / strict behavior of classify() and
verify().

Offline only. Downloads go through the in-memory opener of test_index_hardening.py
(its `env` fixture re-enables the real fetch logic against a tmp cache dir);
anything that does not need a download relies on conftest.py's guards (fake
home, raising fetch stub, socket block). The one subprocess test never reaches
the network: importing the package opens no connection.
"""

import importlib
import json
import os
import subprocess
import sys
import tomllib
import urllib.error
from pathlib import Path

import pytest

import formatscout
from formatscout import IndexIntegrityError, IndexUnavailable, ensure_index
from formatscout.hashing import hash_lookup
from formatscout.hashing.title_match import fuzzy_title_match
from formatscout.index_path import INDEX_PATH_ENV, coerce_index_path, resolve_index_path
from formatscout.tests import smart_media_fixtures as fx
# `env` is a fixture defined (with its fakes) in the hardening tests; importing
# it here registers it for this module. The other names are plain helpers.
from formatscout.tests.test_index_hardening import _PAYLOAD, _Env, _install_managed, env  # noqa: F401

_detector = importlib.import_module("formatscout.detector")
_classify_module = importlib.import_module("formatscout.classify")
_verify_module = importlib.import_module("formatscout.verify")

_USER_INDEX = {"abc": {"title": "User Built", "platform": "Sony - PlayStation", "era": "ps1"}}


def _user_index(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_USER_INDEX), encoding="utf-8")
    return path


def _corrupt_index(tmp_path: Path) -> Path:
    path = tmp_path / "corrupt_index.json"
    path.write_text("{ this is not json", encoding="utf-8")
    return path


def _game(tmp_path: Path, content: bytes = fx.VERIFIED_CONTENT, name: str = "game.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _clear_hooks(monkeypatch) -> None:
    """Module hooks back to None (their production value), so resolution falls
    through to the argument / environment / default."""
    for module in (_detector, _classify_module, _verify_module):
        monkeypatch.setattr(module, "_INDEX_PATH", None)


# ---------------------------------------------------------------------------
# Resolution order
# ---------------------------------------------------------------------------

class TestResolutionOrder:
    def test_explicit_beats_hook_environment_and_default(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(INDEX_PATH_ENV, str(tmp_path / "env.json"))

        resolved = resolve_index_path(tmp_path / "explicit.json", override=tmp_path / "hook.json")

        assert resolved == tmp_path / "explicit.json"

    def test_hook_beats_environment_and_default(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(INDEX_PATH_ENV, str(tmp_path / "env.json"))

        assert resolve_index_path(override=tmp_path / "hook.json") == tmp_path / "hook.json"

    def test_environment_beats_default(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(INDEX_PATH_ENV, str(tmp_path / "env.json"))

        assert resolve_index_path() == tmp_path / "env.json"

    def test_default_when_nothing_else_is_set(self):
        assert resolve_index_path() == hash_lookup.default_index_path()
        assert resolve_index_path() == hash_lookup._DEFAULT_INDEX_PATH  # conftest's tmp default

    @pytest.mark.parametrize("value", ["", "   "])
    def test_blank_environment_value_counts_as_unset(self, value: str, monkeypatch):
        monkeypatch.setenv(INDEX_PATH_ENV, value)

        assert resolve_index_path() == hash_lookup.default_index_path()

    def test_string_and_relative_arguments_become_absolute_paths(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        resolved = resolve_index_path("index.json")

        assert resolved.is_absolute()
        assert resolved.parent.resolve() == tmp_path.resolve()
        assert resolved.name == "index.json"

    @pytest.mark.parametrize("bad, error", [
        ("", ValueError), ("a\0b", ValueError), (42, TypeError), (b"bytes.json", TypeError),
    ])
    def test_malformed_argument_is_a_programmer_error(self, bad, error):
        with pytest.raises(error):
            coerce_index_path(bad)

    def test_none_stays_none(self):
        assert coerce_index_path(None) is None

    def test_environment_variable_drives_detect_classify_and_verify(self, tmp_path: Path, monkeypatch):
        _clear_hooks(monkeypatch)
        monkeypatch.setenv(INDEX_PATH_ENV, str(fx.write_synthetic_index(tmp_path)))
        game = _game(tmp_path)
        sha1 = fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]

        assert _detector.detect(game).method == "hash_sha1"
        assert _classify_module.classify(game, "t", "ps1").status == "verified"
        assert _verify_module.verify(game, sha1).status == "matched"

    def test_explicit_argument_beats_hook_and_environment_in_every_entry_point(self, tmp_path: Path, monkeypatch):
        # conftest already points every hook at a nonexistent file; the
        # environment points at a corrupt one. Only the argument is usable.
        monkeypatch.setenv(INDEX_PATH_ENV, str(_corrupt_index(tmp_path)))
        good = fx.write_synthetic_index(tmp_path)
        game = _game(tmp_path)
        sha1 = fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]

        assert _detector.detect(game, index_path=good).method == "hash_sha1"
        assert _classify_module.classify(game, "t", "ps1", index_path=good).status == "verified"
        assert _classify_module.classify(game, "t", "ps1", index_path=str(good)).status == "verified"
        assert _verify_module.verify(game, sha1, index_path=good).status == "matched"

    def test_index_path_is_keyword_only(self, tmp_path: Path):
        good = fx.write_synthetic_index(tmp_path)
        game = _game(tmp_path)

        with pytest.raises(TypeError):
            _classify_module.classify(game, "t", "ps1", 0.8, good)  # type: ignore[misc]
        with pytest.raises(TypeError):
            _verify_module.verify(game, "0" * 40, good)  # type: ignore[misc]

    def test_title_match_resolves_its_own_index_path(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(INDEX_PATH_ENV, str(fx.write_synthetic_index(tmp_path)))

        match = fuzzy_title_match(fx.TITLE_QUERY_ABOVE_THRESHOLD, "ps1")

        assert match is not None and match[0] == fx.TITLE_MATCH_INDEXED_TITLE

    def test_detect_rejects_a_malformed_index_path_argument(self, tmp_path: Path):
        with pytest.raises(ValueError):
            _detector.detect(_game(tmp_path), index_path="")


# ---------------------------------------------------------------------------
# Lazy home directory
# ---------------------------------------------------------------------------

def _no_home(cls):
    raise RuntimeError("Could not determine home directory.")


class TestLazyHome:
    def test_default_path_follows_the_home_directory_at_call_time(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_CACHE_DIR", None)
        monkeypatch.setattr(hash_lookup, "_DEFAULT_INDEX_PATH", None)
        for var in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(var, str(tmp_path))

        assert hash_lookup.default_index_path() == tmp_path / ".formatscout" / "hash_index.json"

    def test_module_hooks_are_none_by_default(self):
        # Fresh interpreter state, not the conftest-patched one.
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "from formatscout.hashing import hash_lookup\n"
            "import importlib\n"
            "d = importlib.import_module('formatscout.detector')\n"
            "c = importlib.import_module('formatscout.classify')\n"
            "v = importlib.import_module('formatscout.verify')\n"
            "assert hash_lookup._CACHE_DIR is None and hash_lookup._DEFAULT_INDEX_PATH is None\n"
            "assert d._INDEX_PATH is None and c._INDEX_PATH is None and v._INDEX_PATH is None\n"
            "print('hooks-none')\n"
        )
        result = self._run_isolated(code)
        assert result.returncode == 0, result.stderr
        assert "hooks-none" in result.stdout

    def test_importing_the_package_succeeds_when_path_home_raises(self):
        code = (
            "import pathlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "def _no_home(cls):\n"
            "    raise RuntimeError('Could not determine home directory.')\n"
            "pathlib.Path.home = classmethod(_no_home)\n"
            "import formatscout\n"
            "from formatscout.hashing import hash_lookup\n"
            "try:\n"
            "    hash_lookup.default_index_path()\n"
            "except formatscout.IndexUnavailable:\n"
            "    print('import-ok', formatscout.__version__)\n"
            "else:\n"
            "    raise SystemExit('default_index_path() should have raised')\n"
        )
        result = self._run_isolated(code)
        assert result.returncode == 0, result.stderr
        assert "import-ok" in result.stdout

    @staticmethod
    def _run_isolated(code: str) -> subprocess.CompletedProcess:
        root = str(Path(formatscout.__file__).resolve().parent.parent)
        child_env = dict(os.environ, FORMATSCOUT_OFFLINE="1")
        child_env.pop(INDEX_PATH_ENV, None)
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", code, root],
            capture_output=True, text=True, timeout=120, env=child_env,
        )

    def test_without_a_home_the_default_is_index_unavailable_not_a_crash(self, tmp_path: Path, monkeypatch):
        _clear_hooks(monkeypatch)
        monkeypatch.setattr(hash_lookup, "_CACHE_DIR", None)
        monkeypatch.setattr(hash_lookup, "_DEFAULT_INDEX_PATH", None)
        monkeypatch.setattr(Path, "home", classmethod(_no_home))
        game = _game(tmp_path)

        with pytest.raises(IndexUnavailable, match="FORMATSCOUT_INDEX_PATH"):
            hash_lookup.default_index_path()
        assert hash_lookup.is_default_cache_path(tmp_path / "x.json") is False

        result = _classify_module.classify(game, "t", "ps1")
        assert result.status == "unchecked"
        assert [issue.code for issue in result.issues] == ["INDEX_UNAVAILABLE"]
        with pytest.raises(IndexUnavailable):
            _classify_module.classify(game, "t", "ps1", strict=True)

        scan = _detector.detect(_game(tmp_path, b"\x00" * 16, "x.nes"))
        assert scan.era == "nes"
        assert [issue.code for issue in scan.issues] == ["INDEX_UNAVAILABLE"]

        with pytest.raises(IndexUnavailable):
            ensure_index()

    def test_without_a_home_an_explicit_or_environment_path_still_works(self, tmp_path: Path, monkeypatch):
        _clear_hooks(monkeypatch)
        monkeypatch.setattr(hash_lookup, "_CACHE_DIR", None)
        monkeypatch.setattr(hash_lookup, "_DEFAULT_INDEX_PATH", None)
        monkeypatch.setattr(Path, "home", classmethod(_no_home))
        good = fx.write_synthetic_index(tmp_path)
        game = _game(tmp_path)

        assert _classify_module.classify(game, "t", "ps1", index_path=good).status == "verified"
        assert ensure_index(good) == good
        monkeypatch.setenv(INDEX_PATH_ENV, str(good))
        assert _classify_module.classify(game, "t", "ps1").status == "verified"
        assert ensure_index() == good


# ---------------------------------------------------------------------------
# Public exceptions and exports
# ---------------------------------------------------------------------------

class TestPublicTypes:
    def test_hierarchy(self):
        assert issubclass(IndexUnavailable, OSError)
        assert not issubclass(IndexUnavailable, FileNotFoundError)
        assert issubclass(IndexIntegrityError, IndexUnavailable)

    def test_private_names_are_aliases_of_the_public_types(self):
        assert hash_lookup._IndexUnavailableError is IndexUnavailable
        assert hash_lookup._IndexCorruptError is IndexIntegrityError

    def test_exports(self):
        for name in ("ensure_index", "IndexUnavailable", "IndexIntegrityError"):
            assert name in formatscout.__all__
            assert hasattr(formatscout, name)
        assert formatscout.ensure_index is importlib.import_module("formatscout.index").ensure_index

    def test_version_is_0_2_0_in_package_and_pyproject(self):
        assert formatscout.__version__ == "0.2.0"
        pyproject = Path(formatscout.__file__).resolve().parent.parent / "pyproject.toml"
        if not pyproject.exists():
            pytest.skip("pyproject.toml not next to the package (installed copy)")
        assert tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"] == "0.2.0"


# ---------------------------------------------------------------------------
# ensure_index()
# ---------------------------------------------------------------------------

class TestEnsureIndexDefaultCache:
    def test_downloads_once_installs_sidecar_and_returns_the_cache_path(self, env: _Env):
        result = ensure_index()

        assert result == env.index_path
        assert env.opener.calls == 1
        assert env.names() == ["hash_index.json", "hash_index.json.meta"]
        assert env.index_path in hash_lookup._index_cache  # parsed once, ready for detect()

    def test_valid_cache_needs_no_network(self, env: _Env):
        _install_managed(env)

        assert ensure_index() == env.index_path
        assert env.opener.calls == 0

    def test_explicit_default_location_behaves_like_no_argument(self, env: _Env):
        assert ensure_index(env.index_path) == env.index_path
        assert env.opener.calls == 1

    def test_modified_managed_cache_is_quarantined_and_redownloaded(self, env: _Env):
        _install_managed(env)
        env.index_path.write_bytes(b"{ tampered")

        ensure_index()

        assert env.opener.calls == 1
        assert env.index_path.with_name("hash_index.json.corrupt").read_bytes() == b"{ tampered"
        assert env.index_path.read_bytes() == _PAYLOAD

    def test_user_supplied_cache_without_sidecar_is_left_alone(self, env: _Env):
        _user_index(env.index_path)
        before = env.index_path.read_bytes()

        assert ensure_index() == env.index_path

        assert env.opener.calls == 0
        assert env.index_path.read_bytes() == before
        assert not env.sidecar.exists()

    def test_timeout_reaches_the_opener(self, env: _Env):
        ensure_index(timeout=5.0)

        assert env.opener.timeouts == [5.0]

    def test_max_bytes_is_the_download_cap(self, env: _Env):
        with pytest.raises(IndexUnavailable) as excinfo:
            ensure_index(max_bytes=100)

        assert not isinstance(excinfo.value, IndexIntegrityError)
        assert isinstance(excinfo.value.__cause__, ValueError)
        assert not env.index_path.exists()
        assert env.temp_files() == []

    @pytest.mark.parametrize("kwargs", [
        {"timeout": 0}, {"timeout": -1.0}, {"timeout": True}, {"timeout": "30"},
        {"max_bytes": 0}, {"max_bytes": -5}, {"max_bytes": 1.5}, {"max_bytes": True},
    ])
    def test_bad_limits_are_rejected_before_any_work(self, env: _Env, kwargs: dict):
        with pytest.raises(ValueError):
            ensure_index(**kwargs)

        assert env.opener.calls == 0


class TestEnsureIndexFailures:
    def test_offline_raises_index_unavailable_without_touching_the_network(self, env: _Env, monkeypatch):
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")

        with pytest.raises(IndexUnavailable, match=hash_lookup._OFFLINE_ENV):
            ensure_index()

        assert env.opener.calls == 0

    def test_offline_with_a_valid_cache_still_succeeds(self, env: _Env, monkeypatch):
        _install_managed(env)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")

        assert ensure_index() == env.index_path

    def test_failed_download_is_index_unavailable_chained_and_backs_off(self, env: _Env):
        env.opener.fail(urllib.error.URLError("boom"))

        with pytest.raises(IndexUnavailable) as excinfo:
            ensure_index()
        assert not isinstance(excinfo.value, IndexIntegrityError)
        assert isinstance(excinfo.value.__cause__, urllib.error.URLError)

        with pytest.raises(IndexUnavailable, match="not retrying"):
            ensure_index()
        assert env.opener.calls == 1

    def test_pin_mismatch_is_an_integrity_error(self, env: _Env):
        env.opener.serve(_PAYLOAD + b" tampered")

        with pytest.raises(IndexIntegrityError) as excinfo:
            ensure_index()

        assert isinstance(excinfo.value, IndexUnavailable)
        assert "sha256" in str(excinfo.value.__cause__)
        assert not env.index_path.exists()

    def test_oversized_user_supplied_cache_is_an_integrity_error_and_stays(self, env: _Env, monkeypatch):
        _user_index(env.index_path)
        monkeypatch.setattr(hash_lookup, "_MAX_INDEX_BYTES", 5)

        with pytest.raises(IndexIntegrityError, match="byte limit"):
            ensure_index()

        assert env.index_path.exists()
        assert env.opener.calls == 0


class TestEnsureIndexUserSuppliedPath:
    def test_valid_explicit_path_is_returned_and_never_downloaded_to(self, env: _Env, tmp_path: Path):
        custom = fx.write_synthetic_index(tmp_path)

        assert ensure_index(custom) == custom

        assert env.opener.calls == 0
        assert not custom.with_name(custom.name + ".meta").exists()

    def test_environment_path_is_used_when_no_argument_is_given(self, env: _Env, tmp_path: Path, monkeypatch):
        custom = fx.write_synthetic_index(tmp_path)
        monkeypatch.setenv(INDEX_PATH_ENV, str(custom))

        assert ensure_index() == custom
        assert env.opener.calls == 0

    def test_sidecar_next_to_a_custom_path_is_ignored(self, env: _Env, tmp_path: Path):
        custom = _user_index(tmp_path / "mine.json")
        hash_lookup._write_sidecar(custom, "0" * 64, 1, 1)  # a record that cannot match
        before = custom.read_bytes()

        assert ensure_index(custom) == custom

        assert custom.read_bytes() == before
        assert not custom.with_name("mine.json.corrupt").exists()
        assert env.opener.calls == 0

    def test_missing_path_is_index_unavailable_not_file_not_found_and_never_downloads(
        self, env: _Env, tmp_path: Path,
    ):
        missing = tmp_path / "never_built.json"

        with pytest.raises(IndexUnavailable, match="build_index") as excinfo:
            ensure_index(missing)

        assert not isinstance(excinfo.value, FileNotFoundError)
        assert isinstance(excinfo.value.__cause__, FileNotFoundError)
        assert env.opener.calls == 0
        assert not missing.exists()

    def test_corrupt_file_is_an_integrity_error_and_is_left_in_place(self, env: _Env, tmp_path: Path):
        bad = _corrupt_index(tmp_path)
        before = bad.read_bytes()

        with pytest.raises(IndexIntegrityError):
            ensure_index(bad)

        assert bad.read_bytes() == before
        assert not bad.with_name(bad.name + ".corrupt").exists()

    def test_max_bytes_caps_the_file_before_parsing(self, tmp_path: Path):
        custom = fx.write_synthetic_index(tmp_path)

        with pytest.raises(IndexIntegrityError, match="byte limit"):
            ensure_index(custom, max_bytes=10)

        assert ensure_index(custom, max_bytes=custom.stat().st_size) == custom

    def test_force_on_a_custom_path_revalidates_and_never_downloads(self, env: _Env, tmp_path: Path):
        custom = fx.write_synthetic_index(tmp_path)
        ensure_index(custom)
        before = custom.stat()
        custom.write_text("{ now broken", encoding="utf-8")
        os.utime(custom, ns=(before.st_atime_ns, before.st_mtime_ns))  # same mtime: the parse cache still hits

        assert ensure_index(custom) == custom  # served from the in-process cache

        with pytest.raises(IndexIntegrityError):
            ensure_index(custom, force=True)  # force drops the cache and re-validates

        assert env.opener.calls == 0
        assert custom.read_text(encoding="utf-8") == "{ now broken"


class TestEnsureIndexForce:
    def test_replaces_a_pristine_managed_copy_in_place_without_quarantine(self, env: _Env):
        _install_managed(env)

        assert ensure_index(force=True) == env.index_path

        assert env.opener.calls == 1
        assert env.index_path.read_bytes() == _PAYLOAD
        assert env.sidecar.exists()
        assert not env.index_path.with_name("hash_index.json.corrupt").exists()
        assert env.temp_files() == []

    def test_downloads_when_nothing_is_cached(self, env: _Env):
        assert ensure_index(force=True) == env.index_path

        assert env.opener.calls == 1

    def test_moves_a_user_supplied_file_aside_instead_of_destroying_it(self, env: _Env):
        _user_index(env.index_path)
        mine = env.index_path.read_bytes()

        ensure_index(force=True)

        assert env.index_path.read_bytes() == _PAYLOAD
        assert env.index_path.with_name("hash_index.json.corrupt").read_bytes() == mine

    def test_never_overwrites_an_earlier_quarantined_copy(self, env: _Env):
        _user_index(env.index_path)
        first = env.index_path.read_bytes()
        ensure_index(force=True)
        env.index_path.write_bytes(b'{"other": {"title": "Second"}}')  # size differs from the download
        second = env.index_path.read_bytes()

        ensure_index(force=True)

        assert env.index_path.with_name("hash_index.json.corrupt").read_bytes() == first
        assert env.index_path.with_name("hash_index.json.corrupt.1").read_bytes() == second
        assert env.index_path.read_bytes() == _PAYLOAD

    def test_failed_download_leaves_the_existing_file_untouched(self, env: _Env):
        _user_index(env.index_path)
        mine = env.index_path.read_bytes()
        env.opener.fail(urllib.error.URLError("boom"))

        with pytest.raises(IndexUnavailable):
            ensure_index(force=True)

        assert env.index_path.read_bytes() == mine
        assert not env.index_path.with_name("hash_index.json.corrupt").exists()
        assert env.temp_files() == []

    def test_pin_mismatch_leaves_the_existing_file_untouched(self, env: _Env):
        _user_index(env.index_path)
        mine = env.index_path.read_bytes()
        env.opener.serve(b"not the pinned index")

        with pytest.raises(IndexIntegrityError):
            ensure_index(force=True)

        assert env.index_path.read_bytes() == mine
        assert not env.index_path.with_name("hash_index.json.corrupt").exists()

    def test_exhausted_quarantine_names_fail_and_keep_the_file_without_backoff(self, env: _Env):
        names = ["hash_index.json.corrupt"] + [f"hash_index.json.corrupt.{n}" for n in range(1, 6)]
        env.cache_dir.mkdir(parents=True)
        for name in names:
            (env.cache_dir / name).write_bytes(b"old")
        _user_index(env.index_path)
        mine = env.index_path.read_bytes()

        with pytest.raises(IndexUnavailable, match="delete the old quarantined"):
            ensure_index(force=True)

        assert env.index_path.read_bytes() == mine
        assert env.temp_files() == []
        assert not env.marker.exists() and hash_lookup._last_fetch_failure is None

    def test_ignores_the_backoff_window_but_not_offline_mode(self, env: _Env, monkeypatch):
        env.opener.fail(urllib.error.URLError("boom"))
        with pytest.raises(IndexUnavailable):
            ensure_index()
        env.opener.serve(_PAYLOAD)
        with pytest.raises(IndexUnavailable, match="not retrying"):
            ensure_index()
        assert env.opener.calls == 1

        assert ensure_index(force=True) == env.index_path
        assert env.opener.calls == 2
        assert not env.marker.exists() and hash_lookup._last_fetch_failure is None

        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")
        with pytest.raises(IndexUnavailable, match=hash_lookup._OFFLINE_ENV):
            ensure_index(force=True)
        assert env.opener.calls == 2

    def test_refreshed_index_is_what_the_next_load_sees(self, env: _Env):
        _install_managed(env)
        hash_lookup.load_index(env.index_path)  # warm the in-process cache

        ensure_index(force=True)

        index, _md5, _crc = hash_lookup.load_index(env.index_path)
        assert index == fx.build_synthetic_index()


# ---------------------------------------------------------------------------
# classify() / verify(): unchecked and strict
# ---------------------------------------------------------------------------

_SHA1 = fx.hashes_for(fx.VERIFIED_CONTENT)["sha1"]


class TestUncheckedAndStrict:
    def test_classify_unusable_index_is_unchecked_with_the_sha1_kept(self, tmp_path: Path):
        result = _classify_module.classify(_game(tmp_path), "Some Title", "ps1", index_path=_corrupt_index(tmp_path))

        assert result.status == "unchecked"
        assert result.computed_sha1 == _SHA1
        assert result.matched_title is None and result.similarity is None
        assert result.reason.startswith("hash index unavailable: ")
        assert [issue.code for issue in result.issues] == ["INDEX_UNAVAILABLE"]
        assert result.issues[0].message == result.reason

    def test_verify_unusable_index_is_unchecked_with_both_hashes_kept(self, tmp_path: Path):
        result = _verify_module.verify(_game(tmp_path), "f" * 40, index_path=_corrupt_index(tmp_path))

        assert result.status == "unchecked"
        assert result.computed_sha1 == _SHA1
        assert result.expected_sha1 == "f" * 40
        assert result.reason.startswith("hash index unavailable: ")
        assert [issue.code for issue in result.issues] == ["INDEX_UNAVAILABLE"]

    def test_offline_default_cache_is_unchecked(self, env: _Env, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")
        game = _game(tmp_path)

        assert _classify_module.classify(game, "t", "ps1", index_path=env.index_path).status == "unchecked"
        assert _verify_module.verify(game, _SHA1, index_path=env.index_path).status == "unchecked"
        assert env.opener.calls == 0

    def test_strict_raises_the_public_exception(self, tmp_path: Path):
        game = _game(tmp_path)
        bad = _corrupt_index(tmp_path)

        with pytest.raises(IndexIntegrityError):
            _classify_module.classify(game, "t", "ps1", index_path=bad, strict=True)
        with pytest.raises(IndexUnavailable):
            _verify_module.verify(game, _SHA1, index_path=bad, strict=True)

    def test_strict_offline_raises_index_unavailable(self, env: _Env, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")

        with pytest.raises(IndexUnavailable):
            _classify_module.classify(_game(tmp_path), "t", "ps1", index_path=env.index_path, strict=True)

    def test_usable_index_is_unaffected_by_strict(self, tmp_path: Path):
        good = fx.write_synthetic_index(tmp_path)

        assert _classify_module.classify(_game(tmp_path), "t", "ps1", index_path=good, strict=True).status == "verified"
        assert _verify_module.verify(_game(tmp_path), _SHA1, index_path=good, strict=True).status == "matched"

    def test_missing_custom_index_is_still_an_empty_index_even_when_strict(self, tmp_path: Path):
        missing = tmp_path / "never_built.json"
        game = _game(tmp_path)

        classified = _classify_module.classify(game, "t", "ps1", index_path=missing, strict=True)
        assert classified.status == "not_in_index"
        assert [issue.code for issue in classified.issues] == ["index_missing"]
        assert _verify_module.verify(game, _SHA1, index_path=missing, strict=True).status == "not_in_index"

    def test_unreadable_file_keeps_its_existing_behavior(self, tmp_path: Path):
        missing_file = tmp_path / "gone.bin"
        good = fx.write_synthetic_index(tmp_path)

        result = _classify_module.classify(missing_file, "t", "ps1", index_path=good, strict=True)
        assert result.status == "unchecked"
        assert [issue.code for issue in result.issues] == ["hash_failed"]
        assert result.computed_sha1 is None
        with pytest.raises(OSError):
            _verify_module.verify(missing_file, _SHA1, index_path=good)

    def test_title_match_failure_after_a_successful_load_is_also_unchecked(self, tmp_path: Path, monkeypatch):
        good = fx.write_synthetic_index(tmp_path)
        game = _game(tmp_path, fx.UNINDEXED_CONTENT)

        def _fail(*args, **kwargs):
            raise IndexUnavailable("index vanished")

        monkeypatch.setattr(_classify_module, "fuzzy_title_match", _fail)

        result = _classify_module.classify(game, fx.TITLE_QUERY_ABOVE_THRESHOLD, "ps1", index_path=good)
        assert result.status == "unchecked"
        assert [issue.code for issue in result.issues] == ["INDEX_UNAVAILABLE"]
        with pytest.raises(IndexUnavailable):
            _classify_module.classify(game, fx.TITLE_QUERY_ABOVE_THRESHOLD, "ps1", index_path=good, strict=True)

    def test_reason_and_issue_cannot_carry_control_characters(self, tmp_path: Path, monkeypatch):
        def _hostile(path, **kwargs):
            raise IndexUnavailable("bad\x1b[31m red\nline\x00end")

        monkeypatch.setattr(hash_lookup, "load_index", _hostile)

        for result in (
            _classify_module.classify(_game(tmp_path), "t", "ps1"),
            _verify_module.verify(_game(tmp_path), _SHA1),
        ):
            assert result.status == "unchecked"
            assert all(ch.isprintable() for ch in result.reason)
            assert all(ch.isprintable() for ch in result.issues[0].message)

    def test_detect_adds_one_index_unavailable_issue_next_to_the_warning(self, tmp_path: Path):
        scan = _detector.detect(_game(tmp_path, fx.NES_HEADER_BLOB), index_path=_corrupt_index(tmp_path))

        assert scan.era == "nes"
        assert [issue.code for issue in scan.issues] == ["INDEX_UNAVAILABLE"]
        assert scan.issues[0].message in scan.warnings
        assert scan.issues[0].message.startswith("hash index unavailable: ")

    def test_missing_custom_index_stays_quiet_in_detect(self, tmp_path: Path):
        scan = _detector.detect(_game(tmp_path, fx.NES_HEADER_BLOB), index_path=tmp_path / "nowhere" / "x.json")

        assert scan.era == "nes"
        assert scan.issues == ()  # a missing custom index is not a failure
        assert not any(w.startswith("hash index unavailable") for w in scan.warnings)
