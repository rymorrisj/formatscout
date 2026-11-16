"""Tests for the hash index download/cache hardening in hash_lookup.

Nothing here touches the network. The download goes through the module-level
seam hash_lookup._open_index_url, which these tests replace with an in-memory
opener that counts calls. The code under test uses build_opener().open, which
bypasses conftest.py's urllib.request.urlopen guard, so only the socket guard
is a backstop here: if the real opener were ever reached, the connect attempt
would be recorded and fail the test at teardown.

conftest.py also replaces hash_lookup._fetch_default_index with a raising stub.
The real function is captured at import time (collection runs before any
fixture) and put back by the `env` fixture, so the backoff/offline/download
logic is exercised for real against a tmp cache dir.
"""

import io
import itertools
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pytest

from formatscout.hashing import hash_lookup
from formatscout.tests import smart_media_fixtures as fx

_REAL_FETCH = hash_lookup._fetch_default_index
_IndexUnavailableError = hash_lookup._IndexUnavailableError
_IndexCorruptError = hash_lookup._IndexCorruptError

_PAYLOAD = json.dumps(fx.build_synthetic_index()).encode("utf-8")
_WARNING_PREFIX = "hash index unavailable: "
_WARNING_SUFFIX = "; heuristics only"


def _sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


class _FakeResponse(io.BytesIO):
    """In-memory stand-in for an HTTP response (context manager + headers)."""

    def __init__(self, data: bytes, headers: dict[str, str] | None = None) -> None:
        super().__init__(data)
        self.headers = headers or {}
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        chunk = super().read(size)
        self.bytes_read += len(chunk)
        return chunk

    def read1(self, size: int = -1) -> bytes:
        chunk = super().read1(size)
        self.bytes_read += len(chunk)
        return chunk


class _DripResponse(_FakeResponse):
    """Slow-drip server: read1() yields one byte per call, and a plain read()
    (which would block for a full chunk) must never be used."""

    def read(self, size: int | None = -1) -> bytes:
        raise AssertionError("read() would block waiting for a full chunk; read1() expected")

    def read1(self, size: int = -1) -> bytes:
        return super().read1(1)


class _Opener:
    """Replacement for hash_lookup._open_index_url that records its calls."""

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.timeouts: list[float] = []
        self.responder: Callable[[], _FakeResponse] = lambda: _FakeResponse(_PAYLOAD)

    @property
    def calls(self) -> int:
        return len(self.urls)

    def serve(self, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.responder = lambda: _FakeResponse(data, headers)

    def fail(self, exc: Exception) -> None:
        def _raise() -> _FakeResponse:
            raise exc
        self.responder = _raise

    def __call__(self, url: str, timeout: float) -> _FakeResponse:
        self.urls.append(url)
        self.timeouts.append(timeout)
        return self.responder()


@dataclass
class _Env:
    opener: _Opener
    cache_dir: Path
    index_path: Path
    marker: Path
    sha_calls: list[Path] = field(default_factory=list)

    def names(self) -> list[str]:
        return sorted(p.name for p in self.cache_dir.iterdir()) if self.cache_dir.exists() else []

    def temp_files(self) -> list[Path]:
        return list(self.cache_dir.glob("*.tmp")) if self.cache_dir.exists() else []


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> _Env:
    """Real fetch logic, in-memory opener, pin set to the synthetic payload,
    and fresh process-level backoff/verification state."""
    opener = _Opener()
    monkeypatch.setattr(hash_lookup, "_fetch_default_index", _REAL_FETCH)
    monkeypatch.setattr(hash_lookup, "_open_index_url", opener)
    monkeypatch.setattr(hash_lookup, "_INDEX_SHA256", _sha256(_PAYLOAD))
    monkeypatch.setattr(hash_lookup, "_last_fetch_failure", None)
    monkeypatch.setattr(hash_lookup, "_verified_default", set())
    monkeypatch.delenv(hash_lookup._OFFLINE_ENV, raising=False)

    real_sha = hash_lookup._sha256_file
    result = _Env(
        opener=opener,
        cache_dir=hash_lookup._CACHE_DIR,
        index_path=hash_lookup._DEFAULT_INDEX_PATH,
        marker=hash_lookup._CACHE_DIR / hash_lookup._FAILURE_MARKER_NAME,
    )

    def _counting_sha(path: Path) -> str:
        result.sha_calls.append(path)
        return real_sha(path)

    monkeypatch.setattr(hash_lookup, "_sha256_file", _counting_sha)
    return result


def _detect(path: Path):
    from formatscout.detector import detect
    return detect(path)


def _index_warnings(result) -> list[str]:
    return [w for w in result.warnings if w.startswith(_WARNING_PREFIX)]


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

class TestDownload:
    def test_success_installs_verified_index_and_cleans_up(self, env: _Env):
        index, _md5, _crc = hash_lookup.load_index(env.index_path)

        assert index == fx.build_synthetic_index()
        assert env.index_path.read_bytes() == _PAYLOAD
        assert env.opener.calls == 1
        assert env.opener.urls[0].startswith("https://")
        assert env.opener.timeouts == [hash_lookup._SOCKET_TIMEOUT_SECONDS]
        assert env.names() == ["hash_index.json"]  # no temp file, no failure marker

    def test_streams_in_multiple_chunks(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_DOWNLOAD_CHUNK", 16)

        hash_lookup._fetch_default_index()

        assert env.index_path.read_bytes() == _PAYLOAD

    def test_oversize_body_aborts_and_removes_temp(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_MAX_DOWNLOAD_BYTES", 100)
        monkeypatch.setattr(hash_lookup, "_DOWNLOAD_CHUNK", 32)
        assert len(_PAYLOAD) > 100

        with pytest.raises(_IndexUnavailableError) as excinfo:
            hash_lookup.load_index(env.index_path)

        assert isinstance(excinfo.value.__cause__, ValueError)
        assert not env.index_path.exists()
        assert env.temp_files() == []

    def test_declared_oversize_aborts_before_reading_body(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_MAX_DOWNLOAD_BYTES", 100)
        response = _FakeResponse(_PAYLOAD, {"Content-Length": "100000"})
        env.opener.responder = lambda: response

        with pytest.raises(_IndexUnavailableError):
            hash_lookup._fetch_default_index()

        assert response.bytes_read == 0
        assert env.temp_files() == []
        assert not env.index_path.exists()

    def test_sha256_mismatch_leaves_no_cache(self, env: _Env):
        env.opener.serve(_PAYLOAD + b" tampered")

        with pytest.raises(_IndexUnavailableError) as excinfo:
            hash_lookup.load_index(env.index_path)

        assert "sha256" in str(excinfo.value.__cause__)
        assert not env.index_path.exists()
        assert env.temp_files() == []

    def test_failed_download_does_not_clobber_existing_cache(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(b"previous")
        env.opener.serve(b"wrong payload")

        with pytest.raises(_IndexUnavailableError):
            hash_lookup._fetch_default_index()

        assert env.index_path.read_bytes() == b"previous"
        assert env.temp_files() == []

    def test_deadline_exceeded_aborts_and_removes_temp(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_DOWNLOAD_CHUNK", 16)
        ticks = itertools.count(0, 400)  # deadline = 0 + 600; 2nd check sees 800
        monkeypatch.setattr(hash_lookup, "_monotonic", lambda: next(ticks))

        with pytest.raises(_IndexUnavailableError) as excinfo:
            hash_lookup._fetch_default_index()

        assert isinstance(excinfo.value.__cause__, TimeoutError)
        assert not env.index_path.exists()
        assert env.temp_files() == []

    def test_slow_drip_server_cannot_defeat_the_deadline(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_DOWNLOAD_CHUNK", 1024 * 1024)
        response = _DripResponse(_PAYLOAD)
        env.opener.responder = lambda: response
        ticks = itertools.count(0, 100)  # each loop iteration "takes" 100 s; deadline 600 s
        monkeypatch.setattr(hash_lookup, "_monotonic", lambda: next(ticks))

        with pytest.raises(_IndexUnavailableError) as excinfo:
            hash_lookup._fetch_default_index()

        assert isinstance(excinfo.value.__cause__, TimeoutError)
        assert 0 < response.bytes_read < 20  # checked every drip, not every 1 MiB
        assert env.temp_files() == []
        assert not env.index_path.exists()

    def test_stale_temp_files_are_removed_recent_ones_kept(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        stale = env.cache_dir / ".hash_index.json.stale.tmp"
        recent = env.cache_dir / ".hash_index.json.recent.tmp"
        stale.write_bytes(b"x")
        recent.write_bytes(b"x")
        old = stale.stat().st_mtime - 2 * hash_lookup._STALE_TEMP_SECONDS
        os.utime(stale, (old, old))

        hash_lookup._fetch_default_index()

        assert not stale.exists()
        assert recent.exists()

    def test_open_index_url_rejects_non_https_url(self):
        with pytest.raises(ValueError, match="https"):
            hash_lookup._open_index_url("http://example.invalid/hash_index.json", 1.0)

    def test_redirect_to_http_is_refused(self):
        handler = hash_lookup._HttpsOnlyRedirectHandler()
        req = urllib.request.Request("https://example.invalid/a")

        with pytest.raises(urllib.error.URLError, match="non-https"):
            handler.redirect_request(req, None, 302, "Found", {}, "http://example.invalid/b")

    def test_redirect_to_https_is_followed(self):
        handler = hash_lookup._HttpsOnlyRedirectHandler()
        req = urllib.request.Request("https://example.invalid/a")

        new_req = handler.redirect_request(req, None, 302, "Found", {}, "https://example.invalid/b")

        assert new_req is not None
        assert new_req.full_url == "https://example.invalid/b"


# ---------------------------------------------------------------------------
# Backoff, failure marker, offline mode
# ---------------------------------------------------------------------------

class TestBackoff:
    def test_second_call_within_window_never_reaches_opener(self, env: _Env):
        env.opener.fail(urllib.error.URLError("boom"))

        with pytest.raises(_IndexUnavailableError, match="download failed"):
            hash_lookup.load_index(env.index_path)
        with pytest.raises(_IndexUnavailableError, match="not retrying"):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1
        assert env.marker.exists()

    def test_marker_write_error_is_ignored(self, env: _Env, tmp_path: Path, monkeypatch):
        blocker = tmp_path / "a_file"
        blocker.write_bytes(b"")
        monkeypatch.setattr(hash_lookup, "_failure_marker_path", lambda: blocker / "marker")
        env.opener.fail(urllib.error.URLError("boom"))

        with pytest.raises(_IndexUnavailableError, match="download failed"):
            hash_lookup._fetch_default_index()
        with pytest.raises(_IndexUnavailableError, match="not retrying"):
            hash_lookup._fetch_default_index()

        assert env.opener.calls == 1  # in-process backoff still holds

    def test_fresh_marker_from_another_process_is_honored(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.marker.touch()

        with pytest.raises(_IndexUnavailableError, match="not retrying"):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 0

    def test_expired_marker_is_ignored(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.marker.touch()
        old = env.marker.stat().st_mtime - 2 * hash_lookup._FETCH_BACKOFF_SECONDS
        os.utime(env.marker, (old, old))

        hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1

    def test_marker_with_future_mtime_is_ignored(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.marker.touch()
        future = env.marker.stat().st_mtime + 10_000
        os.utime(env.marker, (future, future))

        hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1

    def test_success_after_window_clears_marker_and_state(self, env: _Env, monkeypatch):
        env.opener.fail(urllib.error.URLError("boom"))
        with pytest.raises(_IndexUnavailableError):
            hash_lookup._fetch_default_index()
        assert env.marker.exists()

        # Age the failure past the window, both in-process and on disk.
        monkeypatch.setattr(
            hash_lookup, "_last_fetch_failure",
            hash_lookup._last_fetch_failure - 2 * hash_lookup._FETCH_BACKOFF_SECONDS,
        )
        old = env.marker.stat().st_mtime - 2 * hash_lookup._FETCH_BACKOFF_SECONDS
        os.utime(env.marker, (old, old))
        env.opener.serve(_PAYLOAD)

        hash_lookup._fetch_default_index()

        assert env.opener.calls == 2
        assert not env.marker.exists()
        assert hash_lookup._last_fetch_failure is None
        assert env.index_path.read_bytes() == _PAYLOAD


class TestOffline:
    @pytest.mark.parametrize("value", ["1", "true", "YES"])
    def test_offline_env_never_calls_opener(self, env: _Env, monkeypatch, value: str):
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, value)

        with pytest.raises(_IndexUnavailableError, match=hash_lookup._OFFLINE_ENV):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 0
        assert not env.index_path.exists()

    def test_offline_zero_does_not_disable_downloads(self, env: _Env, monkeypatch):
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "0")

        hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1

    def test_offline_still_loads_an_existing_verified_cache(self, env: _Env, monkeypatch):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(_PAYLOAD)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")

        index, _md5, _crc = hash_lookup.load_index(env.index_path)

        assert index == fx.build_synthetic_index()
        assert env.opener.calls == 0


# ---------------------------------------------------------------------------
# Loading: pin verification, quarantine, caps
# ---------------------------------------------------------------------------

class TestLoadVerification:
    def test_corrupt_cache_is_quarantined_and_refetched(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(b"{ not the pinned bytes")
        quarantine = env.index_path.with_name("hash_index.json.corrupt")
        quarantine.write_bytes(b"older quarantined copy")

        index, _md5, _crc = hash_lookup.load_index(env.index_path)

        assert index == fx.build_synthetic_index()
        assert env.opener.calls == 1
        assert env.index_path.read_bytes() == _PAYLOAD
        assert quarantine.read_bytes() == b"{ not the pinned bytes"  # previous copy overwritten

    def test_quarantine_refetch_follows_backoff_when_download_fails(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(b"bad")
        env.opener.fail(urllib.error.URLError("boom"))

        with pytest.raises(_IndexUnavailableError):
            hash_lookup.load_index(env.index_path)
        with pytest.raises(_IndexUnavailableError, match="not retrying"):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1
        assert not env.index_path.exists()
        assert env.index_path.with_name("hash_index.json.corrupt").read_bytes() == b"bad"

    def test_refetch_after_parse_failure_is_marked_verified(self, env: _Env, monkeypatch):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(_PAYLOAD)
        real_parse = hash_lookup._parse_index
        parse_calls: list[Path] = []

        def _flaky_parse(path: Path):
            parse_calls.append(path)
            if len(parse_calls) == 1:
                raise _IndexCorruptError("simulated corruption")
            return real_parse(path)

        monkeypatch.setattr(hash_lookup, "_parse_index", _flaky_parse)

        hash_lookup.load_index(env.index_path)
        assert env.opener.calls == 1
        assert env.sha_calls == [env.index_path]  # initial check only

        hash_lookup._index_cache.clear()
        hash_lookup.load_index(env.index_path)
        assert env.sha_calls == [env.index_path]  # refetched file not re-hashed

    def test_quarantine_failure_does_not_start_backoff(self, env: _Env, monkeypatch):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(b"bad")
        real_replace = os.replace

        def _locked(src, dst):
            if str(dst).endswith(".corrupt"):
                raise PermissionError("file in use")
            return real_replace(src, dst)

        monkeypatch.setattr(hash_lookup.os, "replace", _locked)

        with pytest.raises(_IndexUnavailableError, match="quarantine"):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 0
        assert not env.marker.exists()
        assert hash_lookup._last_fetch_failure is None

    def test_default_cache_vanishing_mid_load_is_index_unavailable(self, env: _Env, monkeypatch):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(_PAYLOAD)

        def _vanished(path: Path):
            raise FileNotFoundError("quarantined by another process")

        monkeypatch.setattr(hash_lookup, "_parse_index", _vanished)

        with pytest.raises(_IndexUnavailableError) as excinfo:
            hash_lookup.load_index(env.index_path)

        assert not isinstance(excinfo.value, FileNotFoundError)
        assert isinstance(excinfo.value.__cause__, FileNotFoundError)

    def test_pin_valid_but_unparseable_does_not_redownload_in_a_loop(self, env: _Env, monkeypatch):
        not_json = b"definitely not json"
        monkeypatch.setattr(hash_lookup, "_INDEX_SHA256", _sha256(not_json))
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(not_json)
        env.opener.serve(not_json)

        with pytest.raises(_IndexCorruptError):
            hash_lookup.load_index(env.index_path)
        with pytest.raises(_IndexUnavailableError):
            hash_lookup.load_index(env.index_path)

        assert env.opener.calls == 1  # one refetch, then backoff

    def test_pin_is_checked_once_per_process_per_file_version(self, env: _Env):
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(_PAYLOAD)

        hash_lookup.load_index(env.index_path)
        hash_lookup._index_cache.clear()
        hash_lookup.load_index(env.index_path)
        assert env.sha_calls == [env.index_path]

        new_mtime = env.index_path.stat().st_mtime + 5
        os.utime(env.index_path, (new_mtime, new_mtime))
        hash_lookup.load_index(env.index_path)
        assert env.sha_calls == [env.index_path, env.index_path]

    def test_freshly_downloaded_file_is_not_hashed_again(self, env: _Env):
        hash_lookup.load_index(env.index_path)

        assert env.sha_calls == []

    def test_oversized_default_cache_is_rejected_without_hashing(self, env: _Env, monkeypatch):
        monkeypatch.setattr(hash_lookup, "_MAX_INDEX_BYTES", len(_PAYLOAD) - 1)
        monkeypatch.setattr(hash_lookup, "_MAX_DOWNLOAD_BYTES", len(_PAYLOAD) - 1)
        env.cache_dir.mkdir(parents=True)
        env.index_path.write_bytes(_PAYLOAD)

        with pytest.raises(_IndexUnavailableError):
            hash_lookup.load_index(env.index_path)

        assert env.sha_calls == []
        assert env.index_path.with_name("hash_index.json.corrupt").exists()


class TestCustomIndexPath:
    def test_detector_warning_strips_control_characters(self):
        from formatscout.detector import _index_unavailable_warning

        text = _index_unavailable_warning(_IndexUnavailableError("bad\x1b[31m red\nline\x00end"))

        assert all(ch.isprintable() for ch in text)
        assert text.startswith(_WARNING_PREFIX) and text.endswith(_WARNING_SUFFIX)

    def test_custom_path_is_not_checked_against_pin(self, env: _Env, tmp_path: Path):
        custom = fx.write_synthetic_index(tmp_path)
        custom.write_text(json.dumps({"abc": {"title": "Custom", "era": "ps1"}}), encoding="utf-8")
        assert _sha256(custom.read_bytes()) != hash_lookup._INDEX_SHA256

        index, _md5, _crc = hash_lookup.load_index(custom)

        assert index == {"abc": {"title": "Custom", "era": "ps1"}}
        assert env.sha_calls == []
        assert env.opener.calls == 0
        assert custom.exists()

    def test_missing_custom_path_is_file_not_found_and_never_downloads(self, env: _Env, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            hash_lookup.load_index(tmp_path / "missing.json")

        assert env.opener.calls == 0

    def test_size_cap_applies_before_json_load(self, env: _Env, tmp_path: Path, monkeypatch):
        custom = fx.write_synthetic_index(tmp_path)
        monkeypatch.setattr(hash_lookup, "_MAX_INDEX_BYTES", custom.stat().st_size - 1)

        def _must_not_parse(*args, **kwargs):
            raise AssertionError("json.load called on an oversized file")

        monkeypatch.setattr(hash_lookup.json, "load", _must_not_parse)

        with pytest.raises(_IndexCorruptError, match="byte limit"):
            hash_lookup.load_index(custom)

    def test_corrupt_custom_index_raises_and_is_left_in_place(self, env: _Env, tmp_path: Path):
        custom = tmp_path / "custom.json"
        custom.write_text("{ truncated", encoding="utf-8")

        with pytest.raises(_IndexCorruptError, match="not valid JSON"):
            hash_lookup.load_index(custom)

        assert custom.exists()
        assert not custom.with_name("custom.json.corrupt").exists()

    def test_non_object_index_is_rejected(self, env: _Env, tmp_path: Path):
        custom = tmp_path / "custom.json"
        custom.write_text("[1, 2, 3]", encoding="utf-8")

        with pytest.raises(_IndexCorruptError):
            hash_lookup.load_index(custom)


# ---------------------------------------------------------------------------
# detect(): warning on index failure, classify()/verify() contract
# ---------------------------------------------------------------------------

class TestDetectWarning:
    def _nes(self, tmp_path: Path) -> Path:
        path = tmp_path / "game.nes"
        path.write_bytes(fx.UNINDEXED_CONTENT)
        return path

    def test_offline_adds_one_warning_and_keeps_heuristic_result(self, env: _Env, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, env.index_path)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")

        result = _detect(self._nes(tmp_path))

        assert result.era == "nes"
        assert result.confidence == 0.7
        warnings = _index_warnings(result)
        assert len(warnings) == 1
        assert warnings[0].endswith(_WARNING_SUFFIX)
        assert hash_lookup._OFFLINE_ENV in warnings[0]
        assert env.opener.calls == 0

    def test_repeated_detect_calls_each_warn_once_without_new_downloads(self, env: _Env, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, env.index_path)
        env.opener.fail(urllib.error.URLError("boom"))
        path = self._nes(tmp_path)

        first = _detect(path)
        second = _detect(path)

        for result in (first, second):
            assert result.era == "nes"
            assert len(_index_warnings(result)) == 1
        assert "download failed" in _index_warnings(first)[0]
        assert env.opener.calls == 1

    def test_warning_is_appended_after_existing_warnings(self, env: _Env, tmp_path: Path, monkeypatch):
        from formatscout import detector
        from formatscout.result import ScanResult

        fx.patch_detector_index(monkeypatch, env.index_path)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")
        monkeypatch.setattr(
            detector, "_detect_file",
            lambda path, dir_cache=None: ScanResult(
                title=None, platform=None, era="dos", confidence=0.35,
                reason="stub", warnings=["heuristic note"],
            ),
        )

        result = _detect(self._nes(tmp_path))

        assert result.warnings[0] == "heuristic note"
        assert len(result.warnings) == 2
        assert result.warnings[1].startswith(_WARNING_PREFIX)

    def test_corrupt_custom_index_also_warns(self, env: _Env, tmp_path: Path, monkeypatch):
        bad = tmp_path / "bad_index.json"
        bad.write_text("{ truncated", encoding="utf-8")
        fx.patch_detector_index(monkeypatch, bad)

        result = _detect(self._nes(tmp_path))

        assert result.era == "nes"
        assert len(_index_warnings(result)) == 1

    def test_no_warning_when_index_loads(self, env: _Env, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        result = _detect(self._nes(tmp_path))

        assert result.era == "nes"
        assert _index_warnings(result) == []
        assert result.warnings == []

    def test_no_warning_on_hash_hit(self, env: _Env, tmp_path: Path, monkeypatch):
        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))
        path = tmp_path / "game.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        result = _detect(path)

        assert result.era == "ps1"
        assert result.confidence == 1.0
        assert result.warnings == []

    def test_missing_custom_index_stays_quiet(self, env: _Env, tmp_path: Path, monkeypatch):
        """FileNotFoundError means "no index built at this custom path" (or the
        input vanished mid-scan), not an index download/trust problem, so it
        does not warn. The default path is downloaded instead and fails loudly."""
        fx.patch_detector_index(monkeypatch, tmp_path / "never_built.json")

        result = _detect(self._nes(tmp_path))

        assert result.era == "nes"
        assert result.warnings == []

    def test_input_file_read_error_is_not_blamed_on_the_index(self, env: _Env, tmp_path: Path, monkeypatch):
        from formatscout import detector

        fx.patch_detector_index(monkeypatch, fx.write_synthetic_index(tmp_path))

        def _unreadable(path, index_path):
            raise PermissionError("cannot read input")

        monkeypatch.setattr(detector._hash_lookup, "lookup", _unreadable)

        result = _detect(self._nes(tmp_path))

        assert result.era == "nes"
        assert _index_warnings(result) == []


class TestClassifyVerifyContract:
    """Index acquisition errors still escape classify() and verify()."""

    def test_classify_propagates_index_unavailable(self, env: _Env, tmp_path: Path, monkeypatch):
        from formatscout.classify import classify

        fx.patch_classify_index(monkeypatch, env.index_path)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")
        path = tmp_path / "game.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        with pytest.raises(_IndexUnavailableError):
            classify(path, "Some Title", "ps1")

    def test_verify_propagates_index_unavailable(self, env: _Env, tmp_path: Path, monkeypatch):
        from formatscout.verify import verify

        fx.patch_verify_index(monkeypatch, env.index_path)
        monkeypatch.setenv(hash_lookup._OFFLINE_ENV, "1")
        path = tmp_path / "game.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        with pytest.raises(_IndexUnavailableError):
            verify(path, "0" * 40)

    def test_missing_custom_index_still_degrades_to_empty(self, env: _Env, tmp_path: Path, monkeypatch):
        from formatscout.classify import classify

        fx.patch_classify_index(monkeypatch, tmp_path / "never_built.json")
        path = tmp_path / "game.bin"
        path.write_bytes(fx.VERIFIED_CONTENT)

        assert classify(path, "Some Title", "ps1").status == "not_in_index"
