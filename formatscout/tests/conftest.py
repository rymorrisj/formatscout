"""Hermetic-test fixtures applied to every test in formatscout/tests/.

Why each patch exists:

* HOME/USERPROFILE/XDG_CACHE_HOME/LOCALAPPDATA -> a fresh tmp dir, so nothing
  can read or write the developer's real home (hash_lookup caches the ~88MB
  index under ~/.formatscout). Child processes inherit this env too.
* Network block: socket connect/connect_ex/create_connection and
  urllib.request.urlopen record the attempt and raise AssertionError. detect()
  wraps its body in `except Exception`, which would swallow that error, so
  the autouse fixture also fails the test at teardown if any attempt was
  recorded and not explicitly cleared (test_network_guard.py clears its own).
  Note: hash_lookup downloads via urllib.request.build_opener().open, which
  does not go through urllib.request.urlopen, so only the socket patches cover
  it; tests of the download patch hash_lookup._open_index_url instead.
* hash_lookup._CACHE_DIR/_DEFAULT_INDEX_PATH/_fetch_default_index -> a
  nonexistent tmp path and a raising stub, so no code path can download.
* hash_lookup's process-level backoff / verified-file / log-once state is
  reset for each test.
* detector/classify/verify._INDEX_PATH are bound to the real home at import
  time (collection happens before any fixture runs), so they are re-pointed
  here via the shared fx.patch_* helpers. They get a nonexistent path that
  differs from _DEFAULT_INDEX_PATH on purpose: an unpatched call then gets the
  quiet FileNotFoundError path instead of a fetch attempt.

Tests that call fx.patch_* or monkeypatch.setattr themselves use this same
function-scoped monkeypatch and run after this setup, so their values win and
undo is LIFO. Nothing here is session-scoped.
"""

import importlib
import socket
import urllib.request
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx


@pytest.fixture
def network_guard() -> list[str]:
    """Per-test list of blocked network/fetch attempts. Clear it in a test that
    deliberately triggers the guard, otherwise teardown fails the test."""
    return []


def _blocker(name: str, attempts: list[str], skip_self: bool = False):
    def _blocked(*args, **kwargs):
        shown = args[1:] if skip_self else args
        target = f"{name}{shown!r}{kwargs!r}"
        attempts.append(target)
        raise AssertionError(f"network access blocked in tests: {target}")
    return _blocked


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch, tmp_path_factory, network_guard):
    # importlib, not `from formatscout import classify, verify`: the package
    # __init__ rebinds those names to the classify()/verify() functions.
    classify = importlib.import_module("formatscout.classify")
    detector = importlib.import_module("formatscout.detector")
    verify = importlib.import_module("formatscout.verify")
    from formatscout.hashing import hash_lookup

    # Separate from the test's own tmp_path so directory scans never see it.
    home = tmp_path_factory.mktemp("home")
    for var in ("HOME", "USERPROFILE", "XDG_CACHE_HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(var, str(home))

    monkeypatch.setattr(socket.socket, "connect", _blocker("socket.connect", network_guard, True))
    monkeypatch.setattr(socket.socket, "connect_ex", _blocker("socket.connect_ex", network_guard, True))
    monkeypatch.setattr(socket, "create_connection", _blocker("socket.create_connection", network_guard))
    monkeypatch.setattr(urllib.request, "urlopen", _blocker("urllib.request.urlopen", network_guard))

    cache_dir = home / ".formatscout"
    monkeypatch.setattr(hash_lookup, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(hash_lookup, "_DEFAULT_INDEX_PATH", cache_dir / "hash_index.json")
    monkeypatch.setattr(
        hash_lookup, "_fetch_default_index", _blocker("hash_lookup._fetch_default_index", network_guard),
    )

    # Process-level index state (backoff, per-version checks, log-once window)
    # starts empty in every test; monkeypatch restores the originals.
    monkeypatch.setattr(hash_lookup, "_last_fetch_failure", None)
    monkeypatch.setattr(hash_lookup, "_failure_logged_at", None)
    monkeypatch.setattr(hash_lookup, "_verified_default", {})

    no_index: Path = cache_dir / "no_index.json"
    fx.patch_detector_index(monkeypatch, no_index)
    fx.patch_classify_index(monkeypatch, no_index)
    fx.patch_verify_index(monkeypatch, no_index)
    assert detector._INDEX_PATH == classify._INDEX_PATH == verify._INDEX_PATH == no_index

    yield

    if network_guard:
        pytest.fail(f"network/fetch attempts recorded during test (possibly swallowed): {network_guard}")
