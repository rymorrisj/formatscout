"""Self-tests for the autouse hermetic-environment fixture in conftest.py.

Every test that deliberately trips the guard clears the recorder afterwards,
otherwise the fixture's teardown would (correctly) fail it. The target is a
reserved .invalid name and the patched functions raise before any DNS lookup
or connect, so no traffic is ever attempted.
"""

import os
import socket
import urllib.request
from pathlib import Path

import pytest

TARGET = ("example.invalid", 80)


class TestNetworkBlocked:
    def test_create_connection_blocked_and_recorded(self, network_guard: list[str]):
        with pytest.raises(AssertionError, match="network access blocked"):
            socket.create_connection(TARGET)
        assert len(network_guard) == 1 and "example.invalid" in network_guard[0]
        network_guard.clear()

    def test_socket_connect_blocked_and_recorded(self, network_guard: list[str]):
        sock = socket.socket()
        try:
            with pytest.raises(AssertionError, match="network access blocked"):
                sock.connect(TARGET)
            with pytest.raises(AssertionError, match="network access blocked"):
                sock.connect_ex(TARGET)
        finally:
            sock.close()
        assert len(network_guard) == 2
        network_guard.clear()

    def test_urlopen_blocked_and_recorded(self, network_guard: list[str]):
        with pytest.raises(AssertionError, match="network access blocked"):
            urllib.request.urlopen("http://example.invalid/")
        assert len(network_guard) == 1 and "example.invalid" in network_guard[0]
        network_guard.clear()

    def test_fetch_default_index_blocked_and_recorded(self, network_guard: list[str]):
        from formatscout.hashing import hash_lookup

        with pytest.raises(AssertionError, match="network access blocked"):
            hash_lookup._fetch_default_index()
        assert len(network_guard) == 1
        network_guard.clear()

    def test_unrecorded_state_starts_empty(self, network_guard: list[str]):
        assert network_guard == []


class TestHomeIsolation:
    def test_env_vars_point_inside_tmp(self, tmp_path_factory):
        base = tmp_path_factory.getbasetemp().resolve()
        for var in ("HOME", "USERPROFILE", "XDG_CACHE_HOME", "LOCALAPPDATA"):
            value = Path(os.environ[var]).resolve()
            assert base in value.parents, var

    def test_path_home_resolves_to_tmp(self, tmp_path_factory):
        base = tmp_path_factory.getbasetemp().resolve()
        assert base in Path.home().resolve().parents


class TestIndexIsolation:
    def test_default_index_path_is_nonexistent_under_home(self):
        from formatscout.hashing import hash_lookup

        home = Path(os.environ["HOME"]).resolve()
        assert hash_lookup._CACHE_DIR.resolve().is_relative_to(home)
        assert hash_lookup._DEFAULT_INDEX_PATH.resolve().is_relative_to(home)
        assert not hash_lookup._DEFAULT_INDEX_PATH.exists()

    @pytest.mark.parametrize("module_name", ["detector", "classify", "verify"])
    def test_module_index_path_is_nonexistent_under_home(self, module_name: str):
        import importlib

        module = importlib.import_module(f"formatscout.{module_name}")
        home = Path(os.environ["HOME"]).resolve()
        assert module._INDEX_PATH.resolve().is_relative_to(home)
        assert not module._INDEX_PATH.exists()
