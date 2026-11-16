"""Pointer-file path containment (security F35).

A .cue FILE target and an AUTORUN.INF OPEN=/RUN= value are untrusted strings
from the scanned media. They must go through utils.safe_path.resolve_pointer()
before anything touches the filesystem, and a rejected one must yield no
signal plus a "pointer rejected: <reason>" warning.

Hostile cues are written to disk here, against the builders module's general
advice, only because every such test installs _install_fs_spy() first: the
spy raises before any filesystem call receives the hostile string, so even a
regression cannot stat, open or (on Windows) reach a UNC share with it.
"""

import builtins
import io
import os
from pathlib import Path

import pytest

from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.builders import cue as cue_builder
from formatscout.utils.safe_path import (
    MAX_COMPONENT_LENGTH,
    MAX_POINTER_LENGTH,
    WARNING_VALUE_MAX_CHARS,
    rejection_warning,
    resolve_pointer,
    sanitize_for_warning,
    validate_pointer_lexically,
)

_PATH_METHODS = (
    "stat", "lstat", "resolve", "open", "exists", "is_file", "is_dir",
    "is_symlink", "iterdir", "read_bytes", "read_text",
)
_MODULE_FUNCS = (
    (os, "stat"), (os, "lstat"), (os, "open"),
    (os.path, "realpath"), (os.path, "exists"), (os.path, "isfile"),
    (io, "open"), (builtins, "open"),
)


def _as_text(target: object) -> str:
    try:
        value = os.fspath(target)  # type: ignore[arg-type]
    except TypeError:
        return repr(target)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _install_fs_spy(monkeypatch, markers: list[str]) -> list[str]:
    """Wrap Path methods and os/io/builtins filesystem functions. Any call
    whose path argument contains one of *markers* is recorded and blocked
    with AssertionError; every other call passes through unchanged.

    Returns the list of recorded hits. Callers must assert it is empty:
    some code under test catches Exception, which would swallow the raise.
    """
    hits: list[str] = []

    def check(name: str, target: object) -> None:
        text = _as_text(target)
        if any(marker in text for marker in markers):
            hits.append(f"{name}({text!r})")
            raise AssertionError(f"filesystem call received hostile pointer: {name}({text!r})")

    def wrap_method(name: str) -> None:
        original = getattr(Path, name)

        def spy(self, *args, **kwargs):
            check(f"Path.{name}", self)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, name, spy)

    def wrap_func(module, name: str) -> None:
        original = getattr(module, name)

        def spy(target, *args, **kwargs):
            check(f"{module.__name__}.{name}", target)
            return original(target, *args, **kwargs)

        monkeypatch.setattr(module, name, spy)

    for method in _PATH_METHODS:
        wrap_method(method)
    for module, func in _MODULE_FUNCS:
        wrap_func(module, func)
    return hits


def _write_cue(directory: Path, target: str, name: str = "game.cue") -> Path:
    cue_path = directory / name
    cue_path.write_text(
        cue_builder.build_cue([(target, [(1, "MODE2/2352")])]), encoding="utf-8",
    )
    return cue_path


def _cue_bin_path(cue_path: Path, warnings: list[str] | None = None) -> Path | None:
    from formatscout.iso_detect import _cue_bin_path as impl
    return impl(cue_path, warnings)


def _assert_one_rejection(warnings: list[str], reason: str) -> None:
    rejected = [w for w in warnings if w.startswith("pointer rejected: ")]
    assert len(rejected) == 1, warnings
    assert rejected[0].startswith(f"pointer rejected: {reason}"), rejected[0]
    assert not any(ord(c) < 32 or ord(c) == 127 for c in rejected[0])


_OVERLONG_TOTAL = "x" * (MAX_POINTER_LENGTH + 10) + ".bin"
_OVERLONG_COMPONENT = "sub/" + "y" * (MAX_COMPONENT_LENGTH + 1) + ".bin"

# (raw pointer, marker that would appear in any filesystem call made with it,
#  expected rejection reason)
_LEXICAL_CASES = [
    pytest.param(cue_builder.HOSTILE_ABSOLUTE_POSIX, "formatscout-test-nonexistent", "absolute path", id="absolute"),
    pytest.param(cue_builder.HOSTILE_PARENT_POSIX, "formatscout-test-nonexistent", "parent traversal", id="parent"),
    pytest.param(cue_builder.HOSTILE_PARENT_BACKSLASH, "formatscout-test-nonexistent", "parent traversal", id="parent_bs"),
    pytest.param(cue_builder.HOSTILE_UNC, "example.invalid", "UNC path", id="unc"),
    pytest.param("//example.invalid/share/track.bin", "example.invalid", "UNC path", id="unc_fwd"),
    pytest.param(cue_builder.HOSTILE_DRIVE, "formatscout-test-nonexistent", "drive letter", id="drive"),
    pytest.param(cue_builder.HOSTILE_NUL, "\x00", "NUL byte", id="nul"),
    pytest.param("sub/CON.bin", "CON.bin", "device name", id="device_ext"),
    pytest.param("lpt1", "lpt1", "device name", id="device_bare"),
    pytest.param("track.bin:hidden", ":hidden", "colon", id="ads"),
    pytest.param(_OVERLONG_TOTAL, "x" * 300, "too long", id="overlong"),
    pytest.param(_OVERLONG_COMPONENT, "y" * (MAX_COMPONENT_LENGTH + 1), "component too long", id="longcomp"),
]


class TestLexicalValidation:
    """validate_pointer_lexically() is pure string inspection."""

    @pytest.mark.parametrize("raw, reason", [
        ("", "empty"),
        ("a\x1fb.bin", "control character"),
        ("a\x7fb.bin", "control character"),
        ("\\\\?\\C:\\track.bin", "UNC path"),
        ("\\track.bin", "absolute path"),
        ("c:track.bin", "drive letter"),
        ("sub/.../track.bin", "parent traversal"),
        ("sub/.. /track.bin", "parent traversal"),
        ("Con .bin", "device name"),
        ("aux.tar.gz", "device name"),
        ("COM9.bin", "device name"),
        ("COM0.bin", "device name"),
        ("lpt0", "device name"),
        ("sub/NUL", "device name"),
    ])
    def test_rejects(self, raw: str, reason: str):
        assert validate_pointer_lexically(raw) == reason

    @pytest.mark.parametrize("raw", [
        "track.bin",
        "my game (track 01).bin",
        "sub dir/track.bin",
        "sub\\track.bin",
        "./track.bin",
        "CONSOLE.bin",
        "COM10.bin",
        "con2.bin",
        "..track.bin",
    ])
    def test_accepts(self, raw: str):
        assert validate_pointer_lexically(raw) is None

    def test_warning_is_sanitized_and_truncated(self):
        raw = "\x1b[31m" + "a" * 500 + "\x00\r\n"
        message = rejection_warning(raw, "control character")
        assert message.startswith("pointer rejected: control character")
        assert not any(ord(c) < 32 for c in message)
        assert len(sanitize_for_warning(raw)) == WARNING_VALUE_MAX_CHARS + len("...")

    def test_warning_strips_format_and_non_printable_characters(self):
        # RLO bidi override, zero-width space/joiner, BOM, line separator,
        # private-use and lone-surrogate code points.
        hostile = "\u202egame\u200b\u200d\ufeff\u2028\ue000\ud800.bin"
        assert sanitize_for_warning(hostile) == "game.bin"
        message = rejection_warning(hostile, "colon")
        assert all(c == " " or c.isprintable() for c in message)

    def test_warning_keeps_ordinary_text(self):
        assert sanitize_for_warning("My Game (Disc 1) \u00e9.bin") == "My Game (Disc 1) \u00e9.bin"


class TestCueLexicalRejection:
    @pytest.mark.parametrize("raw, marker, reason", _LEXICAL_CASES)
    def test_cue_bin_path_rejects_without_touching_filesystem(
        self, tmp_path: Path, monkeypatch, raw: str, marker: str, reason: str,
    ):
        cue_path = _write_cue(tmp_path, raw)
        hits = _install_fs_spy(monkeypatch, [marker])
        warnings: list[str] = []

        result = _cue_bin_path(cue_path, warnings)

        assert hits == []
        assert result is None
        _assert_one_rejection(warnings, reason)

    @pytest.mark.parametrize("raw, marker, reason", _LEXICAL_CASES)
    def test_resolve_pointer_rejects_without_touching_filesystem(
        self, tmp_path: Path, monkeypatch, raw: str, marker: str, reason: str,
    ):
        hits = _install_fs_spy(monkeypatch, [marker])
        resolution = resolve_pointer(tmp_path, raw)
        assert hits == []
        assert resolution.status == "rejected"
        assert resolution.path is None
        assert resolution.reason == reason

    def test_detect_cue_returns_no_signal_with_warning(self, tmp_path: Path, monkeypatch):
        cue_path = _write_cue(tmp_path, cue_builder.HOSTILE_UNC)
        hits = _install_fs_spy(monkeypatch, ["example.invalid"])
        from formatscout.iso_detect import detect_cue

        result = detect_cue(cue_path)

        assert hits == []
        assert result.era is None
        assert result.confidence == 0.0
        assert result.reason == "no .bin file found for .cue sheet"
        # The pre-existing warning stays first; the rejection is appended.
        assert "game.cue" in result.warnings[0]
        _assert_one_rejection(result.warnings, "UNC path")

    def test_hostile_first_file_falls_through_to_valid_second(self, tmp_path: Path, monkeypatch):
        good = tmp_path / "track02.bin"
        good.write_bytes(b"\x00" * 16)
        cue_path = tmp_path / "game.cue"
        cue_path.write_text(cue_builder.build_cue([
            (cue_builder.HOSTILE_PARENT_POSIX, [(1, "MODE2/2352")]),
            ("track02.bin", [(2, "AUDIO")]),
        ]), encoding="utf-8")
        hits = _install_fs_spy(monkeypatch, ["formatscout-test-nonexistent"])
        warnings: list[str] = []

        result = _cue_bin_path(cue_path, warnings)

        assert hits == []
        assert result == good.resolve()
        _assert_one_rejection(warnings, "parent traversal")

    def test_without_warning_list_rejection_is_logged(self, tmp_path: Path, caplog):
        cue_path = _write_cue(tmp_path, cue_builder.HOSTILE_ABSOLUTE_POSIX)
        with caplog.at_level("WARNING", logger="formatscout.iso_detect"):
            assert _cue_bin_path(cue_path) is None
        assert any("pointer rejected: absolute path" in r.getMessage() for r in caplog.records)


class TestCueValidTargets:
    def test_name_with_spaces(self, tmp_path: Path):
        target = tmp_path / "My Game (Track 01).bin"
        target.write_bytes(b"\x00" * 16)
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(tmp_path, target.name), warnings) == target.resolve()
        assert warnings == []

    @pytest.mark.parametrize("pointer", ["data/sub dir/track.bin", "data\\sub dir\\track.bin"])
    def test_subdirectory_with_either_separator(self, tmp_path: Path, pointer: str):
        target = tmp_path / "data" / "sub dir" / "track.bin"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"\x00" * 16)
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(tmp_path, pointer), warnings) == target.resolve()
        assert warnings == []

    def test_detect_cue_end_to_end_through_subdirectory(self, tmp_path: Path):
        target = tmp_path / "disc" / "track 01.bin"
        target.parent.mkdir()
        target.write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        from formatscout.iso_detect import detect_cue

        result = detect_cue(_write_cue(tmp_path, "disc/track 01.bin"))

        assert result.era == "dreamcast"
        assert result.warnings == []

    def test_missing_target_is_silent(self, tmp_path: Path):
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(tmp_path, "absent.bin"), warnings) is None
        assert warnings == []

    def test_directory_target_is_rejected(self, tmp_path: Path):
        (tmp_path / "track.bin").mkdir()
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(tmp_path, "track.bin"), warnings) is None
        _assert_one_rejection(warnings, "not a regular file")


def _symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def _record_opens(monkeypatch, block: str | None = None) -> list[str]:
    """Record every open() target. A target containing *block* is recorded
    and then refused with AssertionError instead of being opened."""
    opened: list[str] = []

    def note(target: object) -> None:
        text = _as_text(target)
        opened.append(text)
        if block is not None and block in text:
            raise AssertionError(f"open() reached a target that must not be opened: {text!r}")

    for module in (io, builtins, os):
        original = module.open

        def spy(target, *args, _original=original, **kwargs):
            note(target)
            return _original(target, *args, **kwargs)

        monkeypatch.setattr(module, "open", spy)
    original_path_open = Path.open

    def path_spy(self, *args, **kwargs):
        note(self)
        return original_path_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", path_spy)
    return opened


class TestSymlinks:
    def test_file_symlink_escaping_base_is_rejected(self, tmp_path: Path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.bin"
        secret.write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        disc = tmp_path / "disc"
        disc.mkdir()
        _symlink_or_skip(disc / "link.bin", secret)
        cue_path = _write_cue(disc, "link.bin")
        opened = _record_opens(monkeypatch)
        from formatscout.iso_detect import detect_cue

        result = detect_cue(cue_path)

        assert result.era is None
        _assert_one_rejection(result.warnings, "escapes base directory")
        assert not any("secret.bin" in p for p in opened)

    def test_directory_symlink_escaping_base_is_rejected(self, tmp_path: Path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.bin").write_bytes(b"\x00" * 16)
        disc = tmp_path / "disc"
        disc.mkdir()
        _symlink_or_skip(disc / "sub", outside, target_is_directory=True)
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(disc, "sub/secret.bin"), warnings) is None
        _assert_one_rejection(warnings, "escapes base directory")

    def test_symlink_staying_inside_base_is_allowed(self, tmp_path: Path):
        real = tmp_path / "real.bin"
        real.write_bytes(b"\x00" * 16)
        _symlink_or_skip(tmp_path / "alias.bin", real)
        warnings: list[str] = []
        assert _cue_bin_path(_write_cue(tmp_path, "alias.bin"), warnings) == real.resolve()
        assert warnings == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable")
class TestFifo:
    def test_fifo_target_is_rejected_and_never_opened(self, tmp_path: Path, monkeypatch):
        fifo = tmp_path / "pipe.bin"
        os.mkfifo(fifo)
        cue_path = _write_cue(tmp_path, "pipe.bin")
        # Blocking: opening a FIFO with no writer would hang the test.
        opened = _record_opens(monkeypatch, block="pipe.bin")
        from formatscout.iso_detect import detect_cue

        result = detect_cue(cue_path)

        assert not any("pipe.bin" in p for p in opened)
        assert result.era is None
        _assert_one_rejection(result.warnings, "not a regular file")


_SIBLING_CUES = [
    pytest.param(True, id="file_line_names_sibling"),
    pytest.param(False, id="no_file_line"),
]


def _write_sibling_cue(directory: Path, with_file_line: bool) -> Path:
    if with_file_line:
        return _write_cue(directory, "game.bin")
    cue_path = directory / "game.cue"
    cue_path.write_text("  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n", encoding="utf-8")
    return cue_path


class TestSiblingFallback:
    """detect_cue()'s same-stem <cue stem>.bin fallback goes through
    resolve_pointer() as well, so a hostile sibling is never opened."""

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable")
    @pytest.mark.parametrize("with_file_line", _SIBLING_CUES)
    def test_fifo_sibling_is_rejected_and_never_opened(
        self, tmp_path: Path, monkeypatch, with_file_line: bool,
    ):
        os.mkfifo(tmp_path / "game.bin")
        cue_path = _write_sibling_cue(tmp_path, with_file_line)
        opened = _record_opens(monkeypatch, block="game.bin")
        from formatscout.iso_detect import detect_cue

        result = detect_cue(cue_path)

        assert not any("game.bin" in p for p in opened)
        assert result.era is None
        assert result.reason == "no .bin file found for .cue sheet"
        _assert_one_rejection(result.warnings, "not a regular file")

    @pytest.mark.parametrize("with_file_line", _SIBLING_CUES)
    def test_out_of_base_symlink_sibling_is_rejected_and_never_opened(
        self, tmp_path: Path, monkeypatch, with_file_line: bool,
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.bin"
        secret.write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        disc = tmp_path / "disc"
        disc.mkdir()
        _symlink_or_skip(disc / "game.bin", secret)
        cue_path = _write_sibling_cue(disc, with_file_line)
        opened = _record_opens(monkeypatch, block="secret.bin")
        from formatscout.iso_detect import detect_cue

        result = detect_cue(cue_path)

        assert not any("secret.bin" in p for p in opened)
        assert result.era is None
        _assert_one_rejection(result.warnings, "escapes base directory")

    def test_regular_sibling_still_used(self, tmp_path: Path):
        (tmp_path / "game.bin").write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        from formatscout.iso_detect import detect_cue

        result = detect_cue(_write_sibling_cue(tmp_path, False))

        assert result.era == "dreamcast"
        assert result.warnings == []


# A single leading separator is root-relative for AUTORUN.INF (see
# TestAutorunRootRelative), so "/x/evil.exe" is no longer a hostile case here;
# the root-relative forms that must still be rejected are listed below.
_AUTORUN_HOSTILE = [
    pytest.param("..\\..\\formatscout-test-nonexistent\\evil.exe", "formatscout-test-nonexistent", "parent traversal", id="parent"),
    pytest.param("\\\\example.invalid\\share\\evil.exe", "example.invalid", "UNC path", id="unc"),
    pytest.param("//example.invalid/share/evil.exe", "example.invalid", "UNC path", id="unc_fwd"),
    pytest.param("/\\example.invalid\\share\\evil.exe", "example.invalid", "UNC path", id="unc_mixed"),
    pytest.param("\\\\\\formatscout-test-nonexistent\\evil.exe", "formatscout-test-nonexistent", "UNC path", id="triple_sep"),
    pytest.param("Z:\\formatscout-test-nonexistent\\evil.exe", "formatscout-test-nonexistent", "drive letter", id="drive"),
    pytest.param("\\Z:\\formatscout-test-nonexistent\\evil.exe", "formatscout-test-nonexistent", "drive letter", id="root_drive"),
    pytest.param("\\..\\formatscout-test-nonexistent\\evil.exe", "formatscout-test-nonexistent", "parent traversal", id="root_parent"),
    pytest.param("/sub/../../formatscout-test-nonexistent/evil.exe", "formatscout-test-nonexistent", "parent traversal", id="root_nested_parent"),
    pytest.param("CON.exe", "CON.exe", "device name", id="device"),
    pytest.param("\\CON.exe", "CON.exe", "device name", id="root_device"),
    pytest.param("setup.exe:stream.exe", ":stream", "colon", id="ads"),
    pytest.param("\\setup.exe:stream.exe", ":stream", "colon", id="root_ads"),
    pytest.param("\\set\x1bup.exe", "\x1b", "control character", id="root_control"),
    pytest.param("\\" + "x" * MAX_POINTER_LENGTH + ".exe", "x" * 300, "too long", id="root_overlong"),
]


class TestAutorunContainment:
    def _detect(self, root: Path):
        from formatscout.directory_detect import detect_directory
        return detect_directory(root)

    @pytest.mark.parametrize("raw, marker, reason", _AUTORUN_HOSTILE)
    def test_hostile_open_is_rejected_without_touching_filesystem(
        self, tmp_path: Path, monkeypatch, raw: str, marker: str, reason: str,
    ):
        (tmp_path / "AUTORUN.INF").write_text(f"[autorun]\nOPEN={raw}\n", encoding="utf-8")
        hits = _install_fs_spy(monkeypatch, [marker])

        result = self._detect(tmp_path)

        assert hits == []
        assert result.era is None
        _assert_one_rejection(result.warnings, reason)

    def test_rejection_warning_survives_heuristic_fallthrough(self, tmp_path: Path):
        (tmp_path / "AUTORUN.INF").write_text("[autorun]\nRUN=\\\\example.invalid\\s\\x.exe\n", encoding="utf-8")
        (tmp_path / "PS3_DISC.SFB").write_bytes(b"\x00")

        result = self._detect(tmp_path)

        assert result.era == "ps3"
        _assert_one_rejection(result.warnings, "UNC path")

    def test_valid_subdirectory_exe_still_detected(self, tmp_path: Path):
        exe = tmp_path / "bin" / "SETUP.EXE"
        exe.parent.mkdir()
        exe.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        (tmp_path / "AUTORUN.INF").write_text("[autorun]\nOPEN=bin\\SETUP.EXE\n", encoding="utf-8")

        result = self._detect(tmp_path)

        assert result.era == "winxp"
        assert result.warnings == []

    def test_symlink_escape_is_rejected(self, tmp_path: Path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "EVIL.EXE"
        secret.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        disc = tmp_path / "disc"
        disc.mkdir()
        _symlink_or_skip(disc / "SETUP.EXE", secret)
        (disc / "AUTORUN.INF").write_text("[autorun]\nOPEN=SETUP.EXE\n", encoding="utf-8")
        opened = _record_opens(monkeypatch)

        result = self._detect(disc)

        assert result.era is None
        _assert_one_rejection(result.warnings, "escapes base directory")
        assert not any("EVIL.EXE" in p for p in opened)


class TestAutorunRootRelative:
    """AUTORUN.INF OPEN=/RUN= values may start with one separator, meaning
    the disc root (the directory holding AUTORUN.INF). Cue FILE targets get
    no such allowance."""

    @pytest.mark.parametrize("raw", ["\\SETUP.EXE", "/SETUP.EXE", "\\sub\\SETUP.EXE", "/sub/SETUP.EXE"])
    def test_lexically_accepted_only_when_root_relative(self, raw: str):
        assert validate_pointer_lexically(raw, root_relative=True) is None
        assert validate_pointer_lexically(raw) == "absolute path"

    @pytest.mark.parametrize("raw, reason", [
        ("\\\\host\\share", "UNC path"),
        ("//host", "UNC path"),
        ("\\/host", "UNC path"),
        ("/\\host", "UNC path"),
        ("\\\\\\x", "UNC path"),
        ("\\\\?\\C:\\x", "UNC path"),
        ("\\..\\x", "parent traversal"),
        ("\\C:\\x", "drive letter"),
        ("\\CON", "device name"),
        ("\\sub\\nul.exe", "device name"),
        ("\\sub\\x:y", "colon"),
        ("\\", "empty"),
        ("\\a\x00b", "NUL byte"),
        ("\\a\x1fb", "control character"),
        ("\\" + "x" * MAX_POINTER_LENGTH, "too long"),
    ])
    def test_lexical_rejections(self, raw: str, reason: str):
        assert validate_pointer_lexically(raw, root_relative=True) == reason

    @pytest.mark.parametrize("raw, parts", [
        ("\\SETUP.EXE", ("SETUP.EXE",)),
        ("/SETUP.EXE", ("SETUP.EXE",)),
        ("\\sub\\SETUP.EXE", ("sub", "SETUP.EXE")),
    ])
    def test_resolves_under_base(self, tmp_path: Path, raw: str, parts: tuple[str, ...]):
        target = tmp_path.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"MZ")

        resolution = resolve_pointer(tmp_path, raw, root_relative=True)

        assert resolution.status == "ok"
        assert resolution.path == target.resolve()
        assert resolution.path.is_relative_to(tmp_path.resolve())

    def test_without_opt_in_leading_separator_is_rejected_even_if_target_exists(self, tmp_path: Path):
        (tmp_path / "SETUP.EXE").write_bytes(b"MZ")
        resolution = resolve_pointer(tmp_path, "\\SETUP.EXE")
        assert resolution.status == "rejected"
        assert resolution.reason == "absolute path"

    @pytest.mark.parametrize("raw, marker, reason", [
        pytest.param("\\\\example.invalid\\share", "example.invalid", "UNC path", id="unc"),
        pytest.param("//example.invalid", "example.invalid", "UNC path", id="unc_fwd"),
        pytest.param("\\\\\\formatscout-test-nonexistent", "formatscout-test-nonexistent", "UNC path", id="triple_sep"),
        pytest.param("\\..\\formatscout-test-nonexistent", "formatscout-test-nonexistent", "parent traversal", id="parent"),
        pytest.param("\\C:\\formatscout-test-nonexistent", "formatscout-test-nonexistent", "drive letter", id="drive"),
        pytest.param("\\CON", "CON", "device name", id="device"),
    ])
    def test_resolve_pointer_rejects_without_touching_filesystem(
        self, tmp_path: Path, monkeypatch, raw: str, marker: str, reason: str,
    ):
        hits = _install_fs_spy(monkeypatch, [marker])
        resolution = resolve_pointer(tmp_path, raw, root_relative=True)
        assert hits == []
        assert resolution.status == "rejected"
        assert resolution.path is None
        assert resolution.reason == reason

    @pytest.mark.parametrize("directive", [
        "OPEN=\\SETUP.EXE",
        "OPEN=/SETUP.EXE",
        'OPEN="\\SETUP.EXE"',
        "RUN=\\SETUP.EXE",
    ])
    def test_root_exe_detected_through_directory_detect(self, tmp_path: Path, directive: str):
        (tmp_path / "SETUP.EXE").write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        (tmp_path / "AUTORUN.INF").write_text(f"[autorun]\n{directive}\n", encoding="utf-8")
        from formatscout.directory_detect import detect_directory

        result = detect_directory(tmp_path)

        assert result.era == "winxp"
        assert result.warnings == []

    def test_root_subdirectory_exe_detected_through_directory_detect(self, tmp_path: Path):
        exe = tmp_path / "sub" / "SETUP.EXE"
        exe.parent.mkdir()
        exe.write_bytes(fx.build_pe_header(major_os_version=4, subsystem=2))
        (tmp_path / "AUTORUN.INF").write_text("[autorun]\nOPEN=\\sub\\SETUP.EXE\n", encoding="utf-8")
        from formatscout.directory_detect import detect_directory

        result = detect_directory(tmp_path)

        assert result.era == "win98"
        assert result.warnings == []

    def test_missing_root_relative_target_is_silent(self, tmp_path: Path):
        (tmp_path / "AUTORUN.INF").write_text("[autorun]\nOPEN=\\ABSENT.EXE\n", encoding="utf-8")
        from formatscout.directory_detect import detect_directory

        result = detect_directory(tmp_path)

        assert not any(w.startswith("pointer rejected: ") for w in result.warnings)

    def test_root_relative_symlink_escape_is_rejected(self, tmp_path: Path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "EVIL.EXE"
        secret.write_bytes(fx.build_pe_header(major_os_version=5, subsystem=3))
        disc = tmp_path / "disc"
        disc.mkdir()
        _symlink_or_skip(disc / "SETUP.EXE", secret)
        (disc / "AUTORUN.INF").write_text("[autorun]\nOPEN=\\SETUP.EXE\n", encoding="utf-8")
        opened = _record_opens(monkeypatch)
        from formatscout.directory_detect import detect_directory

        result = detect_directory(disc)

        assert result.era is None
        _assert_one_rejection(result.warnings, "escapes base directory")
        assert not any("EVIL.EXE" in p for p in opened)

    @pytest.mark.parametrize("raw", ["\\track.bin", "/track.bin"])
    def test_cue_file_with_leading_separator_still_rejected(self, tmp_path: Path, monkeypatch, raw: str):
        # The target exists at the base, so only the lexical check can stop it.
        (tmp_path / "track.bin").write_bytes(fx.DREAMCAST_IP_BIN_BLOB)
        cue_path = _write_cue(tmp_path, raw)
        opened = _record_opens(monkeypatch)
        warnings: list[str] = []

        assert _cue_bin_path(cue_path, warnings) is None
        _assert_one_rejection(warnings, "absolute path")
        assert not any(p.endswith("track.bin") for p in opened)
