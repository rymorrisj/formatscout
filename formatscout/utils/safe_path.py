"""Containment checks for paths named inside pointer files.

A pointer file (a .cue sheet's FILE line, an AUTORUN.INF OPEN=/RUN= value)
names another file by a string that comes from the scanned media, so it is
untrusted input. Joining it to a base directory unchecked would let it name
an absolute path, climb out with "..", or, on Windows, reach a UNC share
(which leaks the user's NTLM hash to whoever runs that share).

resolve_pointer() is the single entry point. It runs in two stages:

1. Lexical validation of the raw string, with no filesystem access at all,
   so a hostile string is never handed to stat(), open() or resolve().
2. Strict resolution against the base directory: the target must exist,
   resolve (following symlinks) to somewhere inside the resolved base, and
   be a regular file.

Callers must open only PointerResolution.path afterwards, never a path they
rebuild from the raw string. No exception escapes resolve_pointer().

root_relative=True (AUTORUN.INF OPEN=/RUN= only) treats exactly one leading
separator as "the disc root", i.e. the base directory. Cue FILE targets never
pass it, so a leading separator there is still rejected as absolute.
"""

import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

MAX_POINTER_LENGTH = 1024
MAX_COMPONENT_LENGTH = 255
WARNING_VALUE_MAX_CHARS = 120

_SEPARATORS = re.compile(r"[\\/]")
_SEPARATOR_CHARS = ("\\", "/")
# Any two leading separators: a UNC share, a \\?\ or \\.\ device path, or a
# mixed-slash form Windows treats the same way.
_UNC_PREFIXES = ("\\\\", "//", "\\/", "/\\")

# Windows reserved device names. A component is a device if its part before
# the first "." (trailing spaces stripped, case-insensitive) is one of these,
# so "con", "CON.txt" and "Con .bin" all count. COM0/LPT0 and the superscript
# digit forms are included too: Win32 reserves the superscripts, and the 0
# forms are rejected defensively since some Windows versions treat them as
# devices.
_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "0123456789¹²³"}
)

PointerStatus = Literal["ok", "missing", "rejected"]


@dataclass(frozen=True, slots=True)
class PointerResolution:
    """Outcome of resolve_pointer().

    status:
        "ok": path is the resolved, contained, regular-file target.
        "missing": the pointer passed every check but names nothing on disk.
            Not a security event, callers treat it like an absent file.
        "rejected": the pointer failed a lexical or containment check, or
            could not be resolved; reason says why. Callers must not touch
            the target and should surface rejection_warning().
    """
    status: PointerStatus
    path: Path | None
    reason: str | None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _is_control(char: str) -> bool:
    return unicodedata.category(char) == "Cc"


def _is_safe_for_warning(char: str) -> bool:
    """True for a character that can be shown verbatim in a warning.

    Rejects control (Cc) and format (Cf: bidi overrides, zero-width
    characters, BOM) characters explicitly, plus everything else
    str.isprintable() rejects (surrogates, private use, unassigned, line and
    paragraph separators, non-ASCII spaces). The plain ASCII space is kept.
    """
    if char == " ":
        return True
    if unicodedata.category(char) in ("Cc", "Cf"):
        return False
    return char.isprintable()


def sanitize_for_warning(raw: str) -> str:
    """Strip control, format (bidi/zero-width) and other non-printable
    characters from *raw* and truncate it to WARNING_VALUE_MAX_CHARS, for
    safe inclusion in a warning message."""
    cleaned = "".join(c for c in raw if _is_safe_for_warning(c))
    if len(cleaned) > WARNING_VALUE_MAX_CHARS:
        return cleaned[:WARNING_VALUE_MAX_CHARS] + "..."
    return cleaned


def rejection_warning(raw: str, reason: str) -> str:
    """Warning text for a rejected pointer: "pointer rejected: <reason>"
    followed by the sanitized raw value."""
    return f'pointer rejected: {reason}: "{sanitize_for_warning(raw)}"'


def _is_device_name(component: str) -> bool:
    return component.split(".", 1)[0].rstrip(" ").upper() in _DEVICE_NAMES


def validate_pointer_lexically(raw: str, *, root_relative: bool = False) -> str | None:
    """Return a short rejection reason for *raw*, or None if it is acceptable.

    Pure string inspection, never touches the filesystem. Both "/" and "\\"
    are treated as separators on every platform.

    With root_relative=True a single leading separator is allowed and means
    the base directory (AUTORUN.INF's "\\SETUP.EXE" form). The overall length
    and the doubled-separator (UNC) check run on the raw value first; every
    other check then runs on the remainder after that one separator, so a
    remainder that is itself absolute, a drive, "..", a device name, etc. is
    still rejected.
    """
    if root_relative and raw[:1] in _SEPARATOR_CHARS:
        if len(raw) > MAX_POINTER_LENGTH:
            return "too long"
        if raw[:2] in _UNC_PREFIXES:
            return "UNC path"
        return _validate_relative(raw[1:])
    return _validate_relative(raw)


def _strip_root_prefix(raw: str) -> str:
    """Drop exactly one leading separator. Only call on a value that already
    passed validate_pointer_lexically(raw, root_relative=True)."""
    return raw[1:] if raw[:1] in _SEPARATOR_CHARS else raw


def _validate_relative(raw: str) -> str | None:
    """The full lexical check set for a value that must be base-relative."""
    if not raw:
        return "empty"
    if len(raw) > MAX_POINTER_LENGTH:
        return "too long"
    if "\x00" in raw:
        return "NUL byte"
    if any(_is_control(c) for c in raw):
        return "control character"
    if raw[:2] in _UNC_PREFIXES:
        return "UNC path"
    if raw[0] in _SEPARATOR_CHARS:
        return "absolute path"
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        return "drive letter"
    if ":" in raw:
        return "colon"
    for component in _SEPARATORS.split(raw):
        if len(component) > MAX_COMPONENT_LENGTH:
            return "component too long"
        # Win32 strips trailing dots and spaces from a component, so "..."
        # or ".. " can behave like "..". Reject every dot/space-only
        # component containing "..".
        if ".." in component and not component.strip(" ."):
            return "parent traversal"
        if component and _is_device_name(component):
            return "device name"
    return None


def resolve_pointer(base: Path, raw: str, *, root_relative: bool = False) -> PointerResolution:
    """Validate *raw* and resolve it against directory *base*.

    root_relative=True accepts one leading separator as meaning *base* (see
    validate_pointer_lexically()); it is for AUTORUN.INF values only.

    Lexical rejection happens before any filesystem call. Otherwise the
    joined path is resolved strictly (symlinks followed), must stay inside
    the resolved base, and must be a regular file (not a directory, FIFO or
    device). OSError (and the RuntimeError older Pythons raise on a symlink
    loop) during resolution is a rejection, except a plain "does not exist",
    which is reported as "missing".
    """
    reason = validate_pointer_lexically(raw, root_relative=root_relative)
    if reason is not None:
        return PointerResolution("rejected", None, reason)

    relative = _strip_root_prefix(raw) if root_relative else raw
    parts = [p for p in _SEPARATORS.split(relative) if p not in ("", ".")]
    if not parts:
        return PointerResolution("rejected", None, "no file component")

    try:
        base_resolved = base.resolve(strict=True)
        target = base_resolved.joinpath(*parts).resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return PointerResolution("missing", None, "not found")
    except (OSError, RuntimeError, ValueError) as exc:
        return PointerResolution("rejected", None, f"unresolvable ({type(exc).__name__})")

    if not target.is_relative_to(base_resolved):
        return PointerResolution("rejected", None, "escapes base directory")

    try:
        mode = target.stat().st_mode
    except OSError as exc:
        return PointerResolution("rejected", None, f"unresolvable ({type(exc).__name__})")
    if not stat.S_ISREG(mode):
        return PointerResolution("rejected", None, "not a regular file")

    return PointerResolution("ok", target, None)
