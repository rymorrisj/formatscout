"""CUE sheet text builders (builders only).

Never pass a hostile cue from this module to detect(), _cue_bin_path() or any
other library function: they touch the filesystem and, on Windows, a UNC
FILE target reaches the network. Every function here returns a string; never
write hostile cues to disk.
"""


def cue_file_line(name: str, *, quoted: bool = True, file_type: str = "BINARY") -> str:
    """One FILE line, e.g. FILE "track.bin" BINARY."""
    target = f'"{name}"' if quoted else name
    return f"FILE {target} {file_type}"


def build_cue(files: list[tuple[str, list[tuple[int, str]]]], *, quoted: bool = True) -> str:
    """Build a cue sheet from (file name, [(track number, mode), ...]) entries.

    Each track gets "TRACK nn MODE" and "INDEX 01 00:00:00" lines.
    """
    lines: list[str] = []
    for name, tracks in files:
        lines.append(cue_file_line(name, quoted=quoted))
        for number, mode in tracks:
            lines.append(f"  TRACK {number:02d} {mode}")
            lines.append("    INDEX 01 00:00:00")
    return "\n".join(lines) + "\n"


def _hostile(target: str) -> str:
    return build_cue([(target, [(1, "MODE2/2352")])])


HOSTILE_ABSOLUTE_POSIX = "/formatscout-test-nonexistent/track.bin"
HOSTILE_PARENT_POSIX = "../../formatscout-test-nonexistent/track.bin"
HOSTILE_PARENT_BACKSLASH = "..\\..\\formatscout-test-nonexistent\\track.bin"
HOSTILE_UNC = "\\\\example.invalid\\share\\track.bin"
HOSTILE_DRIVE = "Z:\\formatscout-test-nonexistent\\track.bin"
HOSTILE_NUL = "track\x00.bin"


def hostile_cue_absolute_posix() -> str:
    return _hostile(HOSTILE_ABSOLUTE_POSIX)


def hostile_cue_parent_traversal() -> str:
    return _hostile(HOSTILE_PARENT_POSIX)


def hostile_cue_parent_traversal_backslash() -> str:
    return _hostile(HOSTILE_PARENT_BACKSLASH)


def hostile_cue_unc() -> str:
    return _hostile(HOSTILE_UNC)


def hostile_cue_drive_letter() -> str:
    return _hostile(HOSTILE_DRIVE)


def hostile_cue_embedded_nul() -> str:
    return _hostile(HOSTILE_NUL)
