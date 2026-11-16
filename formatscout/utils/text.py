"""Single-line sanitising of text that may embed server or OS output."""

MAX_REASON_CHARS = 120


def one_line(text: str, limit: int = MAX_REASON_CHARS) -> str:
    """*text* as a single printable line of at most *limit* characters."""
    # Control characters (newlines, ESC, ...) become spaces so a message that
    # embeds server or OS text cannot inject terminal escapes or extra lines.
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    line = " ".join(printable.split())
    if len(line) > limit:
        line = line[:limit - 3] + "..."
    return line
