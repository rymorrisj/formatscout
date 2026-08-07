from pathlib import Path

_XBOX_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_XBOX_MAGIC_OFFSET = 0x10000
_ISO9660_MAGIC = b"CD001"
_ISO9660_OFFSET = 0x8001
_DVD_RIP_SIZE_THRESHOLD = 4_000_000_000


class XboxDvdRipDetected(ValueError):
    """Raised when a launch target is identified as a raw Xbox DVD rip.

    Distinct from plain ValueError so the launch coordinator can offer an
    extract-xiso conversion action instead of surfacing a generic failure.
    """


def detect_xbox_image_type(path: str | Path) -> str:
    """
    Returns one of: "xiso", "dvd_rip", "iso9660", "unknown"

    Reads only the minimum bytes needed. Never raises on IO — returns "unknown"
    on any error.
    """
    try:
        p = Path(path)
        with p.open("rb") as fh:
            fh.seek(_XBOX_MAGIC_OFFSET)
            xbox_header = fh.read(20)
            if xbox_header == _XBOX_MAGIC:
                return "xiso"

            fh.seek(_ISO9660_OFFSET)
            iso_header = fh.read(5)
            if iso_header == _ISO9660_MAGIC:
                file_size = p.stat().st_size
                if file_size > _DVD_RIP_SIZE_THRESHOLD:
                    return "dvd_rip"
                return "iso9660"

            return "unknown"
    except Exception:
        return "unknown"


def is_xiso(path: str | Path) -> bool:
    """Returns True only if detect_xbox_image_type returns 'xiso'."""
    return detect_xbox_image_type(path) == "xiso"
