"""Internal Xbox optical-media identification, used only by iso_detect.py's
detect_iso(). Not part of this package's public surface, see __init__.py and
README.md, the extract-xiso signal this module produces reaches callers only
through ScanResult.requires_extraction on the standard detect()/classify()
result objects, never by importing this module directly.
"""

from pathlib import Path

_XBOX_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_XBOX_MAGIC_OFFSET = 0x10000
_ISO9660_MAGIC = b"CD001"
_ISO9660_OFFSET = 0x8001
_DVD_RIP_SIZE_THRESHOLD = 4_000_000_000


def detect_xbox_image_type(path: str | Path) -> str:
    """
    Returns one of: "xiso", "dvd_rip", "iso9660", "unknown"

    Reads only the minimum bytes needed at two fixed offsets. Never raises on
    IO, returns "unknown" on any error.
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
