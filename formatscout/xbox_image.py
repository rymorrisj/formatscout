"""Internal Xbox optical-media identification, used only by iso_detect.py's
detect_iso(). Not part of this package's public surface, see __init__.py and
README.md, the extract-xiso signal this module produces reaches callers only
through ScanResult.requires_extraction on the standard detect()/classify()
result objects, never by importing this module directly.
"""

import logging
import struct
from pathlib import Path

from .constants import DVD_SIZE_THRESHOLD_BYTES

logger = logging.getLogger(__name__)

_XBOX_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_XBOX_MAGIC_OFFSET = 0x10000
_ISO9660_MAGIC = b"CD001"
_ISO9660_OFFSET = 0x8001


def detect_xbox_image_type(path: Path) -> str:
    """
    Returns one of: "xiso", "dvd_rip", "iso9660", "unknown"

    Reads only the minimum bytes needed at two fixed offsets. Never raises on
    IO, returns "unknown" on any error.

    The dvd_rip size boundary is constants.DVD_SIZE_THRESHOLD_BYTES, the same
    value iso_detect._iso_size_fallback() uses, so a file cannot be judged
    over-sized by one of them and under-sized by the other.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(_XBOX_MAGIC_OFFSET)
            xbox_header = fh.read(20)
            if xbox_header == _XBOX_MAGIC:
                return "xiso"

            fh.seek(_ISO9660_OFFSET)
            iso_header = fh.read(5)
            if iso_header == _ISO9660_MAGIC:
                file_size = path.stat().st_size
                if file_size > DVD_SIZE_THRESHOLD_BYTES:
                    return "dvd_rip"
                return "iso9660"

            return "unknown"
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to inspect %s for Xbox/ISO 9660 magic: %s", path, exc)
        return "unknown"
