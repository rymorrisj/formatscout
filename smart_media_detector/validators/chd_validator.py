import struct
from pathlib import Path

from ..result import ScanResult

_CHD_MAGIC = b"MComprHD"
_META_CHTR = b"CHTR"
_META_CHT2 = b"CHT2"
_META_CHGD = b"CHGD"  # GD-ROM track — Dreamcast only

_META_OFFSET_POS = 48

# CHD v5 fixed header layout (chd.h): rawsha1 is the SHA1 of the raw/uncompressed
# hunk data — the value that matches Redump's published per-image hash. The
# adjacent `sha1` field (offset 84) additionally folds in metadata and will not
# match Redump, so it is intentionally not used here.
_RAWSHA1_OFFSET = 64
_RAWSHA1_LEN = 20

# logicalbytes: uncompressed image size in bytes (CHD v5 header, chd.h).
# Used only to distinguish CD-sized (PS1) from DVD-sized (PS2) media when the
# CHTR/CHT2 tag alone can't tell them apart.
_LOGICAL_BYTES_OFFSET = 32
_CD_SIZE_THRESHOLD = 800 * 1024 * 1024  # ~800 MB — independent heuristic; iso_detect.py uses a separate 4.7 GB PS1/PS2 boundary

# Defends the metadata-chain walk below against a crafted file whose next_offset
# chain cycles or wanders past EOF: real CHD files have a handful of metadata
# entries, so this cap is never reached by a well-formed file.
_MAX_METADATA_ENTRIES = 4096


def extract_embedded_sha1(path: Path) -> str | None:
    """
    Read the CHD v5 header's embedded rawsha1 field via fixed-offset parsing.

    No hunk decompression — this only reads header bytes. Returns None on any
    read error, on a header too short to contain the field, or on an
    all-zero field (unset — some chdman versions omit it for non-CD types).
    """
    try:
        with path.open("rb") as fh:
            if fh.read(8) != _CHD_MAGIC:
                return None
            fh.seek(_RAWSHA1_OFFSET)
            raw = fh.read(_RAWSHA1_LEN)
            if len(raw) < _RAWSHA1_LEN:
                return None
            if raw == b"\x00" * _RAWSHA1_LEN:
                return None
            return raw.hex()
    except Exception:
        return None


def detect(path: Path) -> ScanResult:
    """
    Inspect CHD v5 metadata chain to determine platform.

    CHGD tag  → Dreamcast (GD-ROM)
    CHTR/CHT2 → standard CD/DVD track; PS1 vs PS2 is then split by the CHD
                header's logicalbytes size (CD-sized → PS1, DVD-sized → PS2)
    Returns a zero-confidence result on any error or unrecognised metadata.
    Never raises.
    """
    try:
        with path.open("rb") as fh:
            if fh.read(8) != _CHD_MAGIC:
                return ScanResult(
                    title=None, platform=None, era=None, confidence=0.0,
                    reason="CHD magic bytes not found — not a valid CHD file",
                )

            fh.seek(_META_OFFSET_POS)
            raw = fh.read(8)
            if len(raw) < 8:
                return ScanResult(
                    title=None, platform=None, era=None, confidence=0.0,
                    reason="CHD header truncated — could not read metadata offset",
                )
            meta_offset = struct.unpack(">Q", raw)[0]

            fh.seek(_LOGICAL_BYTES_OFFSET)
            logical_raw = fh.read(8)
            logical_bytes = struct.unpack(">Q", logical_raw)[0] if len(logical_raw) == 8 else 0

            file_size = fh.seek(0, 2)
            visited_offsets: set[int] = set()

            while meta_offset != 0:
                if len(visited_offsets) >= _MAX_METADATA_ENTRIES or meta_offset in visited_offsets:
                    break  # cycle or pathologically long chain — bail out rather than spin
                if meta_offset < 0 or meta_offset >= file_size:
                    break  # next_offset points outside the file — malformed/crafted chain
                visited_offsets.add(meta_offset)

                fh.seek(meta_offset)
                entry_header = fh.read(16)  # tag(4) + flags(1) + length(3) + next(8)
                if len(entry_header) < 16:
                    break

                tag = entry_header[0:4]
                next_offset = struct.unpack(">Q", entry_header[8:16])[0]

                if tag == _META_CHGD:
                    return ScanResult(
                        title=None, platform=None, era="dreamcast", confidence=0.85,
                        reason="CHD metadata CHGD tag indicates GD-ROM (Dreamcast)",
                    )

                if tag in (_META_CHTR, _META_CHT2):
                    # CHTR/CHT2 only means "standard CD/DVD track" — it does NOT
                    # distinguish PS1 from PS2 (both use this tag). A real fix
                    # requires decompressing the CHD to inspect SYSTEM.CNF, which
                    # is out of scope (separate backlog item). As a heuristic,
                    # use the header's logical (uncompressed) size to guess
                    # CD-sized (PS1) vs DVD-sized (PS2) — still not authoritative
                    # like the CHGD/hash-index/magic-byte paths.
                    if logical_bytes and logical_bytes <= _CD_SIZE_THRESHOLD:
                        era, size_desc = "ps1", f"{logical_bytes} bytes, CD-sized"
                    elif logical_bytes:
                        era, size_desc = "ps2", f"{logical_bytes} bytes, DVD-sized"
                    else:
                        era, size_desc = "ps2", "size unavailable, defaulted to PS2"
                    return ScanResult(
                        title=None, platform=None, era=era, confidence=0.3,
                        reason=f"heuristic guess (low confidence): CHD metadata CHTR/CHT2 tag "
                               f"confirms a standard CD/DVD track; logical size ({size_desc}) "
                               f"suggests {era.upper()}",
                        warnings=[
                            "not authoritative: CHTR/CHT2 tag + logical size is a heuristic, not "
                            "a hash match; confirm via hash index or manual verification",
                        ],
                    )

                meta_offset = next_offset

        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="CHD container detected but no recognised platform metadata tag found",
            warnings=["no CHGD/CHTR/CHT2 tag in metadata chain"],
        )
    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"CHD read error: {exc}",
        )
