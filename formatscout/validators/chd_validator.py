import logging
import struct
from pathlib import Path

from ..result import Candidate, Issue, IssueCode, Method, ScanResult, Status, Tier

logger = logging.getLogger(__name__)

_CHD_MAGIC = b"MComprHD"

# Metadata tags. CHT2/CHTR/CHCD mark a CD (CHCD is the oldest CD tag), CHGD/CHGT a
# GD-ROM track (Dreamcast, but Sega NAOMI GD-ROMs share them), "DVD " a DVD image.
_META_CHT2 = b"CHT2"
_META_CHTR = b"CHTR"
_META_CHCD = b"CHCD"
_META_CHGD = b"CHGD"
_META_CHGT = b"CHGT"
_META_DVD = b"DVD "
_CD_TAGS = frozenset({_META_CHT2, _META_CHTR, _META_CHCD})
_GD_TAGS = frozenset({_META_CHGD, _META_CHGT})

# Fixed header prefix common to every CHD version: tag(8) length(4) version(4),
# all big-endian. Only version 5 is read beyond this prefix.
_HEADER_PREFIX_LEN = 16
_SUPPORTED_VERSION = 5
_V5_HEADER_LEN = 124

_META_OFFSET_POS = 48

# CHD v5 fixed header layout (chd.h): rawsha1 is the SHA1 of the raw/uncompressed
# hunk data as chdman stores it. For CD CHDs that data is 2448-byte frames (a
# 2352-byte sector plus 96 bytes of subcode) plus track padding, so it cannot
# equal Redump's per-track .bin SHA1. For DVD CHDs it may equal the ISO's SHA1,
# which is unverified here. The adjacent `sha1` field (offset 84) additionally
# folds in metadata, so it is intentionally not used here.
_RAWSHA1_OFFSET = 64
_RAWSHA1_LEN = 20

# Defends the metadata-chain walk below against a crafted file whose next_offset
# chain cycles or wanders past EOF: real CHD files have a handful of metadata
# entries, so this cap is never reached by a well-formed file.
_MAX_METADATA_ENTRIES = 4096

# A metadata entry header is tag(4) + flags(1) + length(3) + next(8). Only the
# first CHT2 payload is read, and never more than this many bytes of it.
_META_ENTRY_HEADER_LEN = 16
_CHT2_PAYLOAD_CAP_BYTES = 4096

# Allow-lists for CHT2 payload values. Parsed values only ever reach the result
# through these, so file content never becomes evidence text.
_CHT2_TRACK_TYPES = frozenset({
    "MODE1", "MODE1_RAW", "MODE2", "MODE2_FORM1", "MODE2_FORM2", "MODE2_FORM_MIX", "MODE2_RAW", "AUDIO",
})
_CHT2_SUBTYPES = frozenset({"NONE", "RW", "RW_RAW"})

# Candidate eras a container-level tag narrows to. A CD tag cannot tell PS1 from
# PS2 (the CHD does not say which disc is inside), and the DVD tag is shared by
# every DVD-based console this package knows.
_CD_CANDIDATE_ERAS = ("ps1", "ps2")
_DVD_CANDIDATE_ERAS = ("ps2", "xbox", "xbox360")


def _read_header_prefix(fh) -> tuple[int, int] | None:
    """Read magic, length and version. Returns (length, version), or None when
    the magic is absent. Raises struct.error when the prefix is truncated."""
    head = fh.read(_HEADER_PREFIX_LEN)
    if head[:8] != _CHD_MAGIC:
        return None
    return struct.unpack(">II", head[8:_HEADER_PREFIX_LEN])


def extract_embedded_sha1(path: Path) -> str | None:
    """
    Read the CHD v5 header's embedded rawsha1 field via fixed-offset parsing.

    No hunk decompression, this only reads header bytes. Returns None on any
    read error, on a header too short to contain the field, on any version
    other than 5 (other versions put the field elsewhere), on a v5 header whose
    length field is not 124, and on an all-zero field. An all-zero field means
    unset: some chdman versions omit it for non-CD types. The value is returned
    as stored in the header and is never checked against the hunk data.
    """
    try:
        with path.open("rb") as fh:
            prefix = _read_header_prefix(fh)
            if prefix != (_V5_HEADER_LEN, _SUPPORTED_VERSION):
                return None
            fh.seek(_RAWSHA1_OFFSET)
            raw = fh.read(_RAWSHA1_LEN)
            if len(raw) < _RAWSHA1_LEN:
                return None
            if raw == b"\x00" * _RAWSHA1_LEN:
                return None
            return raw.hex()
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to read embedded rawsha1 from %s: %s", path, exc)
        return None


def _parse_cht2_payload(payload: bytes) -> tuple[str, ...]:
    """Turn a CHT2 text payload into evidence codes.

    chdman writes NUL-terminated "KEY:VALUE" tokens separated by spaces
    ("TRACK:1 TYPE:MODE2_RAW SUBTYPE:NONE FRAMES:300 ..."). Only TYPE and
    SUBTYPE are used, and only when the value is on an allow-list. No era is
    derived from them.
    """
    text = payload.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
    fields: dict[str, str] = {}
    for token in text.split():
        key, sep, value = token.partition(":")
        if sep and key not in fields:
            fields[key] = value
    if "TYPE" not in fields:
        return ("chd_cht2_unparsed",)
    track_type = fields["TYPE"]
    evidence = [
        f"chd_cht2_type_{track_type.lower()}" if track_type in _CHT2_TRACK_TYPES else "chd_cht2_type_other"
    ]
    if "SUBTYPE" in fields:
        subtype = fields["SUBTYPE"]
        evidence.append(
            f"chd_cht2_subtype_{subtype.lower()}" if subtype in _CHT2_SUBTYPES else "chd_cht2_subtype_other"
        )
    return tuple(evidence)


def _container_only(
    reason: str,
    *,
    container: str = "chd",
    evidence: tuple[str, ...] = ("chd_magic",),
    warnings: list[str] | None = None,
    issues: tuple[Issue, ...] = (),
    candidates: tuple[Candidate, ...] = (),
) -> ScanResult:
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0, reason=reason,
        warnings=warnings or [], status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL,
        container=container, evidence=evidence, issues=issues, candidates=candidates,
    )


def _tag_result(tag: bytes, extra_evidence: tuple[str, ...]) -> ScanResult:
    """The ScanResult for the first recognised platform tag in the chain."""
    base = ("chd_magic", "chd_v5")
    tag_name = tag.decode("ascii")
    if tag in _GD_TAGS:
        return ScanResult(
            title=None, platform=None, era="dreamcast", confidence=0.85,
            reason=f"CHD metadata {tag_name} tag indicates GD-ROM (Dreamcast)",
            warnings=["not authoritative: Sega NAOMI GD-ROM images use the same GD-ROM track tags"],
            method=Method.STRUCTURAL, authoritative=False, container="chd_gd",
            evidence=base + (f"chd_meta_{tag_name.lower()}",) + extra_evidence,
        )
    if tag == _META_DVD:
        eras, container, code, label = _DVD_CANDIDATE_ERAS, "chd_dvd", "chd_meta_dvd", "DVD"
    else:
        eras, container, code, label = _CD_CANDIDATE_ERAS, "chd_cd", f"chd_meta_{tag_name.lower()}", "CD"
    return _container_only(
        f"CHD {label} image (metadata {tag_name.strip()} tag); the tag does not name a platform",
        container=container, evidence=base + (code,) + extra_evidence,
        warnings=[f"CHD {label} tag does not identify the platform, candidates: {', '.join(eras)}"],
        candidates=tuple(Candidate(era, Tier.WEAK, (code,)) for era in eras),
    )


def detect_chd_platform(path: Path) -> ScanResult:
    """
    Inspect a CHD's header and metadata chain. Never raises.

    Only header version 5 is read. Any other version is a container_only result
    (era None, container "chd") carrying a CHD_VERSION_UNSUPPORTED issue; the
    metadata chain of other versions is never walked.

    The first recognised tag in the v5 metadata chain decides the result, and
    the logical size never does:
      CHT2, CHTR, CHCD (CD)  container_only, container "chd_cd", era None,
                             candidates ps1, ps2. CHT2's text payload adds
                             chd_cht2_* evidence codes.
      DVD tag ("DVD ")       container_only, container "chd_dvd", era None,
                             candidates ps2, xbox, xbox360.
      CHGD, CHGT (GD-ROM)    era dreamcast, status guess, authoritative False
                             (NAOMI GD-ROMs share the tags), container "chd_gd".
      none of the above      container_only, container "chd".
    Bad magic is no_signal, a truncated header container_only with a
    CHD_HEADER_TRUNCATED issue, a v5 header whose length field is not 124
    container_only with a CHD_HEADER_INVALID issue, and a read error status error.
    """
    try:
        with path.open("rb") as fh:
            try:
                prefix = _read_header_prefix(fh)
            except struct.error:
                return _container_only(
                    "CHD header truncated, could not read the length and version fields",
                    issues=(Issue("CHD_HEADER_TRUNCATED", "CHD header ends before the version field"),),
                )
            if prefix is None:
                return ScanResult(
                    title=None, platform=None, era=None, confidence=0.0,
                    reason="CHD magic bytes not found, not a valid CHD file",
                    status=Status.NO_SIGNAL, method=Method.NONE,
                )
            header_len, version = prefix
            if version != _SUPPORTED_VERSION:
                message = f"CHD header version {version} is not supported, only version 5 is read"
                return _container_only(
                    message,
                    warnings=[f"CHD version {version} is not parsed, no platform information read"],
                    issues=(Issue(IssueCode.CHD_VERSION_UNSUPPORTED, message),),
                )
            if header_len != _V5_HEADER_LEN:
                message = f"CHD v5 header length is {header_len}, expected {_V5_HEADER_LEN}"
                return _container_only(message, issues=(Issue("CHD_HEADER_INVALID", message),))

            fh.seek(_META_OFFSET_POS)
            raw = fh.read(8)
            if len(raw) < 8:
                return _container_only(
                    "CHD header truncated, could not read metadata offset",
                    issues=(Issue("CHD_HEADER_TRUNCATED", "CHD header ends before the metadata offset field"),),
                )
            meta_offset = struct.unpack(">Q", raw)[0]

            file_size = fh.seek(0, 2)
            visited_offsets: set[int] = set()

            while meta_offset != 0:
                if len(visited_offsets) >= _MAX_METADATA_ENTRIES or meta_offset in visited_offsets:
                    break  # cycle or pathologically long chain, bail out rather than spin
                if meta_offset >= file_size:
                    break  # next_offset points outside the file, malformed/crafted chain
                visited_offsets.add(meta_offset)

                fh.seek(meta_offset)
                entry_header = fh.read(_META_ENTRY_HEADER_LEN)  # tag(4) + flags(1) + length(3) + next(8)
                if len(entry_header) < _META_ENTRY_HEADER_LEN:
                    break

                tag = entry_header[0:4]
                next_offset = struct.unpack(">Q", entry_header[8:16])[0]

                if tag == _META_CHT2:
                    length = struct.unpack(">I", entry_header[4:8])[0] & 0xFFFFFF
                    payload = fh.read(min(length, _CHT2_PAYLOAD_CAP_BYTES))
                    return _tag_result(tag, _parse_cht2_payload(payload))
                if tag in _CD_TAGS or tag in _GD_TAGS or tag == _META_DVD:
                    return _tag_result(tag, ())

                meta_offset = next_offset

        return _container_only(
            "CHD container detected but no recognised platform metadata tag found",
            warnings=["no CHT2/CHTR/CHCD/CHGD/CHGT/DVD tag in metadata chain"],
            evidence=("chd_magic", "chd_v5"),
        )
    except (OSError, struct.error) as exc:
        logger.debug("Failed to read CHD metadata from %s: %s", path, exc)
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"CHD read error: {exc}",
            status=Status.ERROR, method=Method.NONE,
        )
