import logging
import struct
from pathlib import Path

from ..magic.magic_detect import detect_from_magic
from ..result import ScanResult
from ..utils.pointer_file import read_capped_lines

logger = logging.getLogger(__name__)


def resolve_bin_cue(
    bin_path: Path, dir_cache: dict[Path, list[Path]] | None = None,
) -> ScanResult:
    """
    Resolve platform for a .bin file using its sibling .cue sheet.

    Pipeline:
      1. Locate sibling .cue by stem (case-insensitive).
      2. If found: parse first TRACK type, then re-run magic on .bin.
         Magic takes precedence (0.85); track type used as secondary signal.
      3. If no .cue: return low-confidence result with actionable warning.

    dir_cache: caller-owned {parent_dir: entries} map so repeated calls in one
    directory share a single iterdir(). Scope it to one scan sequence, never a
    long-lived cache, or it will serve a stale directory listing.
    """
    cue_path = _find_cue(bin_path, dir_cache)

    if cue_path is None:
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.3,
            reason=f"{bin_path.name}: no sibling .cue sheet found",
            warnings=[
                f"{bin_path.name}: .bin files cannot be reliably identified without their "
                "cue sheet, add the matching .cue file for accurate detection"
            ],
        )

    track_type = _parse_cue_track_type(cue_path)

    # Repeats work: both current callers (detector._detect_file and
    # iso_detect.detect_cue) already ran detect_from_magic on this .bin and only
    # reach here after it returned no era.
    era, reason = detect_from_magic(bin_path, "bin")
    if era is not None:
        return ScanResult(
            title=None,
            platform=None,
            era=era,
            confidence=0.85,
            reason=f"{reason} (confirmed by {cue_path.name})",
        )

    if track_type == "MODE2/2352":
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.4,
            reason=(
                f"{cue_path.name} declares MODE2/2352, raw CD-ROM image, "
                "platform ambiguous (PS1 / PS2 / Dreamcast)"
            ),
            warnings=[
                "no magic byte match in first sector; add this title to the hash index "
                "for definitive platform identification"
            ],
        )

    if track_type == "MODE1/2352":
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.35,
            reason=f"{cue_path.name} declares MODE1/2352, generic CD-ROM data disc, era undetermined",
            warnings=["no platform-specific signals found in MODE1 sector"],
        )

    if track_type == "AUDIO":
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.2,
            reason=f"{cue_path.name} first TRACK is AUDIO, no data track to inspect",
            warnings=["cue sheet describes an audio disc or multi-track image with audio first"],
        )

    if track_type is not None:
        return ScanResult(
            title=None,
            platform=None,
            era=None,
            confidence=0.25,
            reason=f"{cue_path.name}: unrecognised track type '{track_type}'",
            warnings=["cannot infer platform from this track type"],
        )

    return ScanResult(
        title=None,
        platform=None,
        era=None,
        confidence=0.2,
        reason=f"{cue_path.name}: cue sheet contains no parseable TRACK declaration",
        warnings=["malformed or empty cue sheet"],
    )


def _find_cue(bin_path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> Path | None:
    """Case-insensitive search for a .cue file with the same stem in the same directory.

    When dir_cache is supplied, the parent directory's listing is read once
    (iterdir()) and reused for every .bin file sharing that directory, instead
    of rescanning the directory on every call.
    """
    parent = bin_path.parent
    if dir_cache is not None:
        entries = dir_cache.get(parent)
        if entries is None:
            try:
                entries = list(parent.iterdir())
            except OSError:
                entries = []
            dir_cache[parent] = entries
    else:
        try:
            entries = list(parent.iterdir())
        except OSError:
            entries = []

    target_stem = bin_path.stem.lower()
    for candidate in entries:
        if candidate.suffix.lower() == ".cue" and candidate.stem.lower() == target_stem:
            return candidate
    return None


def _parse_cue_track_type(cue_path: Path) -> str | None:
    """
    Return the type of the first TRACK line in the cue sheet.

    Standard values: MODE1/2352, MODE2/2352, MODE1/2048, AUDIO.
    Returns None if the cue sheet is unreadable or contains no TRACK line.
    """
    try:
        for line in read_capped_lines(cue_path):
            stripped = line.strip().upper()
            if stripped.startswith("TRACK "):
                parts = stripped.split()
                if len(parts) >= 3:
                    return parts[2]
        return None
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to parse cue sheet %s: %s", cue_path, exc)
        return None
