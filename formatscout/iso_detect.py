import logging
import struct
from pathlib import Path

from .constants import (
    CD_SIZE_THRESHOLD_BYTES,
    DVD5_SIZE_THRESHOLD_BYTES,
    DVD_SIZE_THRESHOLD_BYTES,
    ISO_LOGICAL_SECTOR_BYTES,
    ROOT_DIR_READ_CAP_BYTES,
)
from .iso9660_dir import iter_dir_records
from .utils.pointer_file import read_capped_lines
from .utils.safe_path import rejection_warning, resolve_pointer
from .xbox_image import detect_xbox_image_type
from .magic.magic_detect import detect_from_magic
from .result import ScanResult, null_scan_result
from .validators import bin_validator
from .validators import chd_validator

logger = logging.getLogger(__name__)

_DOS_PUBLISHERS = frozenset({
    "GT INTERACTIVE", "ID SOFTWARE", "APOGEE", "3D REALMS", "SIERRA ON-LINE",
    "SIERRA", "ACTIVISION", "MICROPROSE", "LUCASARTS", "INTERPLAY", "BRODERBUND",
})


def detect_iso(path: Path) -> ScanResult:
    era, reason = detect_from_magic(path, "iso")
    if era is not None:
        return ScanResult(title=None, platform=None, era=era, confidence=0.9, reason=reason)

    pvd = detect_from_pvd(path)
    if pvd.era is not None:
        return pvd

    xbox_kind = detect_xbox_image_type(path)
    if xbox_kind == "xiso":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.9,
            reason="XDVDFS magic 'MICROSOFT*XBOX*MEDIA' found at 0x10000, Original Xbox disc image",
        )
    if xbox_kind == "dvd_rip":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.9,
            reason="ISO 9660 magic found but file exceeds the xISO size threshold, raw Xbox DVD rip",
            requires_extraction=True,
        )

    # "iso9660" means the ISO 9660 magic was found and the file is not an Xbox
    # image. That is a real signal even though it names no platform, so it is
    # passed down rather than discarded: it separates "a genuine disc image we
    # cannot attribute" from "bytes that are not a recognisable image at all".
    return _iso_size_fallback(path, iso9660_confirmed=(xbox_kind == "iso9660"))


def detect_cue(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    """Detect a .cue sheet by resolving the .bin it references.

    FILE targets go through utils.safe_path.resolve_pointer(); a rejected
    target contributes no signal and is never opened, and its
    "pointer rejected: ..." warning is appended to whichever result is
    returned. The same-stem sibling .bin fallback goes through
    resolve_pointer() too: a <stem>.bin that is a FIFO, a directory or a
    symlink leaving the cue's directory is rejected and never opened.
    """
    pointer_warnings: list[str] = []
    result = _detect_cue(path, dir_cache, pointer_warnings)
    result.warnings.extend(pointer_warnings)
    return result


def _detect_cue(
    path: Path,
    dir_cache: dict[Path, list[Path]] | None,
    pointer_warnings: list[str],
) -> ScanResult:
    bin_path = _cue_bin_path(path, pointer_warnings)
    if bin_path is None:
        sibling_name = path.with_suffix(".bin").name
        sibling = resolve_pointer(path.parent, sibling_name)
        if sibling.ok:
            bin_path = sibling.path
        elif sibling.status == "rejected":
            message = rejection_warning(sibling_name, sibling.reason or "rejected")
            # A FILE line naming the same sibling already produced this text.
            if message not in pointer_warnings:
                pointer_warnings.append(message)
    if bin_path is None:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="no .bin file found for .cue sheet",
            warnings=[f"could not locate the .bin file referenced by {path.name}"],
        )
    era, reason = detect_from_magic(bin_path, "bin")
    if era is not None:
        return ScanResult(title=None, platform=None, era=era, confidence=0.9, reason=reason)
    pvd = detect_from_pvd(bin_path)
    if pvd.era is not None:
        return pvd
    return bin_validator.resolve_bin_cue(bin_path, dir_cache)


def detect_chd(path: Path) -> ScanResult:
    return chd_validator.detect_chd_platform(path)


# ── ISO 9660 PVD ─────────────────────────────────────────────────────────────

def detect_from_pvd(iso_path: Path) -> ScanResult:
    _null = null_scan_result()
    try:
        with iso_path.open("rb") as fh:
            fh.seek(32768)  # sector 16 at 2048 bytes/sector
            pvd = fh.read(2048)

        if len(pvd) < 574 or pvd[0] != 1:
            return _null

        def _field(data: bytes) -> str:
            return data.replace(b"\x00", b"").decode("ascii", errors="replace").strip().upper()

        sys_id = _field(pvd[8:40])
        vol_id = _field(pvd[40:72])
        publisher = _field(pvd[318:446])
        preparer = _field(pvd[446:574])

        # Structural checks run before the loose volume-label keyword match
        # below: PS3_DISC.SFB and the XBE filesystem scan are unambiguous
        # signals, unlike a substring match against a title's volume label
        # (e.g. "COMMANDOS" containing "DOS"), so they must not be
        # short-circuited by the weaker keyword check running first.
        # Read once (see _read_root_dir) and also parse once: both structural
        # checks below consume the same entry-name list rather than each
        # re-walking the raw directory records.
        root_names = _root_dir_entry_names(_read_root_dir(iso_path, pvd))

        if "PS3_DISC.SFB" in root_names:
            return ScanResult(
                title=None, platform=None, era="ps3", confidence=0.9,
                reason="ISO 9660 root directory contains PS3_DISC.SFB, PS3 disc image",
            )

        xbe_result = _xbe_result_from_names(root_names)
        if xbe_result.era is not None:
            return xbe_result

        for kw, era in (
            (("WINDOWS XP", "WINXP", "WXPEVOL", "XP_"), "winxp"),
            (("WIN98", "WINDOWS 98", "W98", "MEMPHIS"), "win98"),
            (("WIN95", "WINDOWS 95", "CHICAGO"), "win95"),
            (("MSDOS", "MS-DOS", "PCDOS", "FREEDOS"), "dos"),
        ):
            if any(k in vol_id for k in kw):
                return ScanResult(
                    title=None, platform=None, era=era, confidence=0.75,
                    reason=f"ISO volume label contains '{vol_id}'",
                )

        for meta, label in ((publisher, "publisher"), (preparer, "preparer")):
            if any(p in meta for p in _DOS_PUBLISHERS):
                matched = next(p for p in _DOS_PUBLISHERS if p in meta)
                return ScanResult(
                    title=None, platform=None, era="dos", confidence=0.7,
                    reason=f"ISO {label} '{meta[:40]}' matches known DOS publisher '{matched}'",
                )

        ps_prefixes = ("SLUS", "SCES", "SCUS", "SLPS", "SCPS", "SLES", "SLEJ")
        vol_starts_ps = any(vol_id.startswith(p) for p in ps_prefixes)
        publisher_sony = "SONY" in publisher

        if vol_starts_ps or (sys_id == "CD-ROM" and publisher_sony):
            try:
                size_bytes = iso_path.stat().st_size
            except OSError:
                size_bytes = 0
            if vol_starts_ps and size_bytes > DVD5_SIZE_THRESHOLD_BYTES:
                return ScanResult(
                    title=None, platform=None, era="ps2", confidence=0.75,
                    reason=f"ISO volume label '{vol_id}' matches PS2 pattern (DVD size)",
                )
            return ScanResult(
                title=None, platform=None, era="ps1", confidence=0.75,
                reason=f"ISO volume label '{vol_id}', publisher '{publisher[:30]}' match PS1",
            )

        return _null

    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"ISO PVD read error: {exc}",
        )


def _read_root_dir(iso_path: Path, pvd: bytes) -> bytes:
    """Read the ISO 9660 root directory's raw bytes, located via the PVD's root
    LBA/size fields (offsets 158/166). Read once by detect_from_pvd and passed
    into _root_dir_entry_names below instead of independently reopening the
    file and re-deriving the same LBA/size math.
    """
    if len(pvd) < 190:
        return b""
    root_lba = struct.unpack_from("<I", pvd, 158)[0]
    root_size = struct.unpack_from("<I", pvd, 166)[0]
    if root_lba == 0 or root_size == 0 or root_size > ROOT_DIR_READ_CAP_BYTES:
        return b""
    try:
        with iso_path.open("rb") as fh:
            fh.seek(root_lba * ISO_LOGICAL_SECTOR_BYTES)
            return fh.read(root_size)
    except OSError:
        return b""


def _root_dir_entry_names(dir_data: bytes) -> list[str]:
    """Return upper-cased, version-stripped file/dir names from raw ISO 9660
    root directory bytes (as produced by _read_root_dir).
    """
    return [rec.name for rec in iter_dir_records(dir_data)]


def _xbe_result_from_names(names: list[str]) -> ScanResult:
    _null = null_scan_result()
    for name in names:
        if name.endswith(".XBE"):
            return ScanResult(
                title=None, platform=None, era="xbox", confidence=0.8,
                reason="ISO filesystem contains .xbe, Original Xbox executable",
            )
    return _null


def _iso_size_fallback(path: Path, *, iso9660_confirmed: bool = False) -> ScanResult:
    """Lowest tier: nothing named a platform, so decide what little can be said
    from file size alone.

    iso9660_confirmed means detect_xbox_image_type() found the ISO 9660 magic
    and ruled out both Xbox shapes. era stays None either way, because a
    filesystem signature identifies the container, not the platform, and
    guessing one here would be a fabrication. What it does change is that the
    result is no longer reported as "no signal found": a confirmed ISO 9660
    image whose size is unremarkable is a different situation for the caller
    than an unrecognisable file, and only the former is worth prompting a user
    to label manually.
    """
    signal = (
        "ISO 9660 magic confirmed but no platform signal"
        if iso9660_confirmed
        else "no PVD signal"
    )
    try:
        size = path.stat().st_size
    except OSError:
        return ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="no signal found")
    if size > DVD_SIZE_THRESHOLD_BYTES:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason=f"ISO exceeds 4 GB, {signal}",
            warnings=["could be PS2 or Xbox OG, please select era manually"],
        )
    if size < CD_SIZE_THRESHOLD_BYTES:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason=f"ISO under 800 MB, {signal}",
            warnings=["era ambiguous, please select era manually"],
        )
    if iso9660_confirmed:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason="ISO 9660 magic confirmed but no platform signal, size is inconclusive",
            warnings=["valid ISO 9660 disc image with no platform signal, please select era manually"],
        )
    return ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="no signal found")


def _cue_bin_path(cue_path: Path, warnings: list[str] | None = None) -> Path | None:
    """Return the resolved path of the first quoted FILE target in the cue
    sheet that exists inside the cue's directory, or None.

    Each target is checked by resolve_pointer() before anything touches it.
    A rejected target is skipped (never opened or stat-ed) and, when
    *warnings* is given, a "pointer rejected: ..." message is appended to it
    (otherwise it is logged). A target that is simply absent is skipped
    silently, as before.
    """
    try:
        for line in read_capped_lines(cue_path):
            line = line.strip()
            if line.upper().startswith("FILE "):
                parts = line.split('"')
                if len(parts) >= 2:
                    resolution = resolve_pointer(cue_path.parent, parts[1])
                    if resolution.ok:
                        return resolution.path
                    if resolution.status == "rejected":
                        message = rejection_warning(parts[1], resolution.reason or "rejected")
                        if warnings is not None:
                            warnings.append(message)
                        else:
                            logger.warning("%s", message)
        return None
    except (OSError, struct.error, UnicodeDecodeError) as exc:
        logger.debug("Failed to parse cue sheet %s: %s", cue_path, exc)
        return None
