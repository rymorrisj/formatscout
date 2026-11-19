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
from .iso9660_dir import DirRecord, iter_dir_records
from .utils.pointer_file import read_capped_lines
from .utils.safe_path import rejection_warning, resolve_pointer
from .xbox_image import detect_xbox_image_type
from .magic.magic_detect import SYSTEM_CNF_READ_CAP_BYTES, classify_system_cnf, detect_from_magic, magic_tags
from .result import Candidate, Issue, Method, ScanResult, Status, null_scan_result, tier_for_confidence
from .validators import bin_validator
from .validators import chd_validator

logger = logging.getLogger(__name__)

_DOS_PUBLISHERS = frozenset({
    "GT INTERACTIVE", "ID SOFTWARE", "APOGEE", "3D REALMS", "SIERRA ON-LINE",
    "SIERRA", "ACTIVISION", "MICROPROSE", "LUCASARTS", "INTERPLAY", "BRODERBUND",
})

_PS_SERIAL_PREFIXES = ("SLUS", "SCES", "SCUS", "SLPS", "SCPS", "SLES", "SLEJ")

# ECMA-119 8.4: a Primary Volume Descriptor is type code 1 followed by the
# standard identifier "CD001".
_PVD_STANDARD_ID = b"CD001"


def detect_iso(path: Path) -> ScanResult:
    era, reason = detect_from_magic(path, "iso")
    if era is not None:
        method, authoritative = magic_tags(reason)
        return ScanResult(
            title=None, platform=None, era=era, confidence=0.9, reason=reason,
            method=method, authoritative=authoritative,
        )

    pvd = detect_from_pvd(path)
    if pvd.era is not None:
        return pvd

    xbox_kind = detect_xbox_image_type(path)
    if xbox_kind == "xiso":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.9,
            reason="XDVDFS magic 'MICROSOFT*XBOX*MEDIA' found at 0x10000, Original Xbox disc image",
            # Not authoritative: Xbox 360 discs use the same XDVDFS magic.
            method=Method.MAGIC, authoritative=False, container="xdvdfs", evidence=("xdvdfs_magic",),
        )
    if xbox_kind == "dvd_rip":
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.9,
            reason="ISO 9660 magic found but file exceeds the xISO size threshold, raw Xbox DVD rip",
            requires_extraction=True,
            method=Method.SIZE_HEURISTIC, authoritative=False, container="iso9660",
            evidence=("iso9660_magic", "size_over_dvd_threshold"),
        )

    # A PlayStation-shaped PVD with no readable SYSTEM.CNF key is ambiguous
    # (candidates ps1/ps2). That is still more than the size fallback below
    # can say, so it is returned as is once the Xbox shapes are ruled out.
    if pvd.status is Status.AMBIGUOUS:
        return pvd

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
    result.issues += tuple(Issue("POINTER_REJECTED", message) for message in pointer_warnings)
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
            status=Status.NO_SIGNAL, method=Method.NONE,
        )
    era, reason = detect_from_magic(bin_path, "bin")
    if era is not None:
        method, authoritative = magic_tags(reason)
        return ScanResult(
            title=None, platform=None, era=era, confidence=0.9, reason=reason,
            method=method, authoritative=authoritative,
        )
    pvd = detect_from_pvd(bin_path)
    if pvd.era is not None:
        return pvd
    return bin_validator.resolve_bin_cue(bin_path, dir_cache)


def detect_chd(path: Path) -> ScanResult:
    return chd_validator.detect_chd_platform(path)


# ── ISO 9660 PVD ─────────────────────────────────────────────────────────────

def detect_from_pvd(iso_path: Path) -> ScanResult:
    """Read the ISO 9660 PVD at sector 16 (2048-byte sectors) and its root
    directory, in this order:

    1. SYSTEM.CNF in the root with a BOOT2 or BOOT key (strict key match,
       magic_detect.classify_system_cnf): ps2 or ps1, Method.SYSTEM_CNF,
       authoritative.
    2. PS3_DISC.SFB, then a .XBE file in the root (structural guesses).
    3. Windows/DOS volume-label keywords.
    4. PlayStation hints with no readable BOOT/BOOT2 key (a serial-shaped
       volume label, a Sony publisher on a CD-ROM system id, or a SYSTEM.CNF
       without a key): era None, status ambiguous, candidates ps1 and ps2.
       Size only orders the candidates, it never names an era.
    5. DOS publisher/preparer keywords, after the PlayStation checks so a
       PlayStation disc whose publisher field names, say, Activision is not
       called dos.

    A sector 16 without type code 1 and "CD001" is no signal.
    """
    _null = null_scan_result()
    try:
        with iso_path.open("rb") as fh:
            fh.seek(32768)  # sector 16 at 2048 bytes/sector
            pvd = fh.read(2048)

        if len(pvd) < 574 or pvd[0] != 1 or pvd[1:6] != _PVD_STANDARD_ID:
            return _null

        def _field(data: bytes) -> str:
            return data.replace(b"\x00", b"").decode("ascii", errors="replace").strip().upper()

        sys_id = _field(pvd[8:40])
        vol_id = _field(pvd[40:72])
        publisher = _field(pvd[318:446])
        preparer = _field(pvd[446:574])

        # Structural checks run before the loose volume-label keyword match
        # below: SYSTEM.CNF, PS3_DISC.SFB and the XBE filesystem scan are
        # unambiguous signals, unlike a substring match against a title's
        # volume label (e.g. "COMMANDOS" containing "DOS"), so they must not
        # be short-circuited by the weaker keyword check running first.
        # Read once (see _read_root_dir) and also parse once: every check
        # below consumes the same record list rather than each re-walking
        # the raw directory records.
        root_records = list(iter_dir_records(_read_root_dir(iso_path, pvd)))
        root_names = [rec.name for rec in root_records]

        cnf_record = next((rec for rec in root_records if rec.name == "SYSTEM.CNF"), None)
        cnf_era = _read_system_cnf_era(iso_path, cnf_record) if cnf_record is not None else "unknown"
        if cnf_era in ("ps1", "ps2"):
            boot_key = "BOOT2" if cnf_era == "ps2" else "BOOT"
            return ScanResult(
                title=None, platform=None, era=cnf_era, confidence=0.9,
                reason=f"ISO 9660 root SYSTEM.CNF {boot_key} key indicates {cnf_era.upper()}",
                method=Method.SYSTEM_CNF, authoritative=True, container="iso9660",
                evidence=("pvd_root_system_cnf",),
            )

        if "PS3_DISC.SFB" in root_names:
            return ScanResult(
                title=None, platform=None, era="ps3", confidence=0.9,
                reason="ISO 9660 root directory contains PS3_DISC.SFB, PS3 disc image",
                # Not authoritative: a file name only, PS3_DISC.SFB's contents are not checked.
                method=Method.STRUCTURAL, authoritative=False, evidence=("pvd_root_ps3_disc_sfb",),
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
                    method=Method.STRUCTURAL, authoritative=False, evidence=("pvd_volume_label_keyword",),
                )

        ps_evidence: tuple[str, ...] = ()
        if any(vol_id.startswith(p) for p in _PS_SERIAL_PREFIXES):
            ps_evidence += ("pvd_ps_serial_label",)
        if sys_id == "CD-ROM" and "SONY" in publisher:
            ps_evidence += ("pvd_sony_cdrom",)
        if cnf_record is not None:
            ps_evidence += ("pvd_root_system_cnf_no_boot_key",)
        if ps_evidence:
            return _ps_ambiguous_result(iso_path, vol_id, publisher, ps_evidence)

        for meta, label in ((publisher, "publisher"), (preparer, "preparer")):
            if any(p in meta for p in _DOS_PUBLISHERS):
                matched = next(p for p in _DOS_PUBLISHERS if p in meta)
                return ScanResult(
                    title=None, platform=None, era="dos", confidence=0.7,
                    reason=f"ISO {label} '{meta[:40]}' matches known DOS publisher '{matched}'",
                    method=Method.STRUCTURAL, authoritative=False, evidence=(f"pvd_{label}_dos_publisher",),
                )

        return _null

    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason=f"ISO PVD read error: {exc}",
            status=Status.ERROR, method=Method.NONE,
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


def _read_system_cnf_era(iso_path: Path, record: DirRecord) -> str:
    """Classify the root SYSTEM.CNF extent of a plain (2048-byte sector)
    ISO 9660 image: "ps2", "ps1" or "unknown".

    Reads at most SYSTEM_CNF_READ_CAP_BYTES from the record's own LBA/size.
    An LBA of 0 (the system area, never a file extent), a size of 0, or a
    read error is "unknown", never a PS1 default.
    """
    if record.lba == 0 or record.size == 0:
        return "unknown"
    try:
        with iso_path.open("rb") as fh:
            fh.seek(record.lba * ISO_LOGICAL_SECTOR_BYTES)
            raw = fh.read(min(record.size, SYSTEM_CNF_READ_CAP_BYTES))
    except OSError as exc:
        logger.debug("Failed to read SYSTEM.CNF from %s: %s", iso_path, exc)
        return "unknown"
    return classify_system_cnf(raw.decode("ascii", errors="replace"))


def _ps_ambiguous_result(iso_path: Path, vol_id: str, publisher: str, evidence: tuple[str, ...]) -> ScanResult:
    """A PlayStation-shaped PVD with no readable BOOT/BOOT2 key: era None,
    candidates ps1 and ps2.

    The file size only orders the candidates (a file past the 4.7 GB DVD-5
    boundary puts ps2 first, at a higher tier); it never names an era. A
    stat failure leaves the default order.
    """
    try:
        over_dvd5 = iso_path.stat().st_size > DVD5_SIZE_THRESHOLD_BYTES
    except OSError:
        over_dvd5 = False
    if over_dvd5:
        evidence += ("size_over_dvd5",)
        method = Method.SIZE_HEURISTIC
        candidates = (
            Candidate("ps2", tier_for_confidence(0.5), evidence),
            Candidate("ps1", tier_for_confidence(0.2), evidence),
        )
    else:
        method = Method.STRUCTURAL
        candidates = tuple(Candidate(ps, tier_for_confidence(0.4), evidence) for ps in ("ps1", "ps2"))
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.4,
        reason=(
            f"ISO volume label '{vol_id}', publisher '{publisher[:30]}' suggest PlayStation, "
            "but no SYSTEM.CNF BOOT/BOOT2 key could be read to tell PS1 from PS2"
        ),
        warnings=["PlayStation disc without a readable SYSTEM.CNF BOOT/BOOT2 key, select PS1 or PS2 manually"],
        status=Status.AMBIGUOUS, method=method, container="iso9660",
        evidence=evidence, candidates=candidates,
    )


def _root_dir_entry_names(dir_data: bytes) -> list[str]:
    """Return upper-cased, version-stripped file/dir names from raw ISO 9660
    root directory bytes (as produced by _read_root_dir).

    The name-only view of iter_dir_records(). detect_from_pvd walks the
    records itself because it also needs SYSTEM.CNF's LBA and size.
    """
    return [rec.name for rec in iter_dir_records(dir_data)]


def _xbe_result_from_names(names: list[str]) -> ScanResult:
    _null = null_scan_result()
    for name in names:
        if name.endswith(".XBE"):
            return ScanResult(
                title=None, platform=None, era="xbox", confidence=0.8,
                reason="ISO filesystem contains .xbe, Original Xbox executable",
                method=Method.STRUCTURAL, authoritative=False, evidence=("pvd_root_xbe",),
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
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0, reason="no signal found",
            status=Status.NO_SIGNAL, method=Method.NONE,
        )
    # A confirmed ISO 9660 image with no platform signal is container_only;
    # an unconfirmed small file has nothing to go on.
    if iso9660_confirmed:
        status, method, container, evidence = Status.CONTAINER_ONLY, Method.STRUCTURAL, "iso9660", ("iso9660_magic",)
    else:
        status, method, container, evidence = Status.NO_SIGNAL, Method.NONE, None, ()
    if size > DVD_SIZE_THRESHOLD_BYTES:
        # The size names two candidates. Reached only unconfirmed in
        # detect_iso(): a confirmed ISO 9660 image this size is a dvd_rip.
        size_evidence = evidence + ("size_over_dvd_threshold",)
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason=f"ISO exceeds 4 GB, {signal}",
            warnings=["could be PS2 or Xbox OG, please select era manually"],
            status=Status.AMBIGUOUS, method=Method.SIZE_HEURISTIC, container=container, evidence=size_evidence,
            candidates=tuple(
                Candidate(era, tier_for_confidence(0.2), size_evidence) for era in ("ps2", "xbox")
            ),
        )
    if size < CD_SIZE_THRESHOLD_BYTES:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason=f"ISO under 800 MB, {signal}",
            warnings=["era ambiguous, please select era manually"],
            status=status, method=method, container=container, evidence=evidence,
        )
    if iso9660_confirmed:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason="ISO 9660 magic confirmed but no platform signal, size is inconclusive",
            warnings=["valid ISO 9660 disc image with no platform signal, please select era manually"],
            status=status, method=method, container=container, evidence=evidence,
        )
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.0, reason="no signal found",
        status=Status.NO_SIGNAL, method=Method.NONE,
    )


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
