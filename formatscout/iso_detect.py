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
from .utils.text import one_line
from .xbox_image import has_iso9660_magic, probe_xbox_image
from .magic.magic_detect import SYSTEM_CNF_READ_CAP_BYTES, classify_system_cnf, detect_from_magic, magic_tags
from .result import (
    Candidate,
    Issue,
    IssueCode,
    Method,
    ScanResult,
    Status,
    null_scan_result,
    tier_for_confidence,
)
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

# Longest PVD text field (volume label, publisher, preparer) quoted in a
# reason. The raw fields are up to 128 bytes of untrusted image content.
_LABEL_DISPLAY_CAP_CHARS = 64


def _display_label(text: str) -> str:
    """*text* (a raw PVD text field) made safe to quote in a reason: control
    characters (newlines, ESC, ...) become spaces, runs of whitespace
    collapse, and the result is capped at _LABEL_DISPLAY_CAP_CHARS characters
    (ending in "..." when cut). Matching still uses the raw field."""
    return one_line(text, limit=_LABEL_DISPLAY_CAP_CHARS)


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

    xbox = _detect_xbox(path)
    if xbox is not None:
        return xbox

    # A PlayStation-shaped PVD with no readable SYSTEM.CNF key is ambiguous
    # (candidates ps1/ps2). That is still more than the size fallback below
    # can say, so it is returned as is once the Xbox shapes are ruled out.
    if pvd.status is Status.AMBIGUOUS:
        return pvd

    # The ISO 9660 magic with no Xbox layout is a real signal even though it
    # names no platform (at any size: an ISO 9660 image over 4 GiB is not
    # an Xbox rip by size alone), so it is passed down rather than
    # discarded: it separates "a genuine disc image we cannot attribute"
    # from "bytes that are not a recognisable image at all".
    return _iso_size_fallback(path, iso9660_confirmed=has_iso9660_magic(path))


_XBOX_CANDIDATE_ERAS = ("xbox", "xbox360")
# Root entries that name the platform on an XDVDFS volume. UNVERIFIED that
# every real disc carries exactly one of them in the root directory.
_XDVDFS_DEFAULT_EXECUTABLES = (("DEFAULT.XBE", "xbox", "Original Xbox"), ("DEFAULT.XEX", "xbox360", "Xbox 360"))


def _xbox_candidates(evidence: tuple[str, ...]) -> tuple[Candidate, ...]:
    return tuple(Candidate(era, tier_for_confidence(0.5), evidence) for era in _XBOX_CANDIDATE_ERAS)


def _detect_xbox(path: Path) -> ScanResult | None:
    """XDVDFS results for detect_iso(), or None when no XDVDFS magic was
    found at any recognised offset (see xbox_image.probe_xbox_image).

    xISO layout (descriptor at 0x10000): DEFAULT.XBE in the root is xbox,
    DEFAULT.XEX is xbox360, neither (or both) is container_only with
    candidates xbox and xbox360. Never authoritative: a root file name only,
    the executable's contents are not checked. requires_extraction stays
    False, an xISO is directly usable.

    Full XGD layouts (magic past a game-partition offset) are not parsed:
    container_only, candidates xbox and xbox360, issue UNSUPPORTED_LAYOUT.
    requires_extraction is set only when the descriptor's root fields are
    also usable, i.e. XDVDFS is positively identified, never from size.

    Magic with unusable root fields at 0x10000 is ambiguous, not a
    confirmed container.
    """
    probe = probe_xbox_image(path)
    if probe is None:
        return None

    if probe.layout != "xiso":
        evidence = ("xdvdfs_magic", f"{probe.layout}_partition")
        message = (
            f"XDVDFS volume found at the {probe.layout.upper()} game partition "
            f"(offset {probe.partition_offset:#x}), a layout this package does not parse"
        )
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.5,
            reason=f"{message}; Original Xbox and Xbox 360 cannot be told apart",
            warnings=["full Xbox/Xbox 360 disc image layout, select Xbox or Xbox 360 manually"],
            requires_extraction=probe.descriptor_valid,
            status=Status.CONTAINER_ONLY, method=Method.MAGIC, container="xdvdfs",
            evidence=evidence, candidates=_xbox_candidates(evidence),
            issues=(Issue(IssueCode.UNSUPPORTED_LAYOUT, message),),
        )

    if not probe.descriptor_valid:
        evidence = ("xdvdfs_magic", "xdvdfs_descriptor_invalid")
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.3,
            reason="XDVDFS magic found at 0x10000 but the volume descriptor's root directory fields are unusable",
            warnings=["XDVDFS magic without a readable root directory, select Xbox or Xbox 360 manually"],
            status=Status.AMBIGUOUS, method=Method.MAGIC,
            evidence=evidence, candidates=_xbox_candidates(evidence),
        )

    found = [entry for entry in _XDVDFS_DEFAULT_EXECUTABLES if entry[0] in probe.root_names]
    if len(found) == 1:
        name, era, label = found[0]
        return ScanResult(
            title=None, platform=None, era=era, confidence=0.9,
            reason=f"XDVDFS volume at 0x10000 with {name} in its root directory, {label} disc image",
            # Not authoritative: a root file name only, its contents are not checked.
            method=Method.MAGIC, authoritative=False, container="xdvdfs",
            evidence=("xdvdfs_magic", f"xdvdfs_root_{name.lower().replace('.', '_')}"),
        )

    evidence = ("xdvdfs_magic", "xdvdfs_root_default_executable_" + ("both" if found else "missing"))
    if probe.walk_truncated:
        evidence += ("xdvdfs_root_walk_truncated",)
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.5,
        reason=(
            "XDVDFS volume at 0x10000, but its root directory holds "
            + ("both DEFAULT.XBE and DEFAULT.XEX" if found else "neither DEFAULT.XBE nor DEFAULT.XEX")
        ),
        warnings=["Xbox disc image whose platform could not be read, select Xbox or Xbox 360 manually"],
        status=Status.CONTAINER_ONLY, method=Method.MAGIC, container="xdvdfs",
        evidence=evidence, candidates=_xbox_candidates(evidence),
    )


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


# ── CHD ──────────────────────────────────────────────────────────────────────
#
# detect_chd() maps chd_validator.detect_chd_platform()'s result onto the
# CHD contract below. It reads nothing itself, it only inspects the
# validator's ScanResult:
#   - result.container already "chd_cd" / "chd_dvd" / "chd_gd", or
#   - one of the tag evidence codes below in result.evidence (the
#     validator's _tag_result() emits "chd_meta_" plus the lower-cased tag:
#     chd_meta_cht2, chd_meta_chtr, chd_meta_chcd, chd_meta_chgd,
#     chd_meta_chgt, chd_meta_dvd), and
#   - an Issue with code IssueCode.CHD_VERSION_UNSUPPORTED for a non-v5
#     header.
#
# Contract:
#   CHT2 / CHTR / CHCD tag -> era None, container_only, container "chd_cd",
#                             candidates ps1, ps2
#   DVD tag                -> era None, container_only, container "chd_dvd",
#                             candidates ps2, xbox, xbox360
#   CHGD / CHGT tag        -> era dreamcast, guess (not authoritative: Sega
#                             NAOMI GD-ROMs share the tag), container "chd_gd"
#   non-v5 header          -> era None, the validator's issue passed through
# No era is ever derived from the CHD logical size.

_CHD_TAG_EVIDENCE: dict[str, frozenset[str]] = {
    "chd_gd": frozenset({"chd_meta_chgd", "chd_meta_chgt"}),
    "chd_dvd": frozenset({"chd_meta_dvd"}),
    "chd_cd": frozenset({"chd_meta_chtr", "chd_meta_cht2", "chd_meta_chcd"}),
}
_CHD_CANDIDATE_ERAS: dict[str, tuple[str, ...]] = {
    "chd_cd": ("ps1", "ps2"),
    "chd_dvd": ("ps2", "xbox", "xbox360"),
}


def detect_chd(path: Path) -> ScanResult:
    return _reconcile_chd_result(chd_validator.detect_chd_platform(path))


def _chd_media_container(result: ScanResult) -> str | None:
    """"chd_cd", "chd_dvd" or "chd_gd" from the validator's container or tag
    evidence; None when neither names a track tag. GD wins over DVD over CD
    when several codes are present."""
    if result.container in _CHD_TAG_EVIDENCE:
        return result.container
    evidence = set(result.evidence)
    for container, codes in _CHD_TAG_EVIDENCE.items():
        if evidence & codes:
            return container
    return None


def _reconcile_chd_result(result: ScanResult) -> ScanResult:
    """Apply the CHD contract above to a validator result. Results that
    already follow it, and era-less results it does not cover (no CHD magic,
    read errors, no recognised tag), are returned unchanged. A result with an
    era but no recognised tag loses the era (container_only)."""
    version_unsupported = any(issue.code == IssueCode.CHD_VERSION_UNSUPPORTED for issue in result.issues)
    if version_unsupported:
        if result.era is None:
            return result
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0, reason=result.reason,
            warnings=list(result.warnings), status=Status.UNSUPPORTED, method=Method.STRUCTURAL,
            container=result.container, evidence=result.evidence, issues=result.issues,
        )

    container = _chd_media_container(result)
    evidence = result.evidence

    if container == "chd_gd":
        was_dreamcast = result.era == "dreamcast"
        if was_dreamcast and result.status is Status.GUESS and result.container == container:
            return result
        return ScanResult(
            title=None, platform=None, era="dreamcast",
            confidence=result.confidence if was_dreamcast else 0.85,
            reason=result.reason if was_dreamcast else "CHD metadata GD-ROM track tag (CHGD/CHGT) indicates Dreamcast",
            warnings=list(result.warnings),
            # Not authoritative: Sega NAOMI GD-ROM images carry the same tag.
            status=Status.GUESS, method=Method.STRUCTURAL, authoritative=False, container=container,
            evidence=evidence, issues=result.issues,
        )

    if container in _CHD_CANDIDATE_ERAS:
        if (
            result.era is None and result.status is Status.CONTAINER_ONLY
            and result.container == container and result.candidates
        ):
            return result
        eras = _CHD_CANDIDATE_ERAS[container]
        media = "CD" if container == "chd_cd" else "DVD"
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.3,
            reason=f"CHD metadata {media} track tag confirms a {media} image but names no platform",
            warnings=list(result.warnings) or [f"CHD {media} image, could be {', '.join(eras)}, select the era manually"],
            status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL, container=container,
            evidence=evidence, issues=result.issues,
            candidates=tuple(Candidate(era, tier_for_confidence(0.3), evidence) for era in eras),
        )

    if result.era is not None:
        # No recognised tag, so nothing here may name an era: whatever the
        # validator (or a replacement for it) based one on, such as the
        # logical size, is dropped.
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            reason="CHD container detected but no recognised platform metadata tag found",
            warnings=list(result.warnings), status=Status.CONTAINER_ONLY, method=Method.STRUCTURAL,
            container=result.container or "chd", evidence=result.evidence, issues=result.issues,
        )
    return result


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
                    reason=f"ISO volume label contains '{_display_label(vol_id)}'",
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
                    reason=f"ISO {label} '{_display_label(meta)}' matches known DOS publisher '{matched}'",
                    method=Method.STRUCTURAL, authoritative=False, evidence=(f"pvd_{label}_dos_publisher",),
                )

        return _null

    except Exception as exc:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.0,
            # Class name only: the message can quote a path or other
            # caller-controlled text.
            reason=f"ISO PVD read error: {type(exc).__name__}",
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
    boundary puts ps2 first, at a higher tier); it never names an era and
    never changes the method, which is Method.STRUCTURAL at every size (the
    PVD fields are what narrowed the answer), so an md5 hit is reconciled
    with this result the same way whatever the file size. A stat failure
    leaves the default order.
    """
    try:
        over_dvd5 = iso_path.stat().st_size > DVD5_SIZE_THRESHOLD_BYTES
    except OSError:
        over_dvd5 = False
    if over_dvd5:
        evidence += ("size_over_dvd5",)
        candidates = (
            Candidate("ps2", tier_for_confidence(0.5), evidence),
            Candidate("ps1", tier_for_confidence(0.2), evidence),
        )
    else:
        candidates = tuple(Candidate(ps, tier_for_confidence(0.4), evidence) for ps in ("ps1", "ps2"))
    return ScanResult(
        title=None, platform=None, era=None, confidence=0.4,
        reason=(
            f"ISO volume label '{_display_label(vol_id)}', publisher '{_display_label(publisher)}' "
            "suggest PlayStation, but no SYSTEM.CNF BOOT/BOOT2 key could be read to tell PS1 from PS2"
        ),
        warnings=["PlayStation disc without a readable SYSTEM.CNF BOOT/BOOT2 key, select PS1 or PS2 manually"],
        status=Status.AMBIGUOUS, method=Method.STRUCTURAL, container="iso9660",
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

    iso9660_confirmed means xbox_image.has_iso9660_magic() found the ISO 9660
    magic and detect_iso() found no XDVDFS layout. era stays None either way
    and at every size (the size only lists candidates), because a
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
        # The size names two candidates and no era, confirmed ISO 9660 or
        # not: an ISO 9660 image over 4 GiB is not an Xbox rip by size alone
        # (ordinary PC DVDs are this size too).
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
