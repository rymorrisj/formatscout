import struct
from pathlib import Path

from ..xbox_image import is_xiso
from .magic.magic_detect import detect_from_magic
from .result import ScanResult
from .validators import bin_validator
from .validators import chd_validator

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

    if is_xiso(path):
        return ScanResult(
            title=None, platform=None, era="xbox", confidence=0.9,
            reason="XDVDFS magic 'MICROSOFT*XBOX*MEDIA' found at 0x10000 — Original Xbox disc image",
        )

    return _iso_size_fallback(path)


def detect_cue(path: Path, dir_cache: dict[Path, list[Path]] | None = None) -> ScanResult:
    bin_path = _cue_bin_path(path)
    if bin_path is None:
        candidate = path.with_suffix(".bin")
        if candidate.exists():
            bin_path = candidate
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
    return chd_validator.detect(path)


# ── ISO 9660 PVD ─────────────────────────────────────────────────────────────

def detect_from_pvd(iso_path: Path) -> ScanResult:
    _null = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
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
        dir_data = _read_root_dir(iso_path, pvd)

        if "PS3_DISC.SFB" in _root_dir_entry_names(dir_data):
            return ScanResult(
                title=None, platform=None, era="ps3", confidence=0.9,
                reason="ISO 9660 root directory contains PS3_DISC.SFB — PS3 disc image",
            )

        xbe_result = _detect_from_xbe_scan(dir_data)
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
            if vol_starts_ps and size_bytes > 4_700_000_000:
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
    into both _root_dir_entry_names and _detect_from_xbe_scan below instead of
    each independently reopening the file and re-deriving the same LBA/size math.
    """
    if len(pvd) < 190:
        return b""
    root_lba = struct.unpack_from("<I", pvd, 158)[0]
    root_size = struct.unpack_from("<I", pvd, 166)[0]
    if root_lba == 0 or root_size == 0 or root_size > 65536:
        return b""
    try:
        with iso_path.open("rb") as fh:
            fh.seek(root_lba * 2048)
            return fh.read(root_size)
    except OSError:
        return b""


def _root_dir_entry_names(dir_data: bytes) -> list[str]:
    """Return upper-cased, version-stripped file/dir names from raw ISO 9660
    root directory bytes (as produced by _read_root_dir).
    """
    names: list[str] = []
    i = 0
    while i < len(dir_data):
        rec_len = dir_data[i]
        if rec_len == 0:
            i = (i | 2047) + 1
            continue
        if i + 33 > len(dir_data):
            break
        name_len = dir_data[i + 32]
        if i + 33 + name_len > len(dir_data):
            break
        name = dir_data[i + 33: i + 33 + name_len].decode("ascii", errors="replace")
        names.append(name.split(";")[0].upper())
        i += rec_len
    return names


def _detect_from_xbe_scan(dir_data: bytes) -> ScanResult:
    _null = ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")
    for name in _root_dir_entry_names(dir_data):
        if name.endswith(".XBE"):
            return ScanResult(
                title=None, platform=None, era="xbox", confidence=0.8,
                reason="ISO filesystem contains .xbe — Original Xbox executable",
            )
    return _null


def _iso_size_fallback(path: Path) -> ScanResult:
    try:
        size = path.stat().st_size
    except OSError:
        return ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="no signal found")
    if size > 4 * 1024 ** 3:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason="ISO exceeds 4 GB but no PVD signal",
            warnings=["could be PS2 or Xbox OG — please select era manually"],
        )
    if size < 800 * 1024 * 1024:
        return ScanResult(
            title=None, platform=None, era=None, confidence=0.2,
            reason="ISO under 800 MB but no PVD signal",
            warnings=["era ambiguous — please select era manually"],
        )
    return ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="no signal found")


_POINTER_FILE_READ_CAP_BYTES = 64 * 1024  # cue/gdi pointer files are a few hundred bytes


def _cue_bin_path(cue_path: Path) -> Path | None:
    try:
        with open(cue_path, "rb") as f:
            raw = f.read(_POINTER_FILE_READ_CAP_BYTES)
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.upper().startswith("FILE "):
                parts = line.split('"')
                if len(parts) >= 2:
                    candidate = cue_path.parent / parts[1]
                    if candidate.exists():
                        return candidate
        return None
    except Exception:
        return None
