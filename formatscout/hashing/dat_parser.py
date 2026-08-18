import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from ..constants import DAT_FILE_READ_CAP_BYTES

logger = logging.getLogger(__name__)

# Redump/No-Intro DAT <header><name> platform strings, checked in order
# (most-specific first):
# - "PlayStation 3" before "PlayStation 2" before the bare "PlayStation"
#   substring.
# - "Xbox 360" before the bare "Xbox" substring.
# - "Super Nintendo Entertainment System" before the "Nintendo
#   Entertainment System" substring it contains.
#
# The bare "playstation" and "xbox" markers are still substring matches.
# A future platform string containing one of them ("PlayStation 4/5",
# "PlayStation Portable/Vita", "Xbox One/Series") with no more-specific
# marker ahead of it in this list will silently fall into ps1/xbox, the
# same way PS3 and Xbox 360 did before this fix. None of those platforms
# are in this package's era vocabulary yet. Do not add a marker for one
# without deciding on its era value first.
#
# Confirmed against real Redump DAT header text in hash_index.json:
# "Sony - PlayStation", "Sony - PlayStation 2", "Sony - PlayStation 3",
# "Microsoft - Xbox", "Microsoft - Xbox 360", presumably "Sega -
# Dreamcast" following the same pattern.
#
# The NES/SNES/N64 entries follow No-Intro's "<Manufacturer> - <full
# system name>" convention but are unverified against a real No-Intro DAT.
_ERA_MARKERS: list[tuple[str, str]] = [
    ("playstation 3", "ps3"),
    ("playstation 2", "ps2"),
    ("playstation", "ps1"),
    ("xbox 360", "xbox360"),
    ("xbox", "xbox"),
    ("dreamcast", "dreamcast"),
    ("super nintendo entertainment system", "snes"),
    ("nintendo entertainment system", "nes"),
    ("nintendo 64", "n64"),
]

# Deliberately no "ibm pc compatible" entry.
# - Redump's single PC disc category covers DOS and Windows 95/98/XP
#   together. The header name alone cannot separate those eras.
# - Any blanket mapping, "dos" included, would let a confidence=1.0 hash
#   match silently mislabel a Windows-era title.
# - Falling through to era=None is the safe default until a per-title
#   strategy exists (inspecting individual game entries, not the shared
#   header name).
# Do not reintroduce a blanket mapping for this platform.


def _resolve_era_from_platform(platform: str | None) -> str | None:
    if not platform:
        return None
    lowered = platform.lower()
    for marker, era in _ERA_MARKERS:
        if marker in lowered:
            return era
    return None


def _reject_internal_entities(raw: bytes, path: Path) -> None:
    """Refuse a DAT whose DOCTYPE declares entities in its internal subset.

    xml.etree.ElementTree expands internal entity declarations. That makes
    it vulnerable to entity-expansion denial of service on untrusted input, 
    and DAT files are third-party downloads.

    Two reasons this is rejected up front instead of mitigated:
    - defusedxml, the usual mitigation, is a new runtime dependency this
      package does not have.
    - This Python's C XMLParser exposes no expat handle to install entity
      handlers on.

    Only the internal subset (the bracketed section of a DOCTYPE) is
    inspected. That is the sole place an entity can be declared: external
    DTDs are never fetched by ElementTree's default parser, so the
    external DOCTYPE real Logiqx/Redump/No-Intro DATs carry stays valid.

    The bracket scan is textual, not a real DTD parse. A "]" appearing
    before the internal subset (inside a quoted SYSTEM identifier, say)
    ends the inspected window early and lets a later entity declaration
    through.
    """
    doctype = raw.find(b"<!DOCTYPE")
    if doctype == -1:
        return
    subset_start = raw.find(b"[", doctype)
    subset_end = raw.find(b"]", doctype)
    if subset_start == -1 or subset_end <= subset_start:
        return
    if b"<!ENTITY" in raw[subset_start:subset_end]:
        raise ValueError(
            f"Failed to parse DAT file {path}: refusing a document that declares "
            "XML entities in its DOCTYPE internal subset (entity-expansion risk)"
        )


def parse_dat(path: Path) -> list[dict]:
    source = path.stem
    records: list[dict] = []

    size = path.stat().st_size
    if size > DAT_FILE_READ_CAP_BYTES:
        raise ValueError(
            f"Failed to parse DAT file {path}: file is {size} bytes, exceeding the "
            f"{DAT_FILE_READ_CAP_BYTES}-byte cap for DAT files"
        )

    raw = path.read_bytes()
    _reject_internal_entities(raw, path)

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse DAT file {path}: {exc}") from exc

    # Platform hint lives in <header><name> on TOSEC and some Redump DATs only.
    platform: str | None = None
    header = root.find("header")
    if header is not None:
        name_el = header.find("name")
        if name_el is not None and name_el.text:
            platform = name_el.text.strip()

    for game in root.iter("game"):
        game_name = game.get("name")
        if not game_name:
            logger.warning("Skipping <game> with no name attribute in %s", path.name)
            continue

        for rom in game.iter("rom"):
            sha1 = (rom.get("sha1") or "").lower().strip()
            md5 = (rom.get("md5") or "").lower().strip()
            # Logiqx/Redump/TOSEC spell the attribute "crc"; "crc32" is a
            # tolerated variant seen in some hand-rolled DATs.
            crc32 = (rom.get("crc") or rom.get("crc32") or "").lower().strip()

            if not sha1 and not md5 and not crc32:
                logger.warning(
                    "Skipping rom '%s' in game '%s' (%s): no hash fields",
                    rom.get("name", ""),
                    game_name,
                    path.name,
                )
                continue

            record: dict = {
                "title": game_name,
                "platform": platform,
                "era": _resolve_era_from_platform(platform),
                "source": source,
            }
            if sha1:
                record["sha1"] = sha1
            if md5:
                record["md5"] = md5
            if crc32:
                record["crc32"] = crc32

            records.append(record)

    return records
