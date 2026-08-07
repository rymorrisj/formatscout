import logging
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)

# Redump/No-Intro DAT <header><name> platform strings, checked in order
# (most-specific first) so "PlayStation 3" is matched before "PlayStation 2"
# before the bare "PlayStation" substring, "Xbox 360" is matched before the
# bare "Xbox" substring, and "Super Nintendo Entertainment System" is matched
# before the "Nintendo Entertainment System" substring it contains.
#
# The bare "playstation" and "xbox" markers are still substring matches, so
# any future platform string that also contains one of them ("PlayStation 4",
# "PlayStation 5", "PlayStation Portable", "PlayStation Vita", "Xbox One",
# "Xbox Series") and has no more-specific marker of its own ahead of it in
# this list will silently fall into ps1/xbox the same way PS3 and Xbox 360
# did before this fix. None of those platforms are in the vocabulary yet
# (see config/constants.yaml eras), so do not add a marker for one without
# also adding its era value to the vocabulary chain first.
#
# These entries are confirmed against real Redump DAT header text ingested
# into hash_index.json ("Sony - PlayStation", "Sony - PlayStation 2",
# "Sony - PlayStation 3", "Microsoft - Xbox", "Microsoft - Xbox 360",
# presumably "Sega - Dreamcast" following the same pattern).
#
# The NES/SNES/N64 entries below follow No-Intro's standard, well-established
# "<Manufacturer> - <full system name>" naming convention. They have not been
# verified against an actually downloaded No-Intro DAT in this session, but
# the convention itself is well known and consistent, so confidence is high.
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

# Deliberately no "ibm pc compatible" entry. Redump ships one PC disc DAT
# category that covers DOS and Windows 95/98/XP era CD software together, a
# platform-name string alone cannot tell those eras apart the way it can for
# the console entries above. Mapping it to any single era, "dos" included,
# would let a confirmed, confidence=1.0 hash match silently mislabel a
# Windows-era title, the same wrong-answer-with-false-confidence failure
# shape as the PS1 sector-sync bug this project already had to fix once. A
# PC DAT should parse cleanly and fall through to era=None here, the same
# safe default any other unmapped platform name already gets, until a real
# per-title resolution strategy (inspecting individual DAT game entries for
# sub-platform hints, not just the shared header name) is built. Do not
# reintroduce a blanket mapping for this platform.


def _resolve_era_from_platform(platform: str | None) -> str | None:
    if not platform:
        return None
    lowered = platform.lower()
    for marker, era in _ERA_MARKERS:
        if marker in lowered:
            return era
    return None


def parse_dat(path: Path) -> list[dict]:
    source = path.stem
    records: list[dict] = []

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse DAT file {path}: {exc}") from exc

    root = tree.getroot()

    # Extract platform hint from <header><name> if present (TOSEC and some Redump DATs)
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
            try:
                sha1 = (rom.get("sha1") or "").lower().strip()
                md5 = (rom.get("md5") or "").lower().strip()
                # Redump uses "crc", TOSEC may use "crc" as well
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

            except Exception as exc:
                logger.warning(
                    "Skipping malformed rom entry in game '%s' (%s): %s",
                    game_name,
                    path.name,
                    exc,
                )
                continue

    return records
