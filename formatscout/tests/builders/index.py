"""Hash index builders, schema v1 (builder only).

Schema v1 is the on-disk shape hash_lookup parses: a JSON object mapping a
lowercase sha1 hex string to {title, platform, era, source, md5?, crc32?}.
Variants here cover the failure shapes a loader must survive: invalid JSON,
truncated JSON, a non-object top level, a non-object entry, and an index that
is valid but keyed by the wrong hash for the content under test.

Tiny and synthetic only. Never write these to the real cache location.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from formatscout.tests.smart_media_fixtures import hashes_for

SOURCE = "synthetic-corpus"


@dataclass(frozen=True)
class IndexEntry:
    """One v1 index record, keyed by *sha1*."""

    sha1: str
    title: str
    era: str | None
    platform: str | None = None
    md5: str | None = None
    crc32: str | None = None

    def as_record(self) -> dict:
        record: dict = {"title": self.title, "platform": self.platform, "era": self.era, "source": SOURCE}
        if self.md5 is not None:
            record["md5"] = self.md5
        if self.crc32 is not None:
            record["crc32"] = self.crc32
        return record


def entry_for(content: bytes, *, title: str, era: str | None, platform: str | None = None) -> IndexEntry:
    """Entry whose sha1/md5/crc32 are the real hashes of *content*."""
    h = hashes_for(content)
    return IndexEntry(h["sha1"], title, era, platform, md5=h["md5"], crc32=h["crc32"])


def wrong_hash_entry(content: bytes, *, title: str, era: str | None, platform: str | None = None) -> IndexEntry:
    """Entry for *content*'s title and era, keyed by hashes of different bytes.

    The hashes are those of *content* with a trailing byte appended, so a
    file holding *content* itself matches none of sha1, md5 or crc32.
    """
    return entry_for(content + b"\x00", title=title, era=era, platform=platform)


def build_index_v1(entries: list[IndexEntry]) -> dict[str, dict]:
    """Raw v1 index dict for *entries* (later duplicates of a sha1 win)."""
    return {e.sha1: e.as_record() for e in entries}


def write_index_v1(path: Path, entries: list[IndexEntry]) -> Path:
    """Write a valid v1 index to *path* and return it."""
    path.write_text(json.dumps(build_index_v1(entries)), encoding="utf-8")
    return path


def write_corrupt_index(path: Path, kind: str = "invalid_json") -> Path:
    """Write a deliberately broken index to *path* and return it.

    kind: "invalid_json" (garbage text), "truncated" (a valid index cut in
    half), "not_object" (a JSON list), "bad_entry" (an object whose entry is
    not an object), or "empty" (zero bytes).
    """
    good = json.dumps(build_index_v1([IndexEntry("0" * 40, "Corrupt Fixture (USA)", "ps1")]))
    payloads = {
        "invalid_json": b"{ this is not json",
        "truncated": good[: len(good) // 2].encode("utf-8"),
        "not_object": b"[]",
        "bad_entry": json.dumps({"0" * 40: "not-an-object"}).encode("utf-8"),
        "empty": b"",
    }
    if kind not in payloads:
        raise ValueError(f"unknown corruption kind: {kind!r}")
    path.write_bytes(payloads[kind])
    return path
