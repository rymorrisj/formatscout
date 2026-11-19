import math
from dataclasses import KW_ONLY, dataclass, field
from enum import StrEnum
from typing import Literal, NamedTuple

# The full era vocabulary any detection tier can assign to ScanResult.era.
# Confirmed by grepping every `era=` assignment package-wide, not just
# guessed from the platform list. "unknown" and "cdrom_sync_ambiguous" are
# deliberately excluded: both are internal return values of plain str-typed
# helper functions (magic_detect._resolve_ps_generation,
# resolve_ps_generation_from_file, and a magic_signatures.toml sentinel
# compared via ==), never assigned to era= on a ScanResult.
Era = Literal[
    "ps1", "ps2", "ps3",
    "xbox", "xbox360",
    "dreamcast",
    "n64", "nes", "snes",
    "dos", "win95", "win98", "winxp",
]


class Status(StrEnum):
    """How a ScanResult should be interpreted, see ScanResult.status.

    A StrEnum, so each member compares equal to its plain string value
    (Status.GUESS == "guess").

    identified: era is set and authoritative (proof, see ScanResult).
    guess: TRANSITIONAL. era is set but not authoritative (size thresholds,
        extension-only shortcuts, directory heuristics, PE OS-version
        guesses, ...). It exists only because era still carries guesses
        today, and is to be removed once era stops carrying them.
    ambiguous: era is None, but the signal narrows the answer to a few
        candidate eras (see ScanResult.candidates).
    container_only: era is None. The container or filesystem was confirmed
        (ISO 9660, CHD, a cue/bin pair), but nothing named a platform.
    unsupported: era is None. The input was recognised as something this
        package does not map to an era (.nds, an index entry with no era, a
        path that is neither file nor directory).
    no_signal: era is None and nothing usable was found.
    error: era is None because the input could not be examined (missing
        path, read or parse error, the detect() catch-all).
    """
    IDENTIFIED = "identified"
    GUESS = "guess"
    AMBIGUOUS = "ambiguous"
    CONTAINER_ONLY = "container_only"
    UNSUPPORTED = "unsupported"
    NO_SIGNAL = "no_signal"
    ERROR = "error"


class Method(StrEnum):
    """Which rule produced a ScanResult, see ScanResult.method.

    hash_sha1/hash_md5/hash_crc32: hash-index hit on the file's own bytes.
    chd_header_claim: hash-index hit on the rawsha1 a CHD header claims for
        its raw data (read from the header, never checked against the hunks).
    magic: fixed-offset signature bytes (magic_signatures.toml, XDVDFS).
    structural: parsed structure (ISO 9660 PVD/root directory, CHD metadata
        chain, cue TRACK type).
    system_cnf: PlayStation SYSTEM.CNF BOOT/BOOT2 key.
    directory_marker: marker file or folder names in a directory tree.
    pe_header: MZ/PE header fields of an executable.
    extension: file extension alone.
    size_heuristic: a file or logical size threshold decided the result.
    title_match: an exact normalized filename-title match against the hash
        index, scoped to the candidate eras of a container (used for CHDs,
        whose raw bytes cannot be hash-matched). Never authoritative.
    none: no rule produced a signal (no_signal and error results).
    """
    HASH_SHA1 = "hash_sha1"
    HASH_MD5 = "hash_md5"
    HASH_CRC32 = "hash_crc32"
    CHD_HEADER_CLAIM = "chd_header_claim"
    MAGIC = "magic"
    STRUCTURAL = "structural"
    SYSTEM_CNF = "system_cnf"
    DIRECTORY_MARKER = "directory_marker"
    PE_HEADER = "pe_header"
    EXTENSION = "extension"
    SIZE_HEURISTIC = "size_heuristic"
    TITLE_MATCH = "title_match"
    NONE = "none"


class Tier(StrEnum):
    """Coarse confidence band, used by ScanResult.candidates. The float
    ScanResult.confidence is unchanged; tier_for_confidence() maps one to the
    other."""
    CERTAIN = "certain"
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


# Lower bounds of each Tier, highest first. The single definition of the
# confidence -> Tier mapping (README "Result contract" documents the same
# ranges): certain 1.0, strong [0.85, 1.0), moderate [0.5, 0.85),
# weak (0.0, 0.5), none 0.0 or below (and NaN).
_TIER_FLOORS: tuple[tuple[float, Tier], ...] = (
    (1.0, Tier.CERTAIN),
    (0.85, Tier.STRONG),
    (0.5, Tier.MODERATE),
)


def tier_for_confidence(confidence: float) -> Tier:
    """Map a ScanResult.confidence float to its Tier band.

    0.0, negatives and NaN are Tier.NONE; 1.0 and above are Tier.CERTAIN.
    """
    if math.isnan(confidence) or confidence <= 0.0:
        return Tier.NONE
    for floor, tier in _TIER_FLOORS:
        if confidence >= floor:
            return tier
    return Tier.WEAK


class Candidate(NamedTuple):
    """One era an ambiguous result could be: (era, tier, evidence_codes)."""
    era: str
    tier: Tier
    evidence: tuple[str, ...] = ()


class Issue(NamedTuple):
    """A machine-readable problem attached to a result: (code, message).
    Complements the free-text warnings list, which is unchanged."""
    code: str
    message: str


class IssueCode(StrEnum):
    """Issue codes introduced with the correctness batch. A StrEnum, so each
    member compares equal to its uppercase string value and can be passed
    anywhere an Issue code string is expected. Older codes (INDEX_UNAVAILABLE,
    POINTER_REJECTED, ...) remain plain strings.

    CLAIM_UNVERIFIED: the result rests on a claim that was not checked against
        the data (a CHD header rawsha1 hit).
    HASH_WEAK: the era came from an md5 or crc32 hit alone, with no
        corroborating structural evidence.
    CONFLICTING_EVIDENCE: a hash hit named a different era than the structure.
    WRONG_ERA: the best title match lies outside the era that was supplied.
    AMBIGUOUS_CONTAINER: several candidate eras matched the title of a
        container whose platform could not be read.
    UNSUPPORTED_LAYOUT: a recognised container layout this package does not
        parse.
    CHD_VERSION_UNSUPPORTED: a CHD header version other than 5.
    """
    CLAIM_UNVERIFIED = "CLAIM_UNVERIFIED"
    HASH_WEAK = "HASH_WEAK"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    WRONG_ERA = "WRONG_ERA"
    AMBIGUOUS_CONTAINER = "AMBIGUOUS_CONTAINER"
    UNSUPPORTED_LAYOUT = "UNSUPPORTED_LAYOUT"
    CHD_VERSION_UNSUPPORTED = "CHD_VERSION_UNSUPPORTED"


_ERA_STATUSES = frozenset({Status.IDENTIFIED, Status.GUESS})

# ClassifyResult.hash_kind's value space.
HashKind = Literal["sha1", "chd_rawsha1", "md5", "crc32"]


@dataclass(slots=True, frozen=True)
class HashFileResult:
    """hash_file()'s result: the three hashes computed from a single read of
    a file's bytes (hashing/hash_lookup.py), used directly by callers that
    need a raw hash rather than a full detection/verification/classification
    result, and internally by lookup(), verify(), and classify() as the
    shared hashing primitive underneath all three.
    """
    sha1: str
    md5: str
    crc32: str


@dataclass(slots=True)
class ScanResult:
    """detect()'s full-pipeline identification result: what a path is,
    with confidence, plus flags describing what a caller must do before the
    media is usable.

    requires_extraction: set only by iso_detect.detect_iso() when an XDVDFS
        volume is positively identified at an XGD game-partition offset (a
        raw Xbox/360 DVD rip, not a bare xISO). True means the caller must run
        extract-xiso on it before launch, mirrors requires_install's "not
        directly usable yet" role but for a format-conversion step instead of
        an install step. Never set from file size.

    The fields above are unchanged; era is still populated exactly as before
    (including guesses). The keyword-only fields below say how to read it:

    status: a Status. Use this, not "era is None", to decide what a result
        means. Left out, it is derived: identified when era is set and
        authoritative is True, guess when era is set otherwise, no_signal when
        era is None. "guess" is TRANSITIONAL: it exists only because era still
        carries non-authoritative answers, and will be removed once era stops
        carrying guesses.
    method: a Method naming the rule that produced the result (none when no
        rule produced a signal).
    authoritative: True only when era was determined from proof (a sha1 index
        hit on a non-CHD file's own bytes, a platform-unique magic signature).
        A CHD header rawsha1 hit is a claim (the header is forgeable and not
        checked against the hunks) and an md5 hit is corroboration only (the
        index stores no sizes yet), so both are False. Always False when era
        is None.
    container: the confirmed container/filesystem, when one was confirmed:
        "iso9660", "xdvdfs", "bin_cue", "chd" (a CHD with no recognised media
        tag, or an unsupported header version), "chd_cd" (CHT2, CHTR or CHCD
        tag), "chd_dvd" (DVD tag) or "chd_gd" (CHGD or CHGT tag). None
        otherwise.
    candidates: the eras the signal narrows to, as Candidate(era, tier,
        evidence_codes) tuples. Set for ambiguous results and for
        container_only results whose container narrows the eras (a CD or DVD
        CHD, an XDVDFS volume with no or both executables); empty otherwise.
    evidence: short stable codes for the specific signals behind the result
        (e.g. "pvd_volume_label_keyword"), finer-grained than method.
    issues: Issue(code, message) tuples for problems worth acting on (index
        unavailable, rejected pointer, ...). warnings is still populated as
        before; issues do not replace it.
    platform_hint: a human-readable platform the signal points at when the
        platform field is not set (e.g. "Nintendo DS" for an unsupported .nds).

    __post_init__ coerces plain strings and tuples to the enum/NamedTuple
    types and raises ValueError for contradictory combinations (an era-less
    result marked authoritative or identified/guess, an era-carrying result
    with any other status, or a status that disagrees with authoritative).
    """
    title: str | None
    platform: str | None
    era: Era | None
    confidence: float
    reason: str
    requires_install: bool = False
    requires_extraction: bool = False
    warnings: list[str] = field(default_factory=list)
    _: KW_ONLY
    # None only as a constructor default: __post_init__ always replaces it
    # with the derived Status, so a constructed ScanResult never holds None.
    status: Status = None  # type: ignore[assignment]
    method: Method = Method.NONE
    authoritative: bool = False
    container: str | None = None
    candidates: tuple[Candidate, ...] = ()
    evidence: tuple[str, ...] = ()
    issues: tuple[Issue, ...] = ()
    platform_hint: str | None = None

    def __post_init__(self) -> None:
        self.method = Method(self.method)
        self.authoritative = bool(self.authoritative)
        self.evidence = tuple(self.evidence)
        self.issues = tuple(Issue(*issue) for issue in self.issues)
        self.candidates = tuple(
            Candidate(c[0], Tier(c[1]), tuple(c[2]) if len(c) > 2 else ()) for c in self.candidates
        )
        has_era = self.era is not None
        if self.status is None:
            if not has_era:
                self.status = Status.NO_SIGNAL
            elif self.authoritative:
                self.status = Status.IDENTIFIED
            else:
                self.status = Status.GUESS
        else:
            self.status = Status(self.status)
        if not has_era and self.authoritative:
            raise ValueError("authoritative=True requires an era")
        if has_era != (self.status in _ERA_STATUSES):
            raise ValueError(f"status {self.status!r} does not fit era {self.era!r}")
        if has_era and (self.status is Status.IDENTIFIED) != self.authoritative:
            raise ValueError(f"status {self.status!r} does not fit authoritative={self.authoritative}")


def null_scan_result() -> ScanResult:
    """Zero-confidence, no-signal ScanResult.

    A factory, not a shared module-level constant: ScanResult is a mutable
    dataclass (not frozen), and detector.py sets requires_install on the
    result it receives back from a detection tier. A single shared instance
    returned by reference from five call sites would let that mutation leak
    into every other caller's "no signal" result.
    """
    return ScanResult(title=None, platform=None, era=None, confidence=0.0, reason="")


@dataclass(slots=True)
class VerifyResult:
    """Result of verify(), a hash-only re-check of a single file, distinct
    from ScanResult, which is detect()'s full-pipeline identification result.

    status:
        "not_in_index", checked first: computed sha1 is not a key in the
            hash index. This applies even when computed sha1 equals
            expected_sha1. A file that changed since it was recorded usually
            gets a new sha1 that is not in the index, so it lands here.
        "matched", computed sha1 is in the hash index and equals
            expected_sha1. The comparison is exact and case-sensitive;
            expected_sha1 is not normalized.
        "mismatched", computed sha1 is in the hash index but differs from
            expected_sha1. In practice this means the file is a different
            indexed file.
        "unchecked", the file hashed fine but the hash index could not be
            obtained or used (offline mode, download backoff or failure, an
            oversized or corrupt index, an unreadable index file), so no
            comparison was possible; computed_sha1 is still set. issues holds
            an INDEX_UNAVAILABLE issue. verify(strict=True) raises
            IndexUnavailable instead. A file that cannot be read still raises
            OSError.

    The hash is over the raw file bytes, including for .chd files. The
    embedded CHD rawsha1 is not used here.

    issues: keyword-only, defaulted. Issue(code, message) tuples; today only
    "INDEX_UNAVAILABLE" for "unchecked".
    """
    status: Literal["matched", "mismatched", "not_in_index", "unchecked"]
    computed_sha1: str
    expected_sha1: str
    reason: str
    _: KW_ONLY
    issues: tuple[Issue, ...] = ()

    def __post_init__(self) -> None:
        self.issues = tuple(Issue(*issue) for issue in self.issues)


@dataclass(slots=True)
class ClassifyResult:
    """Five-state verification classification for a single file, combining
    exact hash-tier lookup (sha1/md5/crc32) with a fuzzy title-match fallback.
    Unlike verify(), this needs no prior expected_sha1, it establishes a
    classification from scratch, used both at ingest and on a manual re-check.

    status:
        "verified", the file's own sha1 exactly matches a hash_index.json
            entry. Highest confidence, the only state that should ever read
            as a positive confirmation. A CHD never reaches it: a CHD's
            header rawsha1 is a claim that is not checked against the image
            data, so that hit is "caution".
        "caution", a weaker hit: either the sha1 of a CHD's header rawsha1
            matched (hash_kind "chd_rawsha1", issue CLAIM_UNVERIFIED), or no
            sha1 matched but md5 or crc32 exactly matches an entry. Real
            index coverage, weaker confidence than a verified sha1 hit.
        "mismatch", no hash of any kind matched, but the title is an
            approximate (>=threshold) match for a title that does exist in
            hash_index.json. Expected to happen often against an inherently
            incomplete public hash catalog, not itself a sign the file is
            bad. The title match is the best difflib SequenceMatcher ratio,
            after bracketed tags are stripped, and it counts only if it
            reaches the threshold (default 0.80) and the numbers in both
            titles (digits and Roman numerals) are equal, so sequels that
            differ only by a number do not match. The supplied era is
            searched on its own first: a match there at or above the
            threshold is used, even if another era scores higher. Only when
            the supplied era has no such match are the other eras searched,
            and if one matches the status is still "mismatch" but
            matched_era names that era and the issue WRONG_ERA is added.
            With era=None the title search is skipped.
        "not_in_index", no hash matched and no confident title match either.
            Neutral, "we have no data on this file", not a warning.
        "unchecked", no classification was possible, for one of two reasons
            that the issue code tells apart. "HASH_FAILED": the file could not
            be hashed at all (missing, unreadable, permission error); only an
            OSError from hashing produces this. "INDEX_UNAVAILABLE": the file
            hashed fine but the hash index could not be obtained or used
            (offline mode, download backoff or failure, an oversized or
            corrupt index, an unreadable index file). classify(strict=True)
            raises IndexUnavailable for the latter instead of returning it.

    computed_sha1 is the file's own raw sha1 (hash_file()'s result), persisted
    whenever hashing succeeds, regardless of which status was reached. It is
    None only for "unchecked" with a "HASH_FAILED" issue. This is not the embedded CHD rawsha1 used
    internally for the verified-tier lookup, a caller needing that value
    should use validators.chd_validator.extract_embedded_sha1 directly.

    matched_title/similarity are populated only for "mismatch": the specific
    index title the fuzzy match landed on and its similarity ratio, useful
    for logging, not required for handling the status itself.

    Keyword-only, defaulted additions (statuses and the fields above are
    unchanged):

    matched_era: the era of the index entry a hash matched ("verified",
        "caution"), or, for "mismatch", the era of the matched title (the
        supplied era, unless WRONG_ERA is reported). None otherwise, and None
        when the matched entry's era is missing or not a string.
    hash_kind: which hash matched: "sha1" (the file's own sha1),
        "chd_rawsha1" (a CHD header's embedded rawsha1), "md5" or "crc32".
        None when no hash matched.
    issues: Issue(code, message) tuples: "HASH_FAILED" or "INDEX_UNAVAILABLE"
        for "unchecked", "INDEX_MISSING" when a missing custom index file was
        treated as empty, "CHD_RAWSHA1_MISSING" when a .chd had no usable
        embedded rawsha1 and its raw file sha1 was looked up instead,
        "CLAIM_UNVERIFIED" on a CHD header rawsha1 hit, and "WRONG_ERA" on a
        "mismatch" whose best title match lies outside the supplied era.
    """
    status: Literal["verified", "caution", "mismatch", "not_in_index", "unchecked"]
    computed_sha1: str | None
    matched_title: str | None
    similarity: float | None
    reason: str
    _: KW_ONLY
    matched_era: str | None = None
    hash_kind: HashKind | None = None
    issues: tuple[Issue, ...] = ()

    def __post_init__(self) -> None:
        self.issues = tuple(Issue(*issue) for issue in self.issues)
