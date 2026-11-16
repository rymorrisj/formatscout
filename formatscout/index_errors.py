"""Public exception types and the issue code for hash-index failures.

Kept free of other package imports so hashing/hash_lookup.py (which raises
them) and index.py (which re-exports them) can both import it without a cycle.
"""

# Issue.code attached to a result when the hash index could not be obtained or
# used (detect(): next to the "hash index unavailable" warning; classify() and
# verify(): on the "unchecked" result).
INDEX_UNAVAILABLE = "INDEX_UNAVAILABLE"


class IndexUnavailable(OSError):
    """The hash index cannot be obtained or used.

    Raised for: downloads disabled by FORMATSCOUT_OFFLINE, a download attempt
    suppressed by the failure backoff, a failed download (the original error
    is chained as __cause__, including a size-cap or deadline failure), an
    index path whose default location cannot be computed (no home directory),
    an unreadable index file, and an index that fails the integrity checks
    (see IndexIntegrityError, a subclass).

    Deliberately not a FileNotFoundError: classify()/verify() treat that as
    "no index built at a custom path" and degrade to an empty index, whereas
    this means the index exists or should exist and could not be trusted or
    fetched.
    """


class IndexIntegrityError(IndexUnavailable):
    """An index failed an integrity check.

    Raised for a download whose sha256 does not match the pinned value, and
    for an index file that is oversized, not valid JSON, or malformed. It is a
    subclass of IndexUnavailable (so one ``except IndexUnavailable`` covers
    every index failure); catch it first to tell "untrustworthy content" from
    "could not get it".
    """
