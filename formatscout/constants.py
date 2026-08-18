"""Constants shared by more than one detection module.

Exists so that a module needing only a shared literal does not have to import
another detection module to reach it (directory_detect.py previously imported
iso_detect.py purely for the pointer-file read cap). Internal to the package,
nothing here is part of the public surface, see __init__.py.
"""

# Cue sheets, GDI files and AUTORUN.INF files are a few hundred bytes. Cap the
# read so an accidentally huge or deliberately padded pointer file cannot be
# pulled into memory whole just to find one FILE=/OPEN= line.
POINTER_FILE_READ_CAP_BYTES = 64 * 1024

# ISO 9660 root directories are a few KB at most. Both the plain-ISO reader
# (iso_detect._read_root_dir) and the raw Mode 2 CD reader
# (magic_detect._resolve_ps_generation) take this length from a 32-bit
# little-endian field read straight out of the image, so a corrupt or crafted
# file can declare up to 4 GB. Cap what either of them will allocate.
ROOT_DIR_READ_CAP_BYTES = 64 * 1024

# ISO 9660 logical sector size, the unit root-directory LBAs are counted in.
# On a plain .iso this is also the physical stride; on a raw Mode 2 image it is
# the user-data payload carried inside each larger physical sector.
ISO_LOGICAL_SECTOR_BYTES = 2048

# The "larger than a single-layer disc image" boundary, shared by
# xbox_image.detect_xbox_image_type()'s raw-DVD-rip check and
# iso_detect._iso_size_fallback()'s size heuristic. Previously these were two
# separate literals (4_000_000_000 decimal and 4 * 1024 ** 3 binary), so a file
# between them landed on opposite sides of the same nominal 4 GB line depending
# on which code path reached it first. Binary GB (4 GiB).
#
# Distinct from the 4.7 GB DVD-5 boundary in iso_detect.detect_from_pvd()
# (DVD5_SIZE_THRESHOLD_BYTES below), which is deliberately decimal because
# optical-disc capacities are quoted that way.
DVD_SIZE_THRESHOLD_BYTES = 4 * 1024 ** 3

# Redump/No-Intro/TOSEC DAT files are XML text, typically a few MB to tens of
# MB even for large platforms. dat_parser.parse_dat() reads the whole file
# into memory before handing it to ET.fromstring(), so an untrusted or
# corrupt DAT far past that size would be read whole just to fail parsing.
# Cap it, mirroring the POINTER_FILE_READ_CAP_BYTES/ROOT_DIR_READ_CAP_BYTES
# pattern above.
DAT_FILE_READ_CAP_BYTES = 500 * 1024 * 1024

# Mirrors chd_validator._MAX_METADATA_ENTRIES: caps the depth-2 directory scan
# in directory_detect._detect_from_directory() so a directory tree with an
# enormous number of subdirectories/children cannot make the scan accumulate
# names unboundedly. This is a detection heuristic, not a hard requirement, so
# the scan stops early rather than raising.
DIRECTORY_DEPTH2_SCAN_CAP_ENTRIES = 4096

# ~800 MB, the CD-vs-DVD size split. Previously three independent literals
# (chd_validator.py, iso_detect.py, detector.py) that all meant the same
# heuristic boundary. Decimal, matching how optical media capacity is quoted.
CD_SIZE_THRESHOLD_BYTES = 800 * 1024 * 1024

# The 4.7 GB DVD-5 boundary iso_detect.detect_from_pvd() uses to split a
# SLUS/SCES/etc.-prefixed volume label into PS1 (CD-sized) vs PS2 (DVD-sized).
# Deliberately decimal, unlike the binary-GiB DVD_SIZE_THRESHOLD_BYTES above,
# because optical-disc capacities are quoted that way. Distinct boundary, do
# not merge with DVD_SIZE_THRESHOLD_BYTES.
DVD5_SIZE_THRESHOLD_BYTES = 4_700_000_000

# No DEFAULT_INDEX_PATH constant here. hash_lookup.default_index_path() is
# the single source of truth for that path; detector.py, classify.py, and
# verify.py each call it directly rather than this module re-exporting it.
# Importing formatscout.hashing here would pull in validators.chd_validator,
# which imports CD_SIZE_THRESHOLD_BYTES back from this module, a real
# circular import: constants -> hash_lookup -> chd_validator -> constants.
# Sequencing around it (importing hash_lookup after the constants it needs
# are defined) previously "worked" for normal imports but broke
# test_magic_detect.py's isolated-package-copy test, which copies only
# constants.py alongside magic_detect.py and has no hashing/ subpackage to
# satisfy the transitive import. This module must have zero non-stdlib
# imports.
