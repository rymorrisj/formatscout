"""Drive detect() offline over every corpus case (formatscout/tests/corpus/cases.py).

Two tests per case, same ids:
* test_detect_returns_result: detect() returns a ScanResult and did not hit its
  catch-all "unexpected detection error" path. Applies to every case.
* test_expected_era: the era equals Case.expect_era (the correct answer). Skipped
  for NOT_ASSERTED cases. Known-wrong cases are strict xfail, so fixing the
  library turns them into failures until the known_wrong flag is removed.
* test_expected_tags: ScanResult.method/authoritative equal
  Case.expect_method/expect_authoritative, for the cases that set them (never
  known-wrong ones, so their xfail stays about the era alone). A separate
  test, so a tag mismatch never hides behind or changes an era result.

Isolation comes from conftest.py (fake home, network block, nonexistent index
path); FORMATSCOUT_OFFLINE is set as well, and a case that needs a hash index
points detector._INDEX_PATH at a tmp file through the shared fixture helper.
"""

from pathlib import Path

import pytest

from formatscout import detect
from formatscout.result import ScanResult
from formatscout.tests import smart_media_fixtures as fx
from formatscout.tests.corpus.cases import (
    CASES,
    FINDINGS,
    NOT_ASSERTED,
    Case,
    detector_extensions,
)

_UNEXPECTED = "unexpected detection error"


def _run(case: Case, tmp_path: Path, monkeypatch) -> ScanResult:
    monkeypatch.setenv("FORMATSCOUT_OFFLINE", "1")
    if case.index is not None:
        index_dir = tmp_path / "index"
        index_dir.mkdir()
        fx.patch_detector_index(monkeypatch, case.index(index_dir))
    workdir = tmp_path / "work"
    workdir.mkdir()
    return detect(case.build(workdir, case.filename))


def _known_wrong_mark(case: Case):
    reason = "; ".join(f"{fid}: {FINDINGS[fid]}" for fid in case.finding_ids)
    return pytest.mark.xfail(strict=True, raises=AssertionError, reason=f"known wrong ({reason})")


ALL_PARAMS = [pytest.param(case, id=case.id) for case in CASES]
ERA_PARAMS = [
    pytest.param(case, id=case.id, marks=[_known_wrong_mark(case)] if case.known_wrong else [])
    for case in CASES
    if case.expect_era is not NOT_ASSERTED
]
TAG_PARAMS = [pytest.param(case, id=case.id) for case in CASES if case.has_tag_expectations]


@pytest.mark.parametrize("case", ALL_PARAMS)
def test_detect_returns_result(case: Case, tmp_path: Path, monkeypatch):
    result = _run(case, tmp_path, monkeypatch)
    assert isinstance(result, ScanResult)
    assert result.reason != _UNEXPECTED, result.warnings


@pytest.mark.parametrize("case", ERA_PARAMS)
def test_expected_era(case: Case, tmp_path: Path, monkeypatch):
    result = _run(case, tmp_path, monkeypatch)
    assert result.era == case.expect_era, f"{result.era!r} (confidence {result.confidence}): {result.reason}"


@pytest.mark.parametrize("case", TAG_PARAMS)
def test_expected_tags(case: Case, tmp_path: Path, monkeypatch):
    result = _run(case, tmp_path, monkeypatch)
    assert result.era == case.expect_era, "tag expectations assume the era is already right"
    if case.expect_method is not None:
        assert result.method == case.expect_method, f"{result.method!r}: {result.reason}"
    if case.expect_authoritative is not None:
        assert result.authoritative is case.expect_authoritative, f"{result.status!r}: {result.reason}"


class TestCorpusTable:
    def test_ids_are_unique(self):
        ids = [case.id for case in CASES]
        assert len(ids) == len(set(ids))

    def test_known_wrong_cases_carry_no_tag_expectations(self):
        assert not [case.id for case in CASES if case.known_wrong and case.has_tag_expectations]

    def test_tag_expectations_cover_hand_written_and_generated_cases(self):
        # Guards the expectation plumbing in cases.py (hand-written rows, the
        # zero-byte generator and _truncations) against silently dropping out.
        tagged = {case.id for case in CASES if case.has_tag_expectations}
        assert {"hash_sha1_hit_names_ps1", "zero_byte_nds", "trunc_ines_bin_at_4"} <= tagged

    def test_every_finding_is_used_by_a_known_wrong_case(self):
        used = {fid for case in CASES if case.known_wrong for fid in case.finding_ids}
        assert used == set(FINDINGS)

    def test_extension_table_derivation_finds_core_extensions(self):
        # Guards the source-reading derivation in cases.detector_extensions():
        # if detector._detect_file stops comparing a `suffix` name, this fails
        # loudly instead of the zero-byte cases silently shrinking.
        assert {".iso", ".bin", ".cue", ".chd", ".img", ".exe", ".pkg", ".xex"} <= detector_extensions()

    def test_zero_byte_case_exists_for_every_handled_extension(self):
        ids = {case.id for case in CASES}
        for ext in detector_extensions():
            assert f"zero_byte{ext.replace('.', '_')}" in ids
