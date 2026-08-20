"""Scorecard adapter tests.

Scorecard is the tool whose failure produced this project's founding
observation: it exited 0 while writing a 0-byte file. These tests exist to make
sure the leg that motivated the coverage attestation is itself covered by it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from normalizer.adapters import ScorecardAdapter, ScanRun, EmptyDocumentError
from normalizer.model import CoverageStatus, Severity, SeveritySource, SnippetBasis

FIX = Path(__file__).parent / "fixtures"
load = lambda n: json.loads((FIX / n).read_text())


def run(doc="scorecard.json", requested=5, **kw):
    return ScorecardAdapter().parse(ScanRun(
        tool="scorecard", documents={"findings": load(doc)},
        probes={"scorecard_checks_requested": requested}, **kw))


# ------------------------------------------------------------ the founding case
def test_zero_byte_document_is_rejected(tmp_path):
    """The original observation: exit 0, 0-byte file, reported as success.

    Reproduced again in local mode with exit 1 and a 0-byte file -- so the exit
    code is not the signal. The bytes are.
    """
    empty = tmp_path / "scorecard.json"
    empty.write_text("")
    with pytest.raises(EmptyDocumentError):
        ScanRun.from_files("scorecard", findings=empty)


def test_all_checks_inconclusive_fails_coverage():
    """A run where nothing resolved is FAIL, not a clean bill of health."""
    r = run("scorecard-inconclusive.json")
    assert r.findings == []
    assert r.coverage.status is CoverageStatus.FAIL_NO_COVERAGE
    assert "no check returned a resolved score" in r.coverage.detail


def test_no_checks_at_all_fails_coverage():
    doc = load("scorecard.json"); doc["checks"] = []
    r = ScorecardAdapter().parse(ScanRun(
        tool="scorecard", documents={"findings": doc},
        probes={"scorecard_checks_requested": 18}))
    assert r.coverage.status is CoverageStatus.FAIL_NO_COVERAGE


def test_clean_scan_distinguishable_from_blind_scan():
    """Both produce zero findings; only the attestation separates them."""
    blind = run("scorecard-inconclusive.json")
    doc = load("scorecard.json")
    for c in doc["checks"]:
        c["score"] = 10
    clean = ScorecardAdapter().parse(ScanRun(
        tool="scorecard", documents={"findings": doc},
        probes={"scorecard_checks_requested": 5}))
    assert blind.findings == clean.findings == []
    assert not blind.coverage.ok and clean.coverage.ok


# ------------------------------------------------------------------- coverage
def test_denominator_is_independent_of_scorecard_output():
    """examined comes from the document; the denominator comes from the runner.

    Reading both from the same place is what let a shallow clone report 1 of 1.
    """
    r = run(requested=18)
    assert r.coverage.examined == 5          # resolved checks in the document
    assert r.coverage.denominator == 18      # checks the runner asked for
    assert "--checks" in r.coverage.denominator_source
    assert r.coverage.status is CoverageStatus.OK   # floor cleared...
    assert r.coverage.ratio is not None and r.coverage.ratio < 1.0  # ...but partial


def test_unverifiable_without_a_probe():
    r = ScorecardAdapter().parse(ScanRun(
        tool="scorecard", documents={"findings": load("scorecard.json")}))
    assert r.coverage.denominator is None


def test_inconclusive_checks_are_not_counted_as_examined():
    doc = load("scorecard.json")
    doc["checks"][0]["score"] = -1
    r = ScorecardAdapter().parse(ScanRun(
        tool="scorecard", documents={"findings": doc},
        probes={"scorecard_checks_requested": 5}))
    assert r.coverage.examined == 4


# ------------------------------------------------------------------- findings
def test_failing_checks_become_findings():
    r = run()
    ids = {f.rule_id for f in r.findings}
    assert "Pinned-Dependencies" in ids and "Token-Permissions" in ids
    assert all(f.severity_source is SeveritySource.SCORECARD_CHECK_SCORE
               for f in r.findings)


def test_passing_checks_are_not_findings():
    r = run()
    assert "Binary-Artifacts" not in {f.rule_id for f in r.findings}


def test_score_bands():
    from normalizer.adapters.scorecard import _severity
    assert _severity(0) is Severity.HIGH
    assert _severity(3) is Severity.HIGH
    assert _severity(5) is Severity.MEDIUM
    assert _severity(8) is Severity.LOW
    assert _severity(10) is Severity.INFO
    assert _severity(-1) is Severity.UNKNOWN


def test_findings_are_repo_level_and_uniquely_identified():
    r = run()
    assert all(f.path == "" and f.start_line is None for f in r.findings)
    assert all(f.snippet_basis is SnippetBasis.IDENTITY_SURROGATE for f in r.findings)
    assert len({f.id for f in r.findings}) == len(r.findings)


def test_aggregate_score_recorded():
    assert "aggregate score" in run().coverage.detail


def test_fixture_labelling():
    assert "Real OpenSSF Scorecard" in load("scorecard.json")["_fixture_note"]
    assert "SYNTHETIC" in load("scorecard-inconclusive.json")["_fixture_note"]
