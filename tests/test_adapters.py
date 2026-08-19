"""Tests against the real Session 1 baseline output.

Every assertion here encodes a failure mode observed in a real tool, not a
hypothetical one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from normalizer.adapters import (
    BanditAdapter, GitleaksAdapter, SemgrepAdapter, TrivyAdapter, ScanRun,
    EmptyDocumentError,
)
from normalizer.model import CoverageStatus, Severity, SeveritySource, SnippetBasis

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def run_for(tool, findings_doc, **kw):
    return ScanRun(tool=tool, documents={"findings": load(findings_doc)}, **kw)


# ---------------------------------------------------------------- bandit ----
class TestBandit:
    def result(self):
        return BanditAdapter().parse(run_for("bandit", "bandit.json"))

    def test_medium_severity_survives(self):
        """The regression the SARIF path cannot pass.

        B314 (unsafe ET.parse) is MEDIUM severity. In bandit's SARIF these two
        findings have NO `level` key at all, so a SARIF-based adapter either
        drops them or ranks them below 90 `note`-level asserts.
        """
        b314 = [f for f in self.result().findings if f.rule_id == "B314"]
        assert len(b314) == 2
        assert all(f.severity is Severity.MEDIUM for f in b314)
        assert all(f.severity_source is SeveritySource.BANDIT_PROPERTIES for f in b314)

    def test_severity_never_unknown_for_known_input(self):
        assert all(f.severity is not Severity.UNKNOWN for f in self.result().findings)

    def test_low_confidence_downgrades(self):
        from normalizer.adapters.bandit import _severity
        assert _severity("HIGH", "HIGH") is Severity.HIGH
        assert _severity("HIGH", "LOW") is Severity.MEDIUM
        assert _severity("LOW", "LOW") is Severity.INFO

    def test_unparseable_severity_is_loud(self):
        from normalizer.adapters.bandit import _severity
        assert _severity("SEVERE", "HIGH") is Severity.UNKNOWN
        assert _severity(None, None) is Severity.UNKNOWN

    def test_coverage_from_metrics_not_findings(self):
        cov = self.result().coverage
        assert cov.examined == 21          # files bandit opened
        assert cov.status is CoverageStatus.OK
        assert "metrics" in cov.evidence

    def test_snippet_withheld_by_default(self):
        assert all(f.snippet is None for f in self.result().findings)

    def test_snippet_opt_in_allowed_for_non_secret_tool(self):
        r = BanditAdapter().parse(run_for("bandit", "bandit.json"), include_snippets=True)
        assert any(f.snippet for f in r.findings)


# -------------------------------------------------------------- gitleaks ----
class TestGitleaks:
    def result(self, **kw):
        return GitleaksAdapter().parse(
            run_for("gitleaks", "gitleaks.sarif", probes={"commits": 1}), **kw
        )

    def test_secret_never_leaves_adapter(self):
        """gitleaks puts the plaintext secret in region.snippet.text."""
        for f in self.result().findings:
            assert f.snippet is None

    def test_include_snippets_cannot_override_secret_bearing(self):
        """Opt-in must not be able to unlock a secret-bearing tool."""
        for f in self.result(include_snippets=True).findings:
            assert f.snippet is None

    def test_no_secret_material_in_serialized_output(self):
        raw = (FIX / "gitleaks.sarif").read_text()
        secrets = [
            json.loads(raw)["runs"][0]["results"][i]["locations"][0]
            ["physicalLocation"]["region"]["snippet"]["text"]
            for i in range(3)
        ]
        out = self.result().to_json()
        for s in secrets:
            assert s not in out

    def test_severity_is_policy_not_tool(self):
        for f in self.result().findings:
            assert f.severity is Severity.HIGH
            assert f.severity_source is SeveritySource.POLICY_CONSTANT

    def test_snippet_hash_still_enables_dedup(self):
        ids = [f.id for f in self.result().findings]
        assert len(set(ids)) == 3
        assert all(f.snippet_basis is SnippetBasis.SNIPPET for f in self.result().findings)

    def test_coverage_unverifiable_without_probe(self):
        """No probe, no log text -> unverifiable, never a comfortable pass."""
        r = GitleaksAdapter().parse(run_for("gitleaks", "gitleaks.sarif"))
        assert r.coverage.status is CoverageStatus.FAIL_UNVERIFIABLE

    def test_coverage_from_stderr_fallback(self):
        r = GitleaksAdapter().parse(
            run_for("gitleaks", "gitleaks.sarif", stderr="INF 6 commits scanned.")
        )
        assert r.coverage.examined == 6 and r.coverage.status is CoverageStatus.OK


# --------------------------------------------------------------- semgrep ----
class TestSemgrep:
    def result(self):
        run = ScanRun(
            tool="semgrep",
            documents={"findings": load("semgrep.sarif"), "metrics": load("semgrep.json")},
        )
        return SemgrepAdapter().parse(run)

    def test_severity_joined_from_rule_not_result(self):
        """All 148 baseline results had no `level`; only the rule carries it."""
        raw = load("semgrep.sarif")["runs"][0]["results"]
        assert all("level" not in r for r in raw)          # premise still holds
        for f in self.result().findings:
            assert f.severity is not Severity.UNKNOWN
            assert f.severity_source is SeveritySource.SEMGREP_RULE_LEVEL

    def test_missing_rule_yields_unknown_not_default(self):
        doc = load("semgrep.sarif")
        doc["runs"][0]["tool"]["driver"]["rules"] = []
        r = SemgrepAdapter().parse(ScanRun(tool="semgrep", documents={"findings": doc}))
        assert all(f.severity is Severity.UNKNOWN for f in r.findings)
        assert all(f.severity_source is SeveritySource.UNRESOLVED for f in r.findings)

    def test_srcroot_uri_normalized(self):
        assert all(not f.path.startswith("%") for f in self.result().findings)

    def test_coverage_reports_what_was_scanned(self):
        cov = self.result().coverage
        assert cov.examined == 15 and cov.status is CoverageStatus.OK

    def test_does_not_invent_a_skip_count(self):
        assert "0 paths skipped" not in (self.result().coverage.detail or "")


# ----------------------------------------------------------------- trivy ----
class TestTrivy:
    def populated(self, packages=4):
        return TrivyAdapter().parse(
            ScanRun(tool="trivy-fs", documents={"findings": load("trivy-fs-populated.sarif")},
                    probes={"packages": packages})
        )

    def test_empty_run_with_zero_packages_fails_coverage(self):
        """The headline case: 0 findings + exit 0 + nothing examined."""
        r = TrivyAdapter().parse(
            ScanRun(tool="trivy-fs", documents={"findings": load("trivy-fs-empty.sarif")},
                    probes={"packages": 0}, exit_code=0)
        )
        assert r.findings == []
        assert r.coverage.status is CoverageStatus.FAIL_NO_COVERAGE
        assert "unpinned" in (r.coverage.detail or "")

    def test_clean_scan_is_distinguishable_from_blind_scan(self):
        blind = TrivyAdapter().parse(
            ScanRun(tool="trivy-fs", documents={"findings": load("trivy-fs-empty.sarif")},
                    probes={"packages": 0}))
        clean = TrivyAdapter().parse(
            ScanRun(tool="trivy-fs", documents={"findings": load("trivy-fs-empty.sarif")},
                    probes={"packages": 12}))
        assert blind.findings == clean.findings == []
        assert not blind.coverage.ok and clean.coverage.ok

    def test_severity_from_numeric_cvss(self):
        for f in self.populated().findings:
            assert f.severity_source is SeveritySource.TRIVY_SECURITY_SEVERITY
            assert f.cvss_score is not None
            assert f.cve is not None

    def test_cvss_banding(self):
        from normalizer.adapters.trivy import _from_cvss
        assert _from_cvss(9.8) is Severity.CRITICAL
        assert _from_cvss(7.5) is Severity.HIGH
        assert _from_cvss(6.5) is Severity.MEDIUM
        assert _from_cvss(0.0) is Severity.INFO

    def test_component_distinguishes_findings_on_same_line(self):
        f = self.populated().findings
        assert all(x.component for x in f)
        assert all(x.snippet_basis is SnippetBasis.IDENTITY_SURROGATE for x in f)
        assert len({x.id for x in f}) == len(f)

    def test_coverage_never_inferred_from_findings(self):
        r = self.populated(packages=0)
        assert r.findings and r.coverage.status is CoverageStatus.FAIL_NO_COVERAGE


# ------------------------------------------------------------ cross-tool ----
def test_id_is_stable_across_line_shifts():
    """A finding must survive an unrelated edit above it."""
    doc = load("bandit.json")
    before = BanditAdapter().parse(ScanRun(tool="bandit", documents={"findings": doc}))
    shifted = json.loads(json.dumps(doc))
    for r in shifted["results"]:
        r["line_number"] += 10
        r["line_range"] = [n + 10 for n in r["line_range"]]
    after = BanditAdapter().parse(ScanRun(tool="bandit", documents={"findings": shifted}))
    assert [f.id for f in before.findings] == [f.id for f in after.findings]
    assert [f.start_line for f in before.findings] != [f.start_line for f in after.findings]


def test_zero_byte_document_is_an_error(tmp_path):
    """scorecard exited 0 and wrote a 0-byte file. That is never 'no findings'."""
    empty = tmp_path / "scorecard.json"
    empty.write_text("")
    with pytest.raises(EmptyDocumentError):
        ScanRun.from_files("scorecard", findings=empty)


def test_every_finding_declares_its_severity_source():
    runs = [
        BanditAdapter().parse(run_for("bandit", "bandit.json")),
        GitleaksAdapter().parse(run_for("gitleaks", "gitleaks.sarif", probes={"commits": 1})),
        SemgrepAdapter().parse(ScanRun(tool="semgrep", documents={
            "findings": load("semgrep.sarif"), "metrics": load("semgrep.json")})),
        TrivyAdapter().parse(ScanRun(tool="trivy-fs", documents={
            "findings": load("trivy-fs-populated.sarif")}, probes={"packages": 4})),
    ]
    for r in runs:
        for f in r.findings:
            assert isinstance(f.severity_source, SeveritySource)
            assert f.to_dict()["severity_source"] != SeveritySource.UNRESOLVED.value
            assert f.snippet_sha256.startswith("sha256:")


# ------------------------------------------------------- populations --------
def test_units_are_not_interchangeable():
    """21 vs 15 is two populations, not a disagreement.

    If both legs reported unit "files", a reader diffing the counts would
    conclude a scanner is broken. The unit names must make the comparison
    obviously invalid.
    """
    b = BanditAdapter().parse(ScanRun(
        tool="bandit", documents={"findings": load("bandit.json")},
        probes={"python_files_on_disk": 21}))
    s = SemgrepAdapter().parse(ScanRun(
        tool="semgrep",
        documents={"findings": load("semgrep.sarif"), "metrics": load("semgrep.json")},
        probes={"python_files_git_tracked": 15}))
    assert b.coverage.unit == "python_files_on_disk"
    assert s.coverage.unit == "python_files_git_tracked"
    assert b.coverage.unit != s.coverage.unit
    assert b.coverage.examined == 21 and s.coverage.examined == 15


def test_coverage_carries_denominator_and_its_source():
    r = BanditAdapter().parse(ScanRun(
        tool="bandit", documents={"findings": load("bandit.json")},
        probes={"python_files_on_disk": 21}))
    assert r.coverage.denominator == 21
    assert "find" in r.coverage.denominator_source
    assert r.coverage.ratio == 1.0


def test_fixtures_are_labelled():
    """A reader must not mistake the synthetic Django CVEs for real ones."""
    for name in ("gitleaks.sarif", "trivy-fs-populated.sarif"):
        assert "SYNTHETIC" in load(name)["_fixture_note"]
    assert "never depended on Django" in load("trivy-fs-populated.sarif")["_fixture_note"]


def test_shallow_clone_is_unverifiable_not_a_pass():
    """A --depth 1 clone makes `git rev-list --count HEAD` return 1.

    examined == denominator == 1, so the row would PASS while gitleaks has seen
    one commit of an unknown-length history. Measuring the truncation is not
    measuring the population.
    """
    deep = GitleaksAdapter().parse(ScanRun(
        tool="gitleaks", documents={"findings": load("gitleaks.sarif")},
        probes={"commits": 1, "shallow": 0}, stderr="INF 1 commits scanned."))
    shallow = GitleaksAdapter().parse(ScanRun(
        tool="gitleaks", documents={"findings": load("gitleaks.sarif")},
        probes={"commits": 1, "shallow": 1}, stderr="INF 1 commits scanned."))
    assert deep.coverage.status is CoverageStatus.OK
    assert shallow.coverage.status is CoverageStatus.FAIL_UNVERIFIABLE
    assert "SHALLOW" in shallow.coverage.evidence
    assert "fetch-depth: 0" in shallow.coverage.detail
