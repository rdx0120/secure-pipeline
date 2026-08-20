"""Attestation + merge tests."""
from __future__ import annotations

import json
from pathlib import Path

from normalizer import attest, normalize
from normalizer.adapters import (BanditAdapter, GitleaksAdapter, SemgrepAdapter,
                                 TrivyAdapter, ScanRun)
from normalizer.model import Severity

FIX = Path(__file__).parent / "fixtures"
load = lambda n: json.loads((FIX / n).read_text())


def build(trivy_fixture="trivy-fs-populated.sarif", packages=4):
    return {
        "bandit": BanditAdapter().parse(ScanRun(
            tool="bandit", documents={"findings": load("bandit.json")},
            probes={"python_files_on_disk": 21})),
        "gitleaks": GitleaksAdapter().parse(ScanRun(
            tool="gitleaks", documents={"findings": load("gitleaks.sarif")},
            probes={"commits": 1})),
        "semgrep": SemgrepAdapter().parse(ScanRun(
            tool="semgrep",
            documents={"findings": load("semgrep.sarif"), "metrics": load("semgrep.json")},
            probes={"python_files_git_tracked": 21})),
        "trivy-fs": TrivyAdapter().parse(ScanRun(
            tool="trivy-fs", documents={"findings": load(trivy_fixture)},
            probes={"packages": packages, "lockfile_packages": 16})),
    }


def test_all_legs_covered_passes():
    """Floors clear on every leg -- the attestation rows themselves all pass."""
    doc, _ = attest.attest(build())
    assert all(r["status"] == "OK" for r in doc["attestation"])
    assert doc["failed_legs"] == []


def test_blind_sca_leg_fails_the_build():
    doc, code = attest.attest(build("trivy-fs-empty.sarif", packages=0))
    assert doc["verdict"] == "FAIL" and code == 2
    assert "trivy-fs" in doc["failed_legs"]


def test_missing_leg_is_a_failure_not_a_pass():
    """A leg that never ran must not silently vanish from the attestation."""
    results = build()
    del results["gitleaks"]
    doc, code = attest.attest(results)
    assert code == 2
    row = next(r for r in doc["attestation"] if r["tool"] == "gitleaks")
    assert row["status"] == "FAIL_UNVERIFIABLE"


def test_cross_check_flags_unresolvable_dependencies():
    doc, _ = attest.attest(build("trivy-fs-empty.sarif", packages=0))
    c = next(c for c in doc["cross_checks"] if c["name"] == "dependency resolution")
    assert not c["ok"] and "no-op" in c["detail"]


def test_partial_coverage_flagged_even_when_floor_cleared():
    """semgrep passes its floor while ignoring every file under tests/.

    This is the check that only works because the populations were kept
    distinct: 15 examined against a 21-file git-tracked population.
    """
    doc, code = attest.attest(build())
    row = next(r for r in doc["attestation"] if r["tool"] == "semgrep")
    assert row["status"] == "OK"                     # floor cleared
    c = next(c for c in doc["cross_checks"] if c["name"].startswith("semgrep:"))
    assert not c["ok"] and "6" in c["detail"]        # but 6 files never looked at
    assert code == 2                                 # and the build still fails


def test_on_disk_matches_git_tracked_on_a_clean_repo():
    doc, _ = attest.attest(build())
    c = next(c for c in doc["cross_checks"] if "on-disk vs git-tracked" in c["name"])
    assert c["ok"] and "Every Python file is tracked" in c["detail"]


def test_render_table_shows_populations_separately():
    doc, _ = attest.attest(build())
    text = attest.render(doc)
    assert "python_files_on_disk" in text and "python_files_git_tracked" in text
    assert "VERDICT:" in text and "CROSS-CHECKS" in text


def test_merge_dedupes_and_sorts():
    report = normalize.merge(build())
    assert len(report.findings) == len({f.id for f in report.findings})
    ranks = [normalize._RANK[f.severity] for f in report.findings]
    assert ranks == sorted(ranks)


def test_merge_collapses_identical_findings_from_two_runs():
    results = build()
    results["bandit-again"] = results["bandit"]
    report = normalize.merge(results)
    assert report.duplicates_collapsed >= len(results["bandit"].findings)


def test_unknown_severity_sorts_first_and_fails():
    doc = load("semgrep.sarif")
    doc["runs"][0]["tool"]["driver"]["rules"] = []
    results = {"semgrep": SemgrepAdapter().parse(
        ScanRun(tool="semgrep", documents={"findings": doc}, probes={}))}
    report = normalize.merge(results)
    assert report.has_unresolved
    assert report.findings[0].severity is Severity.UNKNOWN
    assert normalize.main(results) == 3


def test_no_secret_in_merged_output():
    report = normalize.merge(build())
    blob = json.dumps(report.to_dict())
    for res in load("gitleaks.sarif")["runs"][0]["results"]:
        assert res["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] not in blob


# ---------------------------------------------------- cross-check wording ----
def test_zero_package_cross_check_reads_as_two_sentences():
    """The zero-package branch is the one a reader is most likely to meet.

    The terminator used to hang off the `> 0` case, so the failing path ran two
    sentences together: "0 packages resolvable Nothing resolves".
    """
    doc, _ = attest.attest(build("trivy-fs-empty.sarif", packages=0))
    c = next(c for c in doc["cross_checks"] if c["name"] == "dependency resolution")
    assert ". Nothing resolves" in c["detail"]      # terminated first sentence
    assert "resolvable Nothing" not in c["detail"]  # the run-on it replaced
    assert "lockfile Nothing" not in c["detail"]    # ...in the other clause too


def test_resolved_cross_check_still_ends_cleanly():
    doc, _ = attest.attest(build())
    c = next(c for c in doc["cross_checks"] if c["name"] == "dependency resolution")
    assert c["detail"].endswith(".")
    assert "Nothing resolves" not in c["detail"]
