"""Policy gate tests.

The central assertion here is the asymmetry: the gate must be able to fail on
ZERO findings. A scanner that examined nothing emits the same empty findings
array as a clean codebase, and only the attestation can tell them apart.
"""
from __future__ import annotations

import datetime as dt

import pytest
import yaml

from normalizer import gate

TODAY = dt.date(2026, 8, 19)
FUTURE = "2026-10-01"
PAST = "2026-01-01"

POLICY = yaml.safe_load(open("policy.yaml").read())


def finding(fid="sha256:aaa", tool="bandit", sev="high", corr=None, **kw):
    return {
        "id": fid, "tool": tool, "rule_id": "B314", "severity": sev,
        "path": "p.py", "start_line": 1, "corroboration": corr, **kw,
    }


def attestation(status="OK", cross_ok=True, legs=("bandit", "gitleaks", "semgrep", "trivy-fs")):
    return {
        "attestation": [
            {"tool": t, "status": status, "unit": "u", "examined": 1,
             "floor": 1, "evidence": "probe"} for t in legs
        ],
        "cross_checks": [{"name": "x: y", "ok": cross_ok, "detail": "d"}],
    }


def run(findings, att, exceptions=None):
    return gate.evaluate(
        {"findings": findings, "disagreements": []}, att, POLICY,
        exceptions or {"exceptions": []}, today=TODAY,
    )


# ---------------------------------------------------------------- the thesis --
def test_zero_findings_with_failed_coverage_fails():
    """The asymmetry the whole project exists for."""
    v = run([], attestation(status="FAIL_NO_COVERAGE"))
    assert v.blocked == []
    assert v.coverage_failures
    assert v.exit_code == 2 and v.label == "COVERAGE FAILURE"


def test_zero_findings_with_good_coverage_is_clean():
    v = run([], attestation())
    assert v.exit_code == 0 and v.label == "CLEAN"


def test_coverage_failure_outranks_blocked_findings():
    """'We can't see' and 'we found problems' are different pages, and an
    untrustworthy finding list is not worth gating on."""
    v = run([finding()], attestation(status="FAIL_UNVERIFIABLE"))
    assert v.blocked and v.coverage_failures
    assert v.exit_code == 2


def test_missing_leg_is_a_coverage_failure():
    v = run([], attestation(legs=("bandit", "gitleaks", "semgrep")))
    assert any("did not run" in c["why"] for c in v.coverage_failures)
    assert v.exit_code == 2


def test_partial_coverage_fails_via_cross_check():
    v = run([], attestation(cross_ok=False))
    assert any(c["why"] == "partial coverage" for c in v.coverage_failures)
    assert v.exit_code == 2


# ------------------------------------------------------------------ actions --
def test_high_blocks_medium_warns():
    v = run([finding(sev="high"), finding("sha256:b", sev="medium")], attestation())
    assert len(v.blocked) == 1 and len(v.warned) == 1
    assert v.exit_code == 1


def test_unknown_severity_blocks():
    v = run([finding(sev="unknown")], attestation())
    assert len(v.blocked) == 1 and v.exit_code == 1


def test_below_floor_is_dropped():
    """bandit's floor is medium, so its 92 B101 lows never reach the gate."""
    v = run([finding(sev="low", tool="bandit")], attestation())
    assert v.ignored == 1 and not v.blocked and not v.warned


# ----------------------------------------------------------- corroboration --
def test_corroboration_escalates_warn_to_block():
    corr = {"group_id": "g", "weak_class": "xml_parse_untrusted",
            "agreeing_tools": ["bandit", "semgrep"], "count": 2}
    solo = run([finding(sev="medium")], attestation())
    both = run([finding(sev="medium", corr=corr)], attestation())
    assert solo.warned and not solo.blocked
    assert both.blocked and not both.warned
    assert "corroborated by" in both.blocked[0]["_why"]


def test_corroboration_does_not_change_severity():
    """Confidence is not severity. Inflating it would corrupt the tools' own
    judgment; only the routing changes."""
    corr = {"group_id": "g", "weak_class": "w",
            "agreeing_tools": ["bandit", "semgrep"], "count": 2}
    v = run([finding(sev="medium", corr=corr)], attestation())
    assert v.blocked[0]["severity"] == "medium"


# -------------------------------------------------------------- exceptions --
def exc(fid="sha256:aaa", expires=FUTURE, **kw):
    base = {"id": fid, "reason": "r", "approver": "a@b.c", "expires": expires}
    base.update(kw)
    return {"exceptions": [base]}


def test_valid_exception_suppresses():
    v = run([finding()], attestation(), exc())
    assert len(v.suppressed) == 1 and not v.blocked and v.exit_code == 0


def test_expired_exception_fails_the_build():
    v = run([finding()], attestation(), exc(expires=PAST))
    assert any("EXPIRED" in p for p in v.policy_violations)
    assert v.exit_code == 1


def test_stale_exception_fails_the_build():
    """An exception matching no finding silently re-authorizes it on return."""
    v = run([finding()], attestation(), exc(fid="sha256:gone"))
    assert any("STALE" in p for p in v.policy_violations)
    assert v.exit_code == 1


def test_exception_missing_required_field_fails():
    e = exc()
    del e["exceptions"][0]["approver"]
    v = run([finding()], attestation(), e)
    assert any("missing required field" in p for p in v.policy_violations)
    assert v.exit_code == 1


def test_exception_beyond_max_age_fails():
    v = run([finding()], attestation(), exc(expires="2027-12-31"))
    assert any("more than" in p for p in v.policy_violations)
    assert v.exit_code == 1


def test_expired_exception_does_not_suppress():
    v = run([finding()], attestation(), exc(expires=PAST))
    assert not v.suppressed


# ------------------------------------------------------------------ policy --
def test_no_thresholds_hardcoded_in_gate():
    """Every decision lives in policy.yaml, so a policy change is a diff."""
    src = open("normalizer/gate.py").read()
    for token in ("B314", "critical", '"high"', "0.5"):
        assert token not in src, f"{token!r} should live in policy.yaml"
