"""The gate. Consumes findings + attestation + policy + exceptions.

Exit codes are deliberately not collapsed:

    0  clean
    1  findings blocked, or an exception is expired/stale
    2  coverage failure -- we cannot see

"We found problems" and "we can't see" are different pages. A run with ZERO
findings and a failed attestation exits 2, and that asymmetry is the entire
thesis of this project in one exit code: a scanner that examined nothing
produces the same empty findings array as a clean codebase.

When both conditions hold, coverage wins. If we could not see, the finding
list is not trustworthy enough to reason about.

No thresholds, rule names, or severity arithmetic live in this file. They are
all in policy.yaml.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .model import CoverageStatus, Severity

_RANK = {
    Severity.UNKNOWN: 0, Severity.CRITICAL: 1, Severity.HIGH: 2,
    Severity.MEDIUM: 3, Severity.LOW: 4, Severity.INFO: 5,
}


@dataclass
class Verdict:
    blocked: list[dict] = field(default_factory=list)
    warned: list[dict] = field(default_factory=list)
    ignored: int = 0
    suppressed: list[dict] = field(default_factory=list)
    coverage_failures: list[dict] = field(default_factory=list)
    policy_violations: list[str] = field(default_factory=list)
    disagreements: list[dict] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        # Coverage wins: an untrustworthy finding list is not worth gating on.
        if self.coverage_failures:
            return 2
        if self.blocked or self.policy_violations:
            return 1
        return 0

    @property
    def label(self) -> str:
        return {0: "CLEAN", 1: "BLOCKED", 2: "COVERAGE FAILURE"}[self.exit_code]


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


# --------------------------------------------------------------------------
# exceptions
# --------------------------------------------------------------------------

def check_exceptions(
    exceptions: dict, policy: dict, finding_ids: set[str], today: dt.date
) -> tuple[dict[str, dict], list[str]]:
    """Validate exceptions and return the ones still in force.

    An exception is a dated, attributed decision. Three ways it fails:
      * missing a required field   -> not a decision anyone can audit
      * expired                    -> no indefinite suppressions
      * stale (matches no finding) -> silently re-authorizes on return
    """
    cfg = policy.get("exceptions", {})
    required = cfg.get("require_fields", [])
    violations: list[str] = []
    active: dict[str, dict] = {}

    for i, exc in enumerate(exceptions.get("exceptions") or []):
        where = exc.get("id", f"<entry {i}>")
        missing = [f for f in required if not exc.get(f)]
        if missing:
            violations.append(f"exception {where}: missing required field(s) {missing}")
            continue

        try:
            expires = dt.date.fromisoformat(str(exc["expires"]))
        except ValueError:
            violations.append(f"exception {where}: 'expires' is not an ISO date")
            continue

        if cfg.get("fail_on_expired", True) and expires < today:
            violations.append(
                f"exception {where}: EXPIRED {expires.isoformat()} "
                f"(approver: {exc.get('approver')})"
            )
            continue

        max_age = cfg.get("max_age_days")
        if max_age and (expires - today).days > max_age:
            violations.append(
                f"exception {where}: expires {expires.isoformat()}, "
                f"more than {max_age} days out"
            )
            continue

        if cfg.get("fail_on_stale", True) and exc["id"] not in finding_ids:
            violations.append(
                f"exception {where}: STALE -- matches no current finding. "
                "A stale suppression silently re-authorizes the finding when it returns."
            )
            continue

        active[exc["id"]] = exc
    return active, violations


# --------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------

_STATUS_KEY = {
    CoverageStatus.FAIL_UNVERIFIABLE.value: "fail_on_unverifiable",
    CoverageStatus.FAIL_NO_COVERAGE.value: "fail_on_no_coverage",
    CoverageStatus.FAIL_BELOW_FLOOR.value: "fail_on_below_floor",
}


def check_coverage(attestation: dict, policy: dict) -> list[dict]:
    cfg = policy.get("coverage", {})
    out: list[dict] = []
    rows = {r["tool"]: r for r in attestation.get("attestation", [])}

    for leg in cfg.get("require_legs", []):
        if leg not in rows:
            out.append({"tool": leg, "why": "required leg did not run"})

    for row in attestation.get("attestation", []):
        key = _STATUS_KEY.get(row["status"])
        if key and cfg.get(key, True):
            out.append({"tool": row["tool"], "why": row["status"],
                        "detail": row.get("evidence")})

    if cfg.get("fail_on_partial", True):
        for c in attestation.get("cross_checks", []):
            if not c["ok"]:
                out.append({"tool": c["name"].split(":")[0], "why": "partial coverage",
                            "detail": c["detail"]})
    return out


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------

def evaluate(findings_doc: dict, attestation: dict, policy: dict,
             exceptions: dict, today: dt.date | None = None) -> Verdict:
    today = today or dt.date.today()
    v = Verdict()
    findings = findings_doc.get("findings", [])
    ids = {f["id"] for f in findings}

    active, v.policy_violations = check_exceptions(exceptions, policy, ids, today)
    v.coverage_failures = check_coverage(attestation, policy)
    v.disagreements = findings_doc.get("disagreements", [])

    floors = policy.get("severity_floor", {})
    actions = policy.get("actions", {})
    corr_cfg = policy.get("corroboration", {})

    for f in findings:
        sev = Severity(f["severity"])

        if f["id"] in active:
            v.suppressed.append({**f, "exception": active[f["id"]]})
            continue

        floor = floors.get(f["tool"])
        if floor and _RANK[sev] > _RANK[Severity(floor)]:
            v.ignored += 1
            continue

        action = actions.get(sev.value, "warn")
        corr = f.get("corroboration")
        reason = f"{sev.value} from {f['tool']}"

        if (corr and corr["count"] >= corr_cfg.get("min_tools", 2)
                and corr_cfg.get("escalate_warn_to_block") and action == "warn"):
            action = "block"
            reason = (f"{sev.value}, corroborated by "
                      f"{', '.join(corr['agreeing_tools'])}")

        if action == "block":
            v.blocked.append({**f, "_why": reason})
        elif action == "warn":
            v.warned.append({**f, "_why": reason})
        else:
            v.ignored += 1
    return v


def render(v: Verdict) -> str:
    out = ["POLICY GATE", ""]
    out.append(f"  blocked:     {len(v.blocked)}")
    out.append(f"  warned:      {len(v.warned)}")
    out.append(f"  suppressed:  {len(v.suppressed)} (active exceptions)")
    out.append(f"  below floor: {v.ignored}")
    out.append("")

    if v.coverage_failures:
        out.append("COVERAGE FAILURES -- the scan could not see")
        for c in v.coverage_failures:
            out.append(f"  [{c['tool']}] {c['why']}")
            if c.get("detail"):
                out.append(f"      {c['detail']}")
        out.append("")

    if v.policy_violations:
        out.append("POLICY VIOLATIONS")
        for p in v.policy_violations:
            out.append(f"  {p}")
        out.append("")

    if v.blocked:
        out.append("BLOCKED")
        # Presentation groups corroborated findings; the JSON keeps both records.
        shown: set[str] = set()
        for f in v.blocked:
            corr = f.get("corroboration")
            if corr:
                if corr["group_id"] in shown:
                    continue
                shown.add(corr["group_id"])
                tools = "+".join(corr["agreeing_tools"])
                out.append(f"  {f['severity']:<8} [{tools}] {f['path']}:{f['start_line']}")
                out.append(f"           {corr['weak_class']} -- {f['_why']}")
            else:
                out.append(f"  {f['severity']:<8} [{f['tool']}] {f['path']}:{f['start_line']}"
                           f"  {f['rule_id']}")
        out.append("")

    if v.disagreements:
        out.append("DISAGREEMENTS -- one tool fired, another that examined the file did not")
        for d in v.disagreements:
            out.append(f"  {d['path']}:{d['line']} {d['weak_class']}: "
                       f"flagged by {'+'.join(d['flagged_by'])}, "
                       f"silent: {'+'.join(d['silent'])}")
        out.append("")

    if v.suppressed:
        out.append("SUPPRESSED")
        for f in v.suppressed:
            e = f["exception"]
            out.append(f"  {f['path']}:{f['start_line']} {f['rule_id']} "
                       f"-- {e['approver']}, expires {e['expires']}")
            out.append(f"      {e['reason']}")
        out.append("")

    out.append(f"VERDICT: {v.label}  (exit {v.exit_code})")
    return "\n".join(out)


def main(findings_doc: dict, attestation: dict, policy_path: Path,
         exceptions_path: Path, json_path: Path | None = None) -> int:
    policy = load(policy_path)
    exceptions = load(exceptions_path)
    v = evaluate(findings_doc, attestation, policy, exceptions)
    print(render(v))
    if json_path:
        json_path.write_text(json.dumps({
            "verdict": v.label, "exit_code": v.exit_code,
            "blocked": v.blocked, "warned": v.warned,
            "suppressed": v.suppressed, "below_floor": v.ignored,
            "coverage_failures": v.coverage_failures,
            "policy_violations": v.policy_violations,
            "disagreements": v.disagreements,
        }, indent=2))
    return v.exit_code
