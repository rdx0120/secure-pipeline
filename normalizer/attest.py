"""Coverage attestation.

The output that makes this repo not-a-tutorial. Every "secure CI/CD pipeline"
emits findings; none of them can tell you whether the scanner was awake.

Exit codes:
  0  every leg examined its input and cleared its floor
  2  at least one leg FAILED coverage -- as loud as a critical finding
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .model import AdapterResult, Coverage, CoverageStatus

#: Legs that must be present. A leg that did not run at all is not a pass --
#: it is the same class of failure as a leg that ran and saw nothing.
EXPECTED_LEGS = ("bandit", "gitleaks", "semgrep", "trivy-fs")

_SYMBOL = {
    CoverageStatus.OK: "PASS",
    CoverageStatus.FAIL_NO_COVERAGE: "FAIL",
    CoverageStatus.FAIL_BELOW_FLOOR: "FAIL",
    CoverageStatus.FAIL_UNVERIFIABLE: "FAIL",
}


@dataclass(frozen=True)
class CrossCheck:
    """A finding about the scanners rather than the code."""

    name: str
    ok: bool
    detail: str


def cross_checks(coverages: dict[str, Coverage]) -> list[CrossCheck]:
    """Comparisons only possible because the populations were kept distinct."""
    out: list[CrossCheck] = []

    # 1. Per-leg partial coverage. A leg that cleared its floor can still have
    #    quietly ignored most of its own population -- semgrep passed its floor
    #    while skipping every file under tests/.
    for tool, cov in sorted(coverages.items()):
        if cov.ratio is None or cov.examined < 0:
            continue
        missed = cov.denominator - cov.examined
        if missed > 0:
            out.append(CrossCheck(
                name=f"{tool}: examined its full {cov.unit} population",
                ok=False,
                detail=(f"examined {cov.examined} of {cov.denominator} "
                        f"({cov.ratio:.0%}); {missed} {cov.unit} never looked at."
                        + (f" {cov.detail}" if cov.detail else "")),
            ))

    # 2. on-disk vs git-tracked, compared DENOMINATOR to DENOMINATOR. Comparing
    #    one tool's examined count against another's population conflates two
    #    different questions; this asks only whether git can see the code.
    disk = coverages.get("bandit")
    tracked = coverages.get("semgrep")
    if disk and tracked and disk.denominator and tracked.denominator:
        gap = disk.denominator - tracked.denominator
        out.append(CrossCheck(
            name="python files: on-disk vs git-tracked",
            ok=gap <= 0,
            detail=(f"{disk.denominator} on disk, {tracked.denominator} git-tracked"
                    + (". Every Python file is tracked."
                       if gap <= 0 else
                       f". {gap} file(s) invisible to git-tracked scanning.")),
        ))

    # 3. Declared direct dependencies vs what actually resolves.
    trivy = coverages.get("trivy-fs")
    if trivy is not None:
        declared = trivy.denominator
        out.append(CrossCheck(
            name="dependency resolution",
            ok=trivy.examined > 0,
            detail=(f"{trivy.examined} packages resolvable"
                    + (f" against {declared} in lockfile" if declared else "")
		    + "."
                    + ("" if trivy.examined > 0 else
                       " Nothing resolves -- SCA is a no-op reporting success.")),
        ))
    return out


def attest(results: dict[str, AdapterResult]) -> tuple[dict, int]:
    coverages = {t: r.coverage for t, r in results.items()}
    # Report every leg that produced a result, not just the required ones.
    # Iterating EXPECTED_LEGS alone silently dropped any additional leg from the
    # attestation -- a leg could run, be parsed, and never appear in the table.
    # Scorecard is exactly that case: it is not required for a local scan
    # (it needs a public repo and network), but when it runs it must be attested.
    legs = list(EXPECTED_LEGS) + [t for t in sorted(coverages) if t not in EXPECTED_LEGS]
    rows = []
    for leg in legs:
        cov = coverages.get(leg)
        if cov is None:
            rows.append({
                "tool": leg, "unit": "-", "examined": -1, "denominator": None,
                "denominator_source": None, "floor": None,
                "status": CoverageStatus.FAIL_UNVERIFIABLE.value,
                "evidence": "leg did not run or produced no parseable output",
            })
            continue
        d = cov.to_dict()
        d["findings"] = len(results[leg].findings)
        rows.append(d)

    checks = cross_checks(coverages)
    failed = [r for r in rows if r["status"] != CoverageStatus.OK.value]
    doc = {
        "attestation": rows,
        "cross_checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in checks],
        "verdict": "PASS" if not failed and all(c.ok for c in checks) else "FAIL",
        "failed_legs": [r["tool"] for r in failed],
    }
    return doc, (0 if doc["verdict"] == "PASS" else 2)


def render(doc: dict) -> str:
    rows = doc["attestation"]
    head = ("LEG", "UNIT", "EXAMINED", "OF", "FLOOR", "FINDINGS", "STATUS")
    body = []
    for r in rows:
        examined = "-" if r["examined"] < 0 else str(r["examined"])
        denom = "?" if r.get("denominator") in (None, "") else str(r["denominator"])
        body.append((
            r["tool"], r["unit"], examined, denom,
            str(r.get("floor") if r.get("floor") is not None else "-"),
            str(r.get("findings", "-")),
            _SYMBOL.get(CoverageStatus(r["status"]), r["status"]),
        ))
    widths = [max(len(h), *(len(b[i]) for b in body)) for i, h in enumerate(head)]
    line = "  ".join("-" * w for w in widths)
    out = ["COVERAGE ATTESTATION", ""]
    out.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(head)))
    out.append(line)
    for b in body:
        out.append("  ".join(b[i].ljust(widths[i]) for i in range(len(head))))
    out.append("")
    for r in rows:
        if r["status"] != CoverageStatus.OK.value:
            out.append(f"  {r['tool']}: {r['status']} -- {r.get('evidence','')}")
            if r.get("detail"):
                out.append(f"      {r['detail']}")
    out.append("EVIDENCE")
    for r in rows:
        src = r.get("denominator_source") or "-"
        out.append(f"  {r['tool']:<10} examined <- {r.get('evidence','-')}")
        out.append(f"  {'':<10} of       <- {src}")
    if doc["cross_checks"]:
        out.append("")
        out.append("CROSS-CHECKS")
        for c in doc["cross_checks"]:
            out.append(f"  [{'ok' if c['ok'] else 'FAIL'}] {c['name']}")
            out.append(f"         {c['detail']}")
    out.append("")
    out.append(f"VERDICT: {doc['verdict']}"
               + (f"  (failed legs: {', '.join(doc['failed_legs'])})"
                  if doc["failed_legs"] else ""))
    return "\n".join(out)


def main(results: dict[str, AdapterResult], json_path=None) -> int:
    doc, code = attest(results)
    print(render(doc))
    if json_path:
        json_path.write_text(json.dumps(doc, indent=2))
    return code
