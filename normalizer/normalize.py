"""Merge findings across adapters into one clean list.

No policy here. No block/warn decision, no severity thresholds, no exceptions.
Merge, dedupe, sort -- that is all. Policy arrives later and operates on this
list; keeping the two separate means the merged list stays reviewable on its
own terms.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .model import AdapterResult, Finding, Severity

#: Sort order. `unknown` sorts FIRST, not last: an unresolved severity is a
#: normalizer bug or an upstream format change, and it should be the first
#: thing a reader sees rather than buried under the criticals.
_RANK = {
    Severity.UNKNOWN: 0,
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}


@dataclass(frozen=True)
class MergeReport:
    findings: list[Finding]
    total_in: int
    duplicates_collapsed: int
    unknown_severity: int

    @property
    def has_unresolved(self) -> bool:
        return self.unknown_severity > 0

    def to_dict(self) -> dict:
        return {
            "summary": {
                "findings": len(self.findings),
                "raw_findings": self.total_in,
                "duplicates_collapsed": self.duplicates_collapsed,
                "unknown_severity": self.unknown_severity,
                "by_severity": self.by_severity(),
                "by_tool": self.by_tool(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: _RANK[Severity(kv[0])]))

    def by_tool(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.tool] = out.get(f.tool, 0) + 1
        return dict(sorted(out.items()))


def merge(results: dict[str, AdapterResult]) -> MergeReport:
    seen: dict[str, Finding] = {}
    total = 0
    for _tool, res in results.items():
        for f in res.findings:
            total += 1
            # `id` excludes line numbers by design, so two adapters reporting
            # the same rule on the same file collapse even if their line
            # arithmetic differs. First writer wins; raw_pointer preserves the
            # path back to whichever document it came from.
            seen.setdefault(f.id, f)
    findings = sorted(
        seen.values(),
        key=lambda f: (_RANK[f.severity], f.tool, f.path, f.start_line or 0, f.rule_id),
    )
    return MergeReport(
        findings=findings,
        total_in=total,
        duplicates_collapsed=total - len(findings),
        unknown_severity=sum(1 for f in findings if f.severity is Severity.UNKNOWN),
    )


def render(report: MergeReport, limit: int = 20) -> str:
    out = ["NORMALIZED FINDINGS", ""]
    s = report.to_dict()["summary"]
    out.append(f"  {s['findings']} findings ({s['raw_findings']} raw, "
               f"{s['duplicates_collapsed']} duplicates collapsed)")
    out.append(f"  by severity: {s['by_severity'] or '{}'}")
    out.append(f"  by tool:     {s['by_tool'] or '{}'}")
    if report.has_unresolved:
        out.append(f"  !! {report.unknown_severity} finding(s) with UNRESOLVED severity")
    out.append("")
    head = ("SEVERITY", "TOOL", "RULE", "LOCATION")
    rows = [
        (f.severity.value, f.tool, f.rule_id,
         f"{f.path}:{f.start_line}" if f.start_line else f.path)
        for f in report.findings[:limit]
    ]
    if rows:
        w = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(head)]
        out.append("  ".join(h.ljust(w[i]) for i, h in enumerate(head)))
        out.append("  ".join("-" * x for x in w))
        for r in rows:
            out.append("  ".join(r[i].ljust(w[i]) for i in range(len(head))))
        if len(report.findings) > limit:
            out.append(f"... {len(report.findings) - limit} more")
    else:
        out.append("  (none)")
    return "\n".join(out)


def main(results: dict[str, AdapterResult], json_path=None) -> int:
    report = merge(results)
    print(render(report))
    if json_path:
        json_path.write_text(json.dumps(report.to_dict(), indent=2))
    # Merging is not a gate. The only thing that fails here is a normalizer
    # that could not resolve a severity -- break loudly on format drift.
    return 3 if report.has_unresolved else 0
