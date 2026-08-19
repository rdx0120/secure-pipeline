"""Merge findings across adapters into one clean list.

No policy here. No block/warn decision, no severity thresholds, no exceptions.
Merge, dedupe, sort -- that is all. Policy arrives later and operates on this
list; keeping the two separate means the merged list stays reviewable on its
own terms.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .model import AdapterResult, Finding, Severity, sha256_hex

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
class Corroboration:
    """Two tools reporting the same weakness at the same place.

    Cross-tool agreement is the most valuable thing two scanners can tell you.
    Collapsing the findings to shorten a list throws it away, so both records
    survive with distinct ids and this block is attached to each.
    """

    group_id: str
    weak_class: str
    agreeing_tools: list[str]
    count: int

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "weak_class": self.weak_class,
            "agreeing_tools": self.agreeing_tools,
            "count": self.count,
        }


def classify(finding: Finding, taxonomy: dict) -> str | None:
    """Map a finding to a coarse weakness class WE own.

    Deliberately not CWE. The tools do not agree on CWE assignments, and
    mapping through one would assert equivalences none of them actually make.
    """
    for weak_class, per_tool in (taxonomy or {}).items():
        for pattern in per_tool.get(finding.tool, []):
            if re.fullmatch(pattern, finding.rule_id):
                return weak_class
    return None


@dataclass(frozen=True)
class MergeReport:
    findings: list[Finding]
    total_in: int
    duplicates_collapsed: int
    unknown_severity: int
    #: finding.id -> Corroboration, for findings in a multi-tool group.
    corroboration: dict[str, Corroboration] = field(default_factory=dict)
    #: (weak_class, path, line) groups where one tool fired and another that
    #: examined the same file did not. A coverage gap in the quiet tool.
    disagreements: list[dict] = field(default_factory=list)

    @property
    def has_unresolved(self) -> bool:
        return self.unknown_severity > 0

    def to_dict(self) -> dict:
        out = []
        for f in self.findings:
            d = f.to_dict()
            corr = self.corroboration.get(f.id)
            # Presentation may group these; the data model never does.
            d["corroboration"] = corr.to_dict() if corr else None
            out.append(d)
        return {
            "summary": {
                "findings": len(self.findings),
                "raw_findings": self.total_in,
                "duplicates_collapsed": self.duplicates_collapsed,
                "unknown_severity": self.unknown_severity,
                "corroborated": len(self.corroboration),
                "by_severity": self.by_severity(),
                "by_tool": self.by_tool(),
            },
            "disagreements": self.disagreements,
            "findings": out,
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


def merge(
    results: dict[str, AdapterResult],
    taxonomy: dict | None = None,
    examined_paths: dict[str, set[str]] | None = None,
) -> MergeReport:
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

    # --- corroboration ----------------------------------------------------
    # Group on (weak_class, path, line). Findings that share a group are the
    # same weakness seen by different tools; they are NOT merged.
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        wc = classify(f, taxonomy or {})
        if wc is None:
            continue
        groups.setdefault((wc, f.path, f.start_line), []).append(f)

    corroboration: dict[str, Corroboration] = {}
    disagreements: list[dict] = []
    for (wc, path, line), members in groups.items():
        tools = sorted({m.tool for m in members})
        group_id = sha256_hex(f"{wc}|{path}|{line}")
        if len(tools) > 1:
            c = Corroboration(group_id, wc, tools, len(tools))
            for m in members:
                corroboration[m.id] = c
        elif examined_paths:
            # One tool fired. Another tool is only meaningfully SILENT if it
            # actually has a rule in this weakness class -- semgrep has no
            # equivalent of bandit's B101, so its silence on an assert is not a
            # coverage gap, it is an absence of scope. Without this the report
            # filled with 92 assertion_used "disagreements" that said nothing.
            capable = set((taxonomy or {}).get(wc, {}).keys())
            silent = sorted(
                t for t, paths in examined_paths.items()
                if t not in tools and t in capable and path in paths
            )
            if silent:
                disagreements.append({
                    "group_id": group_id, "weak_class": wc, "path": path,
                    "line": line, "flagged_by": tools, "silent": silent,
                })

    return MergeReport(
        findings=findings,
        total_in=total,
        duplicates_collapsed=total - len(findings),
        unknown_severity=sum(1 for f in findings if f.severity is Severity.UNKNOWN),
        corroboration=corroboration,
        disagreements=disagreements,
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


def main(results: dict[str, AdapterResult], json_path=None,
         taxonomy: dict | None = None,
         examined: dict[str, set[str]] | None = None) -> int:
    report = merge(results, taxonomy=taxonomy, examined_paths=examined)
    print(render(report))
    if json_path:
        json_path.write_text(json.dumps(report.to_dict(), indent=2))
    # Merging is not a gate. The only thing that fails here is a normalizer
    # that could not resolve a severity -- break loudly on format drift.
    return 3 if report.has_unresolved else 0
