"""bandit adapter.

Consumes bandit's JSON, NOT its SARIF. This is a deliberate rejection of the
tool's own SARIF support, on evidence:

  * LOW severity  -> SARIF `level: "note"`
  * MEDIUM severity -> the `level` key is OMITTED ENTIRELY

In the Session 1 baseline the two highest-signal findings in the repo (B314,
unsafe `ET.parse` in both parsers) were exactly the two with no `level`, while
90 `B101` asserts-in-tests came through as `note`. Any consumer reading
`result.level` ranks the real bugs below the test noise, or drops them.

bandit's JSON also carries `metrics`, giving a real coverage number (files
examined + LOC) that the SARIF has no way to express.
"""
from __future__ import annotations

from typing import Any

from ..model import AdapterResult, Coverage, Finding, Severity, SeveritySource
from .base import ScanRun, normalize_path, redact

#: bandit reports impact (severity) and certainty (confidence) separately.
#: We treat severity as the base and let LOW confidence downgrade one step;
#: nothing is ever upgraded by confidence alone.
_BASE = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
_DOWNGRADE = {
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}


def _severity(issue_severity: str | None, issue_confidence: str | None) -> Severity:
    base = _BASE.get((issue_severity or "").upper())
    if base is None:
        return Severity.UNKNOWN          # loud, not safe
    if (issue_confidence or "").upper() == "LOW":
        return _DOWNGRADE[base]
    return base


class BanditAdapter:
    tool = "bandit"
    #: bandit walks the filesystem: it sees untracked and gitignored files too.
    unit = "python_files_on_disk"
    floor = 1
    secret_bearing = False

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult:
        doc: dict[str, Any] = run.documents["findings"]
        results = doc.get("results", [])
        findings: list[Finding] = []

        for i, r in enumerate(results):
            path = normalize_path(r.get("filename"), run.workspace)
            rule_id = r.get("test_id") or ""
            snippet_text = r.get("code")
            surrogate = f"{rule_id}|{path}|{r.get('test_name')}"
            snippet, digest, basis = redact(
                snippet_text,
                secret_bearing=self.secret_bearing,
                include_snippets=include_snippets,
                surrogate=surrogate,
            )
            findings.append(
                Finding(
                    tool=self.tool,
                    tool_version=run.tool_version,
                    rule_id=rule_id,
                    rule_name=r.get("test_name"),
                    message=r.get("issue_text", ""),
                    severity=_severity(r.get("issue_severity"), r.get("issue_confidence")),
                    severity_source=SeveritySource.BANDIT_PROPERTIES,
                    confidence=(r.get("issue_confidence") or "").lower() or None,
                    path=path,
                    start_line=r.get("line_number"),
                    end_line=(r.get("line_range") or [None])[-1],
                    snippet=snippet,
                    snippet_sha256=digest,
                    snippet_basis=basis,
                    raw_pointer=f"bandit.json#/results/{i}",
                    references=[u for u in [r.get("more_info")] if u],
                )
            )

        # Coverage from bandit's own metrics block: the count of files it
        # actually opened, which is independent of whether anything fired.
        metrics = doc.get("metrics") or {}
        examined = len([k for k in metrics if k != "_totals"])
        loc = (metrics.get("_totals") or {}).get("loc")
        coverage = Coverage.assess(
            tool=self.tool,
            unit=self.unit,
            examined=examined if metrics else None,
            floor=self.floor,
            evidence="bandit.json#/metrics (per-file keys)",
            denominator=run.probes.get("python_files_on_disk"),
            denominator_source="runner probe: find . -name '*.py'",
            detail=f"{loc} LOC scanned" if loc is not None else None,
        )
        return AdapterResult(findings=findings, coverage=coverage)
