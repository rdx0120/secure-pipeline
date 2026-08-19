"""semgrep adapter.

Severity lives ONLY on the rule. In the baseline all 148 results had no `level`
key whatsoever; `tool.driver.rules[].defaultConfiguration.level` was the sole
carrier. A result->rule join is mandatory, not an optimization.

Coverage is the subtle one. semgrep scans git-tracked files only and applies a
default `.semgrepignore`; in the baseline it silently skipped 12 files and
examined 15. The SARIF reports neither number. semgrep's JSON output does, via
`paths.scanned`, so the runner is expected to emit both formats and hand the
JSON over as the "metrics" document. Whatever semgrep actually examined must be
reported, never assumed.
"""
from __future__ import annotations

from typing import Any

from ..model import AdapterResult, Coverage, Finding, Severity, SeveritySource
from .base import ScanRun, build_rule_index, normalize_path, pointer, redact, result_location

_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "note": Severity.LOW,
}


class SemgrepAdapter:
    tool = "semgrep"
    unit = "python_files"
    floor = 1
    #: semgrep snippets are source code, not credentials -- but a rule that
    #: matches a hardcoded secret would still capture one, so snippets remain
    #: opt-in per run rather than on by default.
    secret_bearing = False

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult:
        doc: dict[str, Any] = run.documents["findings"]
        sarif_run = doc["runs"][0]
        driver = sarif_run["tool"]["driver"]
        rules = build_rule_index(driver)
        version = run.tool_version or driver.get("semanticVersion")

        findings: list[Finding] = []
        for i, r in enumerate(sarif_run.get("results", [])):
            rule_id = r.get("ruleId") or ""
            rule = rules.get(rule_id)
            # The join is the whole severity story. A missing rule is a real
            # failure, not a reason to invent a default.
            if rule is None:
                severity, source = Severity.UNKNOWN, SeveritySource.UNRESOLVED
            else:
                level = (rule.get("defaultConfiguration") or {}).get("level")
                severity = _LEVEL.get(level, Severity.UNKNOWN)
                source = (
                    SeveritySource.SEMGREP_RULE_LEVEL
                    if severity is not Severity.UNKNOWN
                    else SeveritySource.UNRESOLVED
                )

            phys = result_location(r)
            region = phys.get("region") or {}
            path = normalize_path(
                (phys.get("artifactLocation") or {}).get("uri"), run.workspace
            )
            snippet, digest, basis = redact(
                (region.get("snippet") or {}).get("text"),
                secret_bearing=self.secret_bearing,
                include_snippets=include_snippets,
                surrogate=f"{rule_id}|{path}",
            )
            findings.append(
                Finding(
                    tool=self.tool,
                    tool_version=version,
                    rule_id=rule_id,
                    rule_name=(rule or {}).get("name")
                    or ((rule or {}).get("shortDescription") or {}).get("text"),
                    message=r.get("message", {}).get("text", ""),
                    severity=severity,
                    severity_source=source,
                    confidence=None,
                    path=path,
                    start_line=region.get("startLine"),
                    end_line=region.get("endLine"),
                    snippet=snippet,
                    snippet_sha256=digest,
                    snippet_basis=basis,
                    raw_pointer=pointer("semgrep.sarif", i),
                )
            )

        metrics = run.documents.get("metrics") or {}
        paths = metrics.get("paths") or {}
        scanned = paths.get("scanned")
        if scanned is not None:
            examined, evidence = len(scanned), "semgrep.json#/paths/scanned"
            # `paths.skipped` is absent unless semgrep ran with --verbose. The
            # "12 files skipped" line from the baseline exists ONLY in the human
            # summary, so we must not report a skip count we do not have.
            skipped = paths.get("skipped")
            detail = (
                f"{len(skipped)} paths skipped by .semgrepignore / untracked"
                if skipped is not None
                else "skip list unavailable (semgrep omits paths.skipped without --verbose)"
            )
        else:
            examined = run.probes.get("python_files")
            evidence = (
                "runner probe: git ls-files '*.py'"
                if examined is not None
                else "none: semgrep SARIF does not report scanned paths"
            )
            detail = None

        coverage = Coverage.assess(
            tool=self.tool, unit=self.unit, examined=examined, floor=self.floor,
            evidence=evidence, detail=detail,
        )
        return AdapterResult(findings=findings, coverage=coverage)
