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

def strip_namespace(rule_id: str, namespace: str | None) -> str:
    """Remove the namespace semgrep derives from a LOCAL config path.

    With `--config rules/`, semgrep prefixes every rule id with the resolved
    directory as dots: `root.proj.secure-pipeline.rules.untrusted-xml-parse`.
    That makes rule_id -- and therefore the finding fingerprint, which is
    sha256(tool|rule_id|path|snippet) -- depend on WHERE the repo is checked
    out. The same finding would carry a different id on a CI runner than on a
    laptop, silently invalidating every exception in exceptions.yaml.

    Registry namespaces (`python.lang.security....`) are meaningful and are
    left alone; only the locally-derived prefix is stripped.
    """
    if namespace and rule_id.startswith(namespace + "."):
        return rule_id[len(namespace) + 1:]
    return rule_id


_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "note": Severity.LOW,
}


class SemgrepAdapter:
    tool = "semgrep"
    #: semgrep scans git-tracked paths only, minus .semgrepignore. A DIFFERENT
    #: population from bandit's on-disk walk -- never compare the two counts.
    unit = "python_files_git_tracked"
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
        namespace = run.context.get("rule_namespace")
        for i, r in enumerate(sarif_run.get("results", [])):
            raw_id = r.get("ruleId") or ""
            rule = rules.get(raw_id)
            rule_id = strip_namespace(raw_id, namespace)
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
                    rule_name=strip_namespace((rule or {}).get("name") or "", namespace)
                    or None,
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
            if skipped is None:
                detail = ("skip list unavailable "
                          "(semgrep omits paths.skipped without --verbose)")
            else:
                reasons: dict[str, int] = {}
                for sk in skipped:
                    reasons[sk.get("reason", "unknown")] = (
                        reasons.get(sk.get("reason", "unknown"), 0) + 1
                    )
                # An empty skip list rendered as "0 paths skipped: " -- a
                # trailing colon introducing nothing. The colon belongs to the
                # list, so it only appears when there is a list.
                breakdown = ", ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
                detail = (f"{len(skipped)} paths skipped: {breakdown}"
                          if breakdown else "0 paths skipped")
        else:
            examined = run.probes.get("python_files_git_tracked")
            evidence = (
                "runner probe: git ls-files '*.py'"
                if examined is not None
                else "none: semgrep SARIF does not report scanned paths"
            )
            detail = None

        coverage = Coverage.assess(
            tool=self.tool, unit=self.unit, examined=examined, floor=self.floor,
            evidence=evidence,
            denominator=run.probes.get("python_files_git_tracked"),
            denominator_source="runner probe: git ls-files '*.py'",
            detail=detail,
        )
        return AdapterResult(findings=findings, coverage=coverage)
