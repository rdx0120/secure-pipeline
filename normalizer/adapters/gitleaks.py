"""gitleaks adapter.

The hardest input, for two reasons that have nothing to do with parsing:

1. NO SEVERITY VOCABULARY EXISTS. Results carry no `level`; rule objects carry
   only `id` and `shortDescription`. There is nothing to extract. Severity is
   assigned by POLICY as `high` and stamped `severity_source=policy.constant`,
   so the attestation records that this is our judgment, not the tool's.

2. THE SARIF CONTAINS THE PLAINTEXT SECRET, in `region.snippet.text`. This
   adapter is the redaction boundary. `secret_bearing = True` means snippets
   are dropped unconditionally -- `include_snippets=True` cannot override it.

gitleaks emits no `invocations` and no `artifacts`, so the SARIF says nothing
about what was scanned. Coverage requires an external probe (commits scanned),
which the runner supplies; absent it, coverage is FAIL_UNVERIFIABLE rather
than a comfortable zero.
"""
from __future__ import annotations

import re
from typing import Any

from ..model import AdapterResult, Coverage, Finding, Severity, SeveritySource
from .base import ScanRun, build_rule_index, normalize_path, pointer, redact, result_location

#: gitleaks logs "N commits scanned." to stderr. Parsed only as a fallback when
#: the runner supplied no independent probe -- human log text is not a contract.
_COMMITS = re.compile(r"(\d+)\s+commits?\s+scanned", re.IGNORECASE)


class GitleaksAdapter:
    tool = "gitleaks"
    unit = "commits"
    floor = 1
    #: Non-negotiable. A live credential must not be copied into a normalized
    #: findings file that is uploaded as a build artifact.
    secret_bearing = True

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult:
        doc: dict[str, Any] = run.documents["findings"]
        sarif_run = doc["runs"][0]
        driver = sarif_run["tool"]["driver"]
        # Lookups only. gitleaks emits all 222 rules regardless of what fired,
        # so len(rules) is not evidence of anything.
        rules = build_rule_index(driver)
        version = run.tool_version or driver.get("semanticVersion")

        findings: list[Finding] = []
        for i, r in enumerate(sarif_run.get("results", [])):
            phys = result_location(r)
            region = phys.get("region") or {}
            path = normalize_path(
                (phys.get("artifactLocation") or {}).get("uri"), run.workspace
            )
            rule_id = r.get("ruleId") or ""
            rule = rules.get(rule_id, {})

            secret_text = (region.get("snippet") or {}).get("text")
            snippet, digest, basis = redact(
                secret_text,
                secret_bearing=self.secret_bearing,   # forces snippet -> None
                include_snippets=include_snippets,
                surrogate=f"{rule_id}|{path}",
            )
            findings.append(
                Finding(
                    tool=self.tool,
                    tool_version=version,
                    rule_id=rule_id,
                    rule_name=(rule.get("shortDescription") or {}).get("text"),
                    message=r.get("message", {}).get("text", ""),
                    # No severity exists upstream. This is policy.
                    severity=Severity.HIGH,
                    severity_source=SeveritySource.POLICY_CONSTANT,
                    confidence=None,
                    path=path,
                    start_line=region.get("startLine"),
                    end_line=region.get("endLine"),
                    snippet=snippet,
                    snippet_sha256=digest,
                    snippet_basis=basis,
                    raw_pointer=pointer("gitleaks.sarif", i),
                )
            )

        # `examined` must be gitleaks' OWN claim about what it did; the probe is
        # the independent population it is measured against. Using the probe for
        # both makes the row tautological -- 6 of 6 proves nothing.
        m = _COMMITS.search(run.stderr or "") or _COMMITS.search(run.stdout or "")
        if m:
            examined = int(m.group(1))
            evidence = "gitleaks stderr log text (its only coverage signal)"
        elif run.probes.get("commits") is not None:
            examined = run.probes["commits"]
            evidence = "runner probe (fallback): git rev-list --count"
        else:
            examined = None
            evidence = "none: gitleaks SARIF has no invocations or artifacts"

        coverage = Coverage.assess(
            tool=self.tool, unit=self.unit, examined=examined, floor=self.floor,
            evidence=evidence,
            denominator=run.probes.get("commits"),
            denominator_source="runner probe: git rev-list --count HEAD",
        )
        return AdapterResult(findings=findings, coverage=coverage)
