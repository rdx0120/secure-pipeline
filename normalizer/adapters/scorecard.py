"""OpenSSF Scorecard adapter.

The leg that motivated the whole design, and the last one built.

Session 1 ran Scorecard against this repository and it **exited 0 while writing
a 0-byte file** -- a total failure that reported success. That single
observation is why this project emits a coverage attestation at all. Until now,
the tool that produced the founding observation was the only tool the design
did not cover.

Its failure modes are not hypothetical, and both have been reproduced:

  * exit 0, 0-byte output      (Session 1, `--repo` against a repo it could not reach)
  * exit 1, 0-byte output      (local mode, a check that cannot run offline)

The exit code is therefore not evidence of anything. An empty document fails on
sight -- see `ScanRun.from_files` -- and a run whose checks all came back
without a resolved score is FAIL_NO_COVERAGE, not a clean bill of health.
"""
from __future__ import annotations

from typing import Any

from ..model import AdapterResult, Coverage, Finding, Severity, SeveritySource
from .base import ScanRun, redact

#: Scorecard scores each check 0-10, and uses -1 for "could not be evaluated".
#: A -1 is a COVERAGE fact, not a finding: the check did not run, so it says
#: nothing about the repository either way.
INCONCLUSIVE = -1


def _severity(score: int) -> Severity:
    if score >= 10:
        return Severity.INFO
    if score >= 7:
        return Severity.LOW
    if score >= 4:
        return Severity.MEDIUM
    if score >= 0:
        return Severity.HIGH
    return Severity.UNKNOWN


class ScorecardAdapter:
    tool = "scorecard"
    #: Checks that returned a resolved score -- NOT checks that appear in the
    #: output. A check present with score -1 was requested and did not run.
    unit = "scorecard_checks"
    floor = 1
    secret_bearing = False

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult:
        doc: dict[str, Any] = run.documents["findings"] or {}
        checks = doc.get("checks") or []
        version = run.tool_version or (doc.get("scorecard") or {}).get("version")

        findings: list[Finding] = []
        resolved = 0
        for i, c in enumerate(checks):
            score = c.get("score", INCONCLUSIVE)
            if score == INCONCLUSIVE:
                # Not a finding. Counted against coverage instead.
                continue
            resolved += 1
            if score >= 10:
                continue                      # a passing check is not a finding

            name = c.get("name", "")
            docs = c.get("documentation") or {}
            snippet, digest, basis = redact(
                None,
                secret_bearing=self.secret_bearing,
                include_snippets=include_snippets,
                # Scorecard findings identify a CHECK on a repository, not a
                # line of code. The check name is the stable identity.
                surrogate=f"{name}|{(doc.get('repo') or {}).get('name', '')}",
            )
            findings.append(
                Finding(
                    tool=self.tool,
                    tool_version=version,
                    rule_id=name,
                    rule_name=docs.get("short"),
                    message=f"{c.get('reason', '')} (score {score}/10)",
                    severity=_severity(score),
                    severity_source=SeveritySource.SCORECARD_CHECK_SCORE,
                    confidence=None,
                    # Repository-level posture: no file, no line.
                    path="",
                    start_line=None,
                    end_line=None,
                    snippet=snippet,
                    snippet_sha256=digest,
                    snippet_basis=basis,
                    raw_pointer=f"scorecard.json#/checks/{i}",
                    references=[u for u in [docs.get("url")] if u],
                )
            )

        # The denominator is the list of checks REQUESTED, supplied by the
        # runner from the `--checks` argument it passed. Reading it back out of
        # Scorecard's own output would make the row tautological -- the same
        # mistake that let a shallow clone report "1 of 1" for gitleaks.
        requested = run.probes.get("scorecard_checks_requested")
        aggregate = doc.get("score")
        coverage = Coverage.assess(
            tool=self.tool,
            unit=self.unit,
            examined=resolved if checks else 0,
            floor=self.floor,
            evidence="scorecard.json#/checks (entries with a resolved score)",
            denominator=requested,
            denominator_source="runner probe: --checks list passed to scorecard",
            detail=(
                f"aggregate score {aggregate}/10"
                if aggregate is not None and resolved
                else "no check returned a resolved score"
            ),
        )
        return AdapterResult(findings=findings, coverage=coverage)
