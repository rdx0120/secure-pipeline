"""Normalized finding + coverage model.

Two outputs, not one:
  * Finding  - normalized, deduplicated, policy-gated security findings.
  * Coverage - what a scanner leg actually examined, asserted against a floor.

A leg that examined zero units of its input type is a build failure, exactly
like a critical finding. Silence is not success.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    #: No adapter could resolve a severity. This FAILS THE BUILD. It is never
    #: coerced to a default -- when an upstream format shifts, break loudly.
    UNKNOWN = "unknown"


class SeveritySource(str, Enum):
    """Where a finding's severity came from. Mandatory, fixed set.

    This is the field that makes the bandit failure visible instead of silent,
    and the field that catches tool version drift a year from now.
    """

    BANDIT_PROPERTIES = "bandit.results[].issue_severity+issue_confidence"
    TRIVY_SECURITY_SEVERITY = "trivy.rules[].properties.security-severity"
    SEMGREP_RULE_LEVEL = "semgrep.rules[].defaultConfiguration.level"
    #: gitleaks emits no severity vocabulary anywhere. `high` is OUR policy
    #: judgment, not the tool's: a verified live secret is high by definition.
    POLICY_CONSTANT = "policy.constant"
    #: Extraction failed. Pairs with Severity.UNKNOWN and fails the build.
    UNRESOLVED = "unresolved"


class SnippetBasis(str, Enum):
    """What `snippet_sha256` was computed over.

    SCHEMA AMENDMENT (see report): the agreed schema says snippet_sha256 is
    "always populated", but trivy findings have no snippet at all -- they are
    identified by (CVE, package, version). Rather than emit a hash of the empty
    string and pretend, the adapter hashes a tool-specific identity surrogate
    and records which basis was used, so `id` stability stays auditable.
    """

    SNIPPET = "snippet"
    IDENTITY_SURROGATE = "identity_surrogate"


class CoverageStatus(str, Enum):
    OK = "OK"
    FAIL_NO_COVERAGE = "FAIL_NO_COVERAGE"
    FAIL_BELOW_FLOOR = "FAIL_BELOW_FLOOR"
    #: The tool did not report what it examined, and no independent probe was
    #: supplied. Unprovable coverage is not passing coverage.
    FAIL_UNVERIFIABLE = "FAIL_UNVERIFIABLE"


def sha256_hex(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    tool: str
    tool_version: str | None
    rule_id: str
    rule_name: str | None
    message: str
    severity: Severity
    severity_source: SeveritySource
    confidence: str | None
    path: str
    start_line: int | None
    end_line: int | None
    #: Null by default. Populated ONLY for tools explicitly marked
    #: non-secret-bearing, and even then only when the caller opts in.
    snippet: str | None
    snippet_sha256: str
    snippet_basis: SnippetBasis
    raw_pointer: str
    cve: str | None = None
    cvss_score: float | None = None
    #: SCHEMA AMENDMENT: SCA findings are about a package, not a line. Without
    #: this, two CVEs on different packages in the same requirements.txt line
    #: are indistinguishable after normalization.
    component: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Deliberately excludes line numbers.

        A finding must survive an unrelated edit above it; otherwise every
        suppression expires the moment someone adds an import.
        """
        return sha256_hex(
            "|".join([self.tool, self.rule_id, self.path, self.snippet_sha256])
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d = {k: (v.value if isinstance(v, Enum) else v) for k, v in d.items()}
        return {"id": self.id, **d}


@dataclass(frozen=True)
class Coverage:
    """What one leg examined, and out of what population.

    `unit` is deliberately tool-specific -- `python_files_on_disk` is NOT
    `python_files_git_tracked`. bandit walks the filesystem and saw 21 files;
    semgrep scans git-tracked paths and saw 15. Reporting both as "files"
    implies a comparison that does not hold, and invites the reader to diff two
    different populations and conclude a scanner is broken.

    Keeping the populations distinct is also what makes the stronger check
    possible later: if the git-tracked population drops well below the on-disk
    one, something got .gitignore'd out of scanning.
    """

    tool: str
    unit: str
    examined: int
    floor: int
    status: CoverageStatus
    #: How `examined` was established. Never inferred from the findings list --
    #: a scanner that found nothing and a scanner that looked at nothing produce
    #: identical finding arrays.
    evidence: str
    #: Size of the population this tool SHOULD have examined, in its own unit.
    #: None when the runner supplied no inventory probe.
    denominator: int | None = None
    denominator_source: str | None = None
    detail: str | None = None

    @classmethod
    def assess(
        cls, tool: str, unit: str, examined: int | None, floor: int, evidence: str,
        denominator: int | None = None, denominator_source: str | None = None,
        detail: str | None = None,
    ) -> "Coverage":
        if examined is None:
            status = CoverageStatus.FAIL_UNVERIFIABLE
            examined = -1
        elif examined == 0:
            status = CoverageStatus.FAIL_NO_COVERAGE
        elif examined < floor:
            status = CoverageStatus.FAIL_BELOW_FLOOR
        else:
            status = CoverageStatus.OK
        return cls(tool, unit, examined, floor, status, evidence,
                   denominator, denominator_source, detail)

    @property
    def ok(self) -> bool:
        return self.status is CoverageStatus.OK

    @property
    def ratio(self) -> float | None:
        """Fraction of its own population the tool examined."""
        if self.denominator in (None, 0) or self.examined < 0:
            return None
        return self.examined / self.denominator

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass(frozen=True)
class AdapterResult:
    findings: list[Finding]
    coverage: Coverage

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "coverage": self.coverage.to_dict(),
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=indent,
        )
