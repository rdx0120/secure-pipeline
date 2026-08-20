"""trivy fs adapter.

The best-behaved input and the most dangerous result. Its SARIF is complete --
`error`/`warning`/`note` on results AND numeric `security-severity` (CVSS) on
rules. We take the numeric value: it is finer-grained than the categorical
level and survives trivy changing its own bucketing.

The danger is coverage. Against the real target repo trivy emitted a run with
ZERO rules and ZERO results and exited 0, because `requirements.txt` pins
nothing (`requests>=2.31`) and trivy's pip parser cannot resolve a range. An
empty findings array from a scanner that examined no packages is
indistinguishable, in the findings channel alone, from a clean bill of health.
That is the entire reason the coverage attestation exists.
"""
from __future__ import annotations

import re
from typing import Any

from ..model import AdapterResult, Coverage, Finding, Severity, SeveritySource
from .base import ScanRun, build_rule_index, normalize_path, pointer, redact, result_location

_CVE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)", re.IGNORECASE)


def _from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class TrivyAdapter:
    tool = "trivy-fs"
    #: Resolvable packages, which is NOT the count of declared requirements --
    #: an unpinned range declares a dependency that resolves to nothing.
    unit = "resolvable_packages"
    floor = 1
    secret_bearing = False

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult:
        doc: dict[str, Any] = run.documents["findings"]
        sarif_run = doc["runs"][0]
        driver = sarif_run["tool"]["driver"]
        rules = build_rule_index(driver)
        version = run.tool_version or driver.get("version")
        # trivy leaks the absolute host path here; used to re-relativize URIs.
        base = (sarif_run.get("originalUriBaseIds") or {}).get("ROOTPATH", {}).get("uri")

        findings: list[Finding] = []
        for i, r in enumerate(sarif_run.get("results", [])):
            rule_id = r.get("ruleId") or ""
            rule = rules.get(rule_id)
            score = None
            if rule is not None:
                raw = (rule.get("properties") or {}).get("security-severity")
                try:
                    score = float(raw) if raw is not None else None
                except (TypeError, ValueError):
                    score = None
            if score is None:
                severity, source = Severity.UNKNOWN, SeveritySource.UNRESOLVED
            else:
                severity, source = _from_cvss(score), SeveritySource.TRIVY_SECURITY_SEVERITY

            phys = result_location(r)
            region = phys.get("region") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri")
            path = normalize_path(uri, run.workspace)
            if base and path.startswith(base.replace("file://", "")):
                path = normalize_path(path, None)

            msg = r.get("message", {}).get("text", "")
            cve_match = _CVE.search(rule_id) or _CVE.search(msg)
            # SCA findings identify a package, not a line. The surrogate is what
            # keeps two CVEs on different packages in one manifest from
            # collapsing to the same id.
            component = _component(msg)
            snippet, digest, basis = redact(
                None,
                secret_bearing=self.secret_bearing,
                include_snippets=include_snippets,
                surrogate=f"{rule_id}|{component or path}",
            )
            refs = []
            if rule is not None:
                refs = [u for u in [rule.get("helpUri")] if u]
            findings.append(
                Finding(
                    tool=self.tool,
                    tool_version=version,
                    rule_id=rule_id,
                    rule_name=(rule or {}).get("shortDescription", {}).get("text"),
                    message=msg,
                    severity=severity,
                    severity_source=source,
                    confidence=None,
                    path=path,
                    start_line=region.get("startLine"),
                    end_line=region.get("endLine"),
                    snippet=snippet,
                    snippet_sha256=digest,
                    snippet_basis=basis,
                    raw_pointer=pointer("trivy-fs.sarif", i),
                    cve=cve_match.group(1).upper() if cve_match else None,
                    cvss_score=score,
                    component=component,
                    references=refs,
                )
            )

        # NEVER infer coverage from the findings list. Packages examined must
        # come from an independent inventory of the lockfile.
        examined = run.probes.get("packages")
        coverage = Coverage.assess(
            tool=self.tool, unit=self.unit, examined=examined, floor=self.floor,
            evidence=(
                "runner probe: resolved packages in lockfile"
                if examined is not None
                else "none: trivy SARIF reports no package inventory"
            ),
            # Declared DIRECT deps are not the population: a lockfile resolves
            # them plus their transitive closure. Comparing 16 resolvable
            # against 3 declared produced a meaningless "16 of 3".
            denominator=run.probes.get("lockfile_packages"),
            denominator_source="runner probe: packages parsed from uv.lock",
            detail=_no_coverage_detail(run) if examined == 0 else None,
        )
        return AdapterResult(findings=findings, coverage=coverage)


def _no_coverage_detail(run: ScanRun) -> str:
    """Explain a zero-package scan in terms of THIS repository.

    The previous message read "an unpinned requirements.txt yields zero packages
    and exit 0" -- true of the first repository this pipeline ever scanned, and
    asserted about every repository since. Told YARAdec, which has no
    `requirements.txt` at all, that its `requirements.txt` was the problem.

    A diagnostic that names a file the repository does not contain is making a
    claim it has not checked, which is the failure this project is about.
    """
    manifests = run.context.get("manifests")
    if manifests is None:
        return ("no packages resolved; the manifests present were not recorded, "
                "so the cause cannot be attributed")
    if not manifests:
        return ("no dependency manifest found in this repository, so there was "
                "nothing for trivy to resolve")
    found = ", ".join(manifests)
    return (f"no packages resolved from {found}. trivy needs concrete pinned "
            f"versions -- a lockfile -- not declared ranges")


def _component(message: str) -> str | None:
    """trivy phrases messages as 'Package: x\\nInstalled Version: y\\n...'."""
    pkg = re.search(r"Package:\s*(\S+)", message)
    ver = re.search(r"Installed Version:\s*(\S+)", message)
    if not pkg:
        return None
    return f"{pkg.group(1)}@{ver.group(1)}" if ver else pkg.group(1)
