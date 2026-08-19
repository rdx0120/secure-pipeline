"""Adapter interface.

Shaped by two facts discovered in the Session 1 baseline:

1. NO scanner records what it examined in its SARIF. None of the four emit
   `run.artifacts[]`; gitleaks emits no `invocations` at all. Coverage
   therefore CANNOT be derived from the findings document. An adapter that
   only received SARIF could not honour the coverage attestation contract.
   So `parse()` takes a ScanRun, not a document.

2. Severity extraction has no generic path. Each adapter declares its own
   and stamps `severity_source` on every finding it emits.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, runtime_checkable

from ..model import AdapterResult, Finding, SnippetBasis, sha256_hex


@dataclass(frozen=True)
class ScanRun:
    """Everything one scanner leg produced.

    `documents` is keyed by role rather than by format, because the document an
    adapter parses is not always the one the tool advertises. The bandit
    adapter reads role "findings" from bandit's JSON, not its SARIF, because
    the SARIF drops MEDIUM severity entirely.
    """

    tool: str
    documents: dict[str, Any] = field(default_factory=dict)
    #: Independent probes of the input inventory, e.g. {"python_files": 15}.
    #: Used when the tool itself reports nothing about what it examined.
    probes: dict[str, int] = field(default_factory=dict)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    workspace: Path | None = None
    tool_version: str | None = None
    #: Runner-supplied facts an adapter cannot derive from its documents,
    #: e.g. the namespace semgrep derived from a local config path.
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_files(cls, tool: str, *, workspace: Path | None = None,
                   probes: dict[str, int] | None = None, exit_code: int | None = None,
                   stdout: str = "", stderr: str = "", **documents: Path | str) -> "ScanRun":
        docs: dict[str, Any] = {}
        for role, path in documents.items():
            p = Path(path)
            #: A zero-byte output file fails on sight -- that is exactly how
            #: scorecard reported total failure while exiting 0.
            if p.stat().st_size == 0:
                raise EmptyDocumentError(f"{tool}: {role} document {p} is zero bytes")
            docs[role] = json.loads(p.read_text())
        return cls(tool=tool, documents=docs, probes=probes or {}, exit_code=exit_code,
                   stdout=stdout, stderr=stderr, workspace=workspace)


class EmptyDocumentError(RuntimeError):
    """A scanner produced an empty artifact. Never treated as 'no findings'."""


@runtime_checkable
class Adapter(Protocol):
    tool: str
    #: Coverage unit and floor, per the attestation contract.
    unit: str
    floor: int
    #: True if this tool's snippets can contain live secrets. Snippets from a
    #: secret-bearing tool are NEVER written to disk, in any mode.
    secret_bearing: bool

    def parse(self, run: ScanRun, *, include_snippets: bool = False) -> AdapterResult: ...


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def normalize_path(uri: str | None, workspace: Path | None = None) -> str:
    """Repo-relative POSIX path.

    Handles the three shapes seen in the baseline: bare relative (bandit,
    gitleaks), `%SRCROOT%`-based (semgrep), and `ROOTPATH`-based with an
    absolute `originalUriBaseIds` (trivy, which leaks the host path).
    """
    if not uri:
        return ""
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    p = PurePosixPath(uri)
    if p.is_absolute() and workspace is not None:
        try:
            p = PurePosixPath(str(p)).relative_to(PurePosixPath(str(workspace)))
        except ValueError:
            pass
    s = str(p)
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/")


def build_rule_index(driver: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index `tool.driver.rules` by id, FOR LOOKUPS ONLY.

    Never use len() of this as evidence of anything: gitleaks emits all 222 of
    its rules regardless of which ones fired.
    """
    return {r["id"]: r for r in driver.get("rules", []) if "id" in r}


def redact(
    snippet_text: str | None,
    *,
    secret_bearing: bool,
    include_snippets: bool,
    surrogate: str | None = None,
) -> tuple[str | None, str, SnippetBasis]:
    """Decide what leaves the adapter.

    Redaction happens HERE, in the adapter, before anything is written to disk
    or uploaded. gitleaks puts the plaintext secret in `region.snippet.text`;
    forwarding that SARIF to code scanning or an artifact bucket republishes
    the secret into a second location with different access controls.

    Returns (snippet_or_None, snippet_sha256, basis).
    """
    if snippet_text:
        digest = sha256_hex(snippet_text)
        emit = snippet_text if (include_snippets and not secret_bearing) else None
        return emit, digest, SnippetBasis.SNIPPET
    if surrogate is None:
        raise ValueError("no snippet and no identity surrogate supplied")
    return None, sha256_hex(surrogate), SnippetBasis.IDENTITY_SURROGATE


def result_location(result: dict[str, Any]) -> dict[str, Any]:
    locs = result.get("locations") or []
    if not locs:
        return {}
    return (locs[0].get("physicalLocation") or {})


def pointer(document_role: str, index: int) -> str:
    return f"{document_role}#/runs/0/results/{index}"
