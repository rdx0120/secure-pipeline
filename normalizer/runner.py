"""Executes the scanner legs and collects the independent probes.

Two rules this module exists to enforce:

1. EVERY SCANNER IS FORCED TO EXIT 0. No `--error`, no `--exit-code 1`. The
   orchestrator alone decides block vs warn. A scanner's own exit code is
   recorded as evidence and never used as a gate -- semgrep and trivy both
   return 0 with findings present anyway, so trusting it fails open.

2. COVERAGE PROBES ARE INDEPENDENT OF THE SCANNERS. The population each tool
   should have examined is measured by this module, not reported by the tool.
"""
from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .adapters import ScanRun


@dataclass(frozen=True)
class Probes:
    python_files_on_disk: int
    python_files_git_tracked: int
    commits: int
    #: True when the checkout is shallow. A shallow clone silently caps what
    #: any history-scanning tool can see.
    shallow: bool
    resolvable_packages: int
    declared_dependencies: int
    lockfile_packages: int

    def as_dict(self) -> dict[str, int]:
        return {
            "python_files_on_disk": self.python_files_on_disk,
            "python_files_git_tracked": self.python_files_git_tracked,
            "commits": self.commits,
            "shallow": int(self.shallow),
            "packages": self.resolvable_packages,
            "declared_dependencies": self.declared_dependencies,
            "lockfile_packages": self.lockfile_packages,
        }


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


SEMGREPIGNORE_TEMPLATE = Path(__file__).parent.parent / "rules" / "semgrepignore.template"


@contextlib.contextmanager
def declared_scope(root: Path):
    """Install our scope declaration over semgrep's shipped default.

    Semgrep applies a built-in .semgrepignore template -- which excludes tests/
    -- whenever the project has none of its own. There is no supported flag to
    disable it (`--x-semgrepignore-filename` is INTERNAL and does not suppress
    the default; `--semgrepignore-v2` does not either). Writing a real file is
    the only stable override, so we install one and restore whatever was there.

    A project that ships its OWN .semgrepignore has made a deliberate decision,
    and we leave it alone.
    """
    target = root / ".semgrepignore"
    if target.exists():
        yield          # the project declared its own scope; respect it
        return
    try:
        target.write_text(SEMGREPIGNORE_TEMPLATE.read_text())
        yield
    finally:
        with contextlib.suppress(OSError):
            target.unlink()


def probe(root: Path, trivy_pkg_json: Path | None = None) -> Probes:
    on_disk = len([p for p in root.rglob("*.py") if ".git" not in p.parts])
    tracked = _run(["git", "ls-files", "*.py"], root).stdout.split()
    commits = _run(["git", "rev-list", "--count", "HEAD"], root).stdout.strip()
    shallow = _run(["git", "rev-parse", "--is-shallow-repository"],
                   root).stdout.strip() == "true"

    packages = 0
    if trivy_pkg_json and trivy_pkg_json.exists() and trivy_pkg_json.stat().st_size:
        doc = json.loads(trivy_pkg_json.read_text())
        for res in doc.get("Results") or []:
            packages += len(res.get("Packages") or [])

    declared = 0
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        import tomllib
        data = tomllib.loads(pyproject.read_text())
        proj = data.get("project", {})
        declared = len(proj.get("dependencies") or [])
        for extra in (proj.get("optional-dependencies") or {}).values():
            declared += len(extra)

    # Independent of trivy: parse the lockfile ourselves so `examined` and
    # `denominator` are never two readings of the same measurement.
    lock = root / "uv.lock"
    lockfile_packages = 0
    if lock.exists():
        import tomllib
        pkgs = tomllib.loads(lock.read_text()).get("package") or []
        lockfile_packages = len([p for p in pkgs if p.get("name") != root.name])

    return Probes(
        python_files_on_disk=on_disk,
        python_files_git_tracked=len(tracked),
        commits=int(commits) if commits.isdigit() else 0,
        shallow=shallow,
        resolvable_packages=packages,
        declared_dependencies=declared,
        lockfile_packages=lockfile_packages,
    )


def examined_paths(runs: dict[str, ScanRun]) -> dict[str, set[str]]:
    """Which files each leg provably opened.

    Disagreement is only meaningful against this: a tool that stayed silent on
    a file it never opened tells you nothing.
    """
    out: dict[str, set[str]] = {}
    b = runs.get("bandit")
    if b:
        m = (b.documents["findings"].get("metrics") or {})
        out["bandit"] = {k.lstrip("./") for k in m if k != "_totals"}
    sg = runs.get("semgrep")
    if sg and "metrics" in sg.documents:
        out["semgrep"] = set((sg.documents["metrics"].get("paths") or {}).get("scanned") or [])
    return out


def scan(root: Path, out: Path, semgrep_config: str) -> dict[str, ScanRun]:
    """Run all four legs. Never raises on scanner failure; records it."""
    out.mkdir(parents=True, exist_ok=True)
    runs: dict[str, ScanRun] = {}

    def tool(name: str) -> str | None:
        return shutil.which(name)

    # -- trivy: package inventory first, so probes can count what IS resolvable
    pkg_json = out / "trivy-packages.json"
    if tool("trivy"):
        _run(["trivy", "fs", "--format", "json", "--list-all-pkgs",
              "-o", str(pkg_json), "."], root)
    probes = probe(root, pkg_json).as_dict()

    # -- bandit: JSON, not SARIF (SARIF omits `level` for MEDIUM)
    if tool("bandit"):
        p = out / "bandit.json"
        r = _run(["bandit", "-r", ".", "-f", "json", "-o", str(p)], root)
        if p.exists() and p.stat().st_size:
            runs["bandit"] = ScanRun(
                tool="bandit", documents={"findings": json.loads(p.read_text())},
                probes=probes, exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                workspace=root, tool_version=_version("bandit", ["bandit", "--version"]),
            )

    # -- gitleaks
    if tool("gitleaks"):
        p = out / "gitleaks.sarif"
        r = _run(["gitleaks", "detect", "--report-format", "sarif",
                  "--report-path", str(p), "--exit-code", "0"], root)
        if p.exists() and p.stat().st_size:
            runs["gitleaks"] = ScanRun(
                tool="gitleaks", documents={"findings": json.loads(p.read_text())},
                probes=probes, exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                workspace=root,
            )

    # -- semgrep: SARIF for findings, JSON for coverage.
    #    --verbose so `paths.skipped` is populated; without it semgrep reports
    #    the skip count only in its human summary and the attestation has to
    #    admit the skip list is unavailable.
    if tool("semgrep"):
        sarif, sjson = out / "semgrep.sarif", out / "semgrep.json"
        # Resolve a local ruleset against the CALLER's cwd before handing it to
        # semgrep, which runs with cwd=root. A relative --config silently
        # resolved against the scanned repo, semgrep errored, and the leg
        # examined 0 files -- caught by the attestation rather than shipped as
        # a clean scan.
        cfg = semgrep_config
        namespace = None
        if not cfg.startswith(("p/", "r/")) and Path(cfg).exists():
            resolved = Path(cfg).resolve()
            cfg = str(resolved)
            # Mirrors how semgrep derives a rule-id prefix from a local path.
            namespace = ".".join(resolved.parts[1:]) if resolved.is_dir() else None
        base = ["semgrep", "--config", cfg, "--metrics=off", "--verbose"]
        with declared_scope(root):
            r = _run(base + ["--sarif", "-o", str(sarif), "."], root)
            _run(base + ["--json", "-o", str(sjson), "."], root)
        if sarif.exists() and sarif.stat().st_size:
            docs = {"findings": json.loads(sarif.read_text())}
            if sjson.exists() and sjson.stat().st_size:
                docs["metrics"] = json.loads(sjson.read_text())
            runs["semgrep"] = ScanRun(
                tool="semgrep", documents=docs, probes=probes,
                exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr, workspace=root,
                context={"rule_namespace": namespace},
            )

    # -- trivy findings
    if tool("trivy"):
        p = out / "trivy-fs.sarif"
        r = _run(["trivy", "fs", "--format", "sarif", "-o", str(p), "."], root)
        if p.exists() and p.stat().st_size:
            runs["trivy-fs"] = ScanRun(
                tool="trivy-fs", documents={"findings": json.loads(p.read_text())},
                probes=probes, exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                workspace=root,
            )
    return runs


def _version(_name: str, cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
        return out.split()[-1] if out else None
    except OSError:
        return None
