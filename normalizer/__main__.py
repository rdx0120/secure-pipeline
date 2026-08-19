"""End-to-end: scan -> adapt -> attest + normalize.

Exit codes are the orchestrator's, never a scanner's:
  0  coverage passed, findings merged
  2  a coverage floor failed
  3  a finding had unresolvable severity
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import attest, gate, normalize
from .adapters import ADAPTERS
from .runner import examined_paths, scan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="normalizer")
    ap.add_argument("root", type=Path)
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--semgrep-config", default="p/python")
    ap.add_argument("--include-snippets", action="store_true",
                    help="opt in to snippets for non-secret-bearing tools only")
    ap.add_argument("--policy", type=Path, default=Path("policy.yaml"))
    # Exceptions are FEDERATED: they live in the repo being scanned, reviewed
    # by whoever owns that code. policy.yaml is centrally governed here.
    ap.add_argument("--exceptions", type=Path, default=None,
                    help="default: <root>/.security/exceptions.yaml")
    ap.add_argument("--no-gate", action="store_true",
                    help="emit attestation and findings without gating")
    args = ap.parse_args(argv)

    root = args.root.resolve()
    exceptions_path = args.exceptions or (root / ".security" / "exceptions.yaml")
    runs = scan(root, args.out, args.semgrep_config)
    results = {
        tool: ADAPTERS[tool].parse(run, include_snippets=args.include_snippets)
        for tool, run in runs.items()
        if tool in ADAPTERS
    }

    args.out.mkdir(parents=True, exist_ok=True)
    taxonomy = (yaml.safe_load(args.policy.read_text()) or {}).get("taxonomy", {}) \
        if args.policy.exists() else {}

    attest.main(results, args.out / "attestation.json")
    print()
    normalize.main(
        results, args.out / "findings.json",
        taxonomy=taxonomy, examined=examined_paths(runs),
    )
    if args.no_gate:
        return 0

    print()
    return gate.main(
        json.loads((args.out / "findings.json").read_text()),
        json.loads((args.out / "attestation.json").read_text()),
        args.policy, exceptions_path, args.out / "gate.json", root=root,
    )


if __name__ == "__main__":
    sys.exit(main())
