"""End-to-end: scan -> adapt -> attest + normalize.

Exit codes are the orchestrator's, never a scanner's:
  0  coverage passed, findings merged
  2  a coverage floor failed
  3  a finding had unresolvable severity
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import attest, normalize
from .adapters import ADAPTERS
from .runner import scan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="normalizer")
    ap.add_argument("root", type=Path)
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--semgrep-config", default="p/python")
    ap.add_argument("--include-snippets", action="store_true",
                    help="opt in to snippets for non-secret-bearing tools only")
    args = ap.parse_args(argv)

    runs = scan(args.root.resolve(), args.out, args.semgrep_config)
    results = {
        tool: ADAPTERS[tool].parse(run, include_snippets=args.include_snippets)
        for tool, run in runs.items()
        if tool in ADAPTERS
    }

    code_a = attest.main(results, args.out / "attestation.json")
    print()
    code_n = normalize.main(results, args.out / "findings.json")
    return code_a or code_n


if __name__ == "__main__":
    sys.exit(main())
