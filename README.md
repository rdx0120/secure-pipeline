# secure-pipeline

A scanner orchestrator with **two** outputs, not one:

1. **Findings** — normalized, deduplicated, policy-gated.
2. **A coverage attestation** — what each leg actually examined, asserted
   against a floor.

## Why the second output exists

The Session 1 baseline ran six scanners against a small Python repo. Four of
them reported success while looking at little or nothing:

| Leg | Reported | Actually examined |
|---|---|---|
| trivy fs | exit 0, empty SARIF run | **0 packages** — the pip parser cannot resolve `requests>=2.31` |
| syft | exit 0, valid SBOM | **0 Python components** (only GitHub Actions from `ci.yml`) |
| semgrep | exit 0, "scan completed successfully" | 15 files; **silently skipped 12** |
| scorecard | **exit 0** | nothing — wrote a **0-byte file** on total failure |

A scanner that found nothing and a scanner that looked at nothing produce an
identical findings array. **Silence is not success.** A leg that examined zero
units of its input type fails the build as loudly as a critical finding.

Coverage is never inferred from the findings list. It comes from the tool's own
metrics block where one exists (`bandit.json#/metrics`,
`semgrep.json#/paths/scanned`), and from an independent runner probe where none
does (gitleaks, trivy). Where neither is available the status is
`FAIL_UNVERIFIABLE` — unprovable coverage is not passing coverage.

## Secret redaction is an adapter responsibility

**gitleaks writes the plaintext secret into `region.snippet.text`.**

Forwarding that SARIF to GitHub code scanning, or uploading it to an artifact
bucket, republishes every detected credential into a second location with
different access controls and a different retention policy. The scanner that
finds your leaked key becomes the thing that leaks it again, more durably.

So redaction happens **in the adapter, before anything is written to disk or
uploaded** — not in a later export step that can be bypassed:

- `snippet` is `null` by default for every tool.
- `snippet_sha256` is always populated, so dedup and suppression still work
  without retaining the secret.
- Adapters declare `secret_bearing`. For gitleaks it is `True`, and
  `include_snippets=True` **cannot** override it. There is no flag that makes
  this pipeline write a credential to disk.
- Snippets pass through only for tools explicitly marked non-secret-bearing,
  and even then only when the caller opts in per run.

The raw SARIF files are never discarded — normalization is lossy by design and
`raw_pointer` is the escape hatch during triage — but they are treated as
secret-bearing artifacts and stay out of any upload path.

## Severity has no generic extraction path

Writing one universal `get_severity()` makes bandit's two real findings vanish.
Each adapter declares its own extraction and stamps `severity_source` on every
finding:

| Tool | Extraction | Why |
|---|---|---|
| bandit | `results[].issue_severity` × `issue_confidence` (from **JSON**, not SARIF) | SARIF maps LOW→`note` and **omits `level` entirely for MEDIUM** |
| trivy | `rules[id].properties["security-severity"]` (numeric CVSS) | Join result→rule; numeric beats categorical |
| semgrep | `rules[id].defaultConfiguration.level` | Join result→rule; result `level` is **always absent** |
| gitleaks | constant `high`, by **policy** | No severity vocabulary exists anywhere in its SARIF |
| *any* | fallback → `unknown` | **`unknown` fails the build.** Never silently coerced |

`tool.driver.rules` is indexed for lookups only, never counted: gitleaks emits
all 222 of its rules regardless of which fired.

## Populations, not a shared denominator

`unit` is deliberately tool-specific. bandit walks the filesystem; semgrep
scans git-tracked paths minus `.semgrepignore`. Reporting both as "files"
implies a comparison that does not hold — someone will eventually diff 21
against 15 and conclude a scanner is broken.

Each coverage record carries `{examined, denominator, denominator_source}`, and
`examined` and `denominator` are always **two independent measurements**. A row
where both come from the same probe proves nothing.

Keeping the populations distinct is what makes the real detections possible:

```
[FAIL] semgrep: examined its full python_files_git_tracked population
       examined 15 of 21 (71%); 6 never looked at.
       12 paths skipped: semgrepignore_patterns_match=12
```

semgrep cleared its floor and still ignored every file under `tests/`. A floor
check alone passes that; a floor check plus a denominator does not.

## Exit codes

The orchestrator alone decides. Every scanner is forced to exit 0 — no
`--error`, no `--exit-code 1` — because semgrep and trivy both return 0 with
findings present, so trusting a scanner's exit code fails open.

| Code | Meaning |
|---|---|
| 0 | every leg examined its population and cleared its floor |
| 2 | a coverage floor failed, or a leg examined less than its population |
| 3 | a finding had unresolvable severity (upstream format drift) |

## Layout

```
normalizer/
  model.py             Finding, Coverage, Severity, SeveritySource
  runner.py            executes legs, collects INDEPENDENT coverage probes
  attest.py            coverage attestation + cross-checks
  normalize.py         merge, dedupe, sort (no policy)
  adapters/
    base.py            Adapter protocol, ScanRun, redaction boundary
    bandit.py  gitleaks.py  semgrep.py  trivy.py
tests/
  fixtures/            real baseline output; synthetic ones labelled inline
  test_adapters.py  test_attest.py
```

Run tests: `python3 -m pytest tests/ -q`

Run end-to-end: `python3 -m normalizer /path/to/repo --out out/`

See [AI-USE.md](AI-USE.md) for disclosure of AI assistance.
