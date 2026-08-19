# secure-pipeline

**Premise: a check that runs cleanly and verifies nothing is the most dangerous
state a security control can be in.** It is worse than a check that fails,
because a failure gets investigated and a false pass gets trusted.

Every instance below is one I hit in my own work, in a different domain, and
none of them announced themselves — each was found by asking a scanner to prove
what it examined rather than reading its exit code:

| Where | What ran clean | What it actually verified |
|---|---|---|
| Wazuh rule tuning | Custom rules loaded, alerts fired | `if_group` matched a parent that never fired — the rule was dead |
| Vulnerability triage | Scan completed, no errors | 4 hosts of 28 |
| This pipeline, session 1 | trivy exit 0, empty SARIF | 0 packages — the pip parser cannot resolve `>=` |
| This pipeline, session 1 | syft exit 0, valid SBOM | 0 Python components |
| This pipeline, session 1 | scorecard **exit 0** | nothing; it wrote a 0-byte file |
| This pipeline, session 3 | semgrep "scan completed successfully" | 15 of 21 files; it silently skipped `tests/` |
| This pipeline, session 4 | A taint rule passing its own fixtures | Semgrep OSS taint does not reach slice bounds; the rule missed its most important sink |

Four scanners in session 1 reported success while examining little or nothing.
So this orchestrator emits **two outputs, not one**:

1. **Findings** — normalized, deduplicated, corroborated, policy-gated.
2. **A coverage attestation** — what each leg actually examined, asserted
   against a floor and against its own population.

A leg that examined zero units of its input type fails the build as loudly as a
critical finding. **The gate can fail on zero findings**, and that asymmetry is
the whole design in one exit code.

## The evidence

The Session 1 baseline ran six scanners against a small Python repo:

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

## Corroboration: group, never collapse

Cross-tool agreement is the most valuable thing two scanners can tell you, so
findings are never merged away to shorten a list. Both records survive with
distinct `id`s and carry a shared `corroboration` block, grouped on
`(weak_class, path, line)`.

`weak_class` is a coarse taxonomy declared in `policy.yaml`. It is deliberately
**not CWE**: the tools disagree on CWE assignment, and mapping through it would
assert equivalences none of them make.

The gate uses agreement two ways:

- **Confidence, not severity.** A corroborated finding is routed differently —
  it blocks where a lone finding of the same severity would only warn. Its
  severity is left untouched, because inflating it would corrupt the tools' own
  judgment.
- **Disagreement as its own signal.** When one tool fires and another that
  *provably examined the same file* stays silent, that is a coverage gap in the
  quiet tool. The attestation is what makes this a real negative instead of an
  unknown. A tool is only counted as silent if it actually has a rule in that
  weakness class — semgrep having no equivalent of bandit's `B101` is an
  absence of scope, not a disagreement.

Presentation groups these rows; the JSON keeps both records.

## Exceptions

Every entry in `exceptions.yaml` requires `id`, `reason`, `approver`, and an
ISO `expires`. Four things fail the build:

| Condition | Why it fails |
|---|---|
| Missing required field | Not a decision anyone can audit |
| Expired | No indefinite suppressions |
| Beyond `max_age_days` | An exception is a deadline, not a deletion |
| **Stale** — matches no current finding | Silently re-authorizes the finding the day it returns |

The staleness check is the one that makes this different from a `# noqa`
sprinkle. Suppressions that outlive their findings accumulate, and each one is
a pre-approval for a bug nobody is looking at any more.

## Exit codes

The orchestrator alone decides. Every scanner is forced to exit 0 — no
`--error`, no `--exit-code 1` — because semgrep and trivy both return 0 with
findings present, so trusting a scanner's exit code fails open.

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | findings blocked, or an exception expired / went stale |
| 2 | coverage failure — **we cannot see** |

`1` and `2` are deliberately not collapsed: "we found problems" and "we can't
see" are different pages. When both hold, coverage wins — if we could not see,
the finding list is not trustworthy enough to reason about.

## Scanning scope: we scan tests

Semgrep's shipped default excludes `tests/` whenever a project has no
`.semgrepignore` of its own. That exclusion is not a decision anyone made, and
**undeclared scope reduction is the exact failure this pipeline exists to
catch** — ratifying one because it was already there would be retrofitting
intent onto an accident.

So the orchestrator installs its own scope declaration for the duration of a
scan (`rules/semgrepignore.template`), and a project that ships its own
`.semgrepignore` is left alone, because that project made a real decision.

**We scan tests because our test trees are security-relevant, not boilerplate.**
`secure-pipeline`'s own fixtures hold synthetic credential material and SARIF
parser inputs; under semgrep's default, the one directory holding planted
credentials is the one directory never examined. The same default would apply
to YARAdec's fixtures, which include attacker-controlled binary inputs and the
parser paths that consume them.

**Noise is suppressed by rule ID, never by path.** Exclude the behaviour, not
the software. A rule suppressed by id stays suppressed for a stated reason that
survives review; a suppressed directory silently hides everything that ever
lands in it afterwards.

Keeping tests in scope also preserves symmetry with bandit, which walks the
filesystem. If semgrep scanned 15 files and bandit 21, every future cross-check
between them would carry a permanent 6-file offset that someone would
eventually read as a real signal.

## Rules

Rules in `rules/` are written here, not pulled from the maintained registry.
The Semgrep Registry's maintained rulesets are license-encumbered, so the
design is to author our own and pull only from openly-licensed rulesets. The
registry being unreachable from the build environment is incidental — it is not
the reason.

| Rule | Grounded in |
|---|---|
| `untrusted-xml-parse` | `kev-epss-prioritizer`'s Nessus/OpenVAS parsers. Taint-tracked, so a parse of a scanner export is reported and a parse of a bundled constant is not — the distinction bandit's `B314` cannot make |
| `requests-without-timeout` | The KEV/EPSS enrichment calls. A hung call does not fail a remediation pipeline, it stalls it silently |
| `secret-reaches-sink` | The redaction boundary in `normalizer/adapters` — the tool that finds leaked credentials is itself a credential-handling program |
| `subprocess-shell-injection` | `normalizer/runner.py`, which shells out to six scanners with externally-supplied paths |
| `unbounded-binary-read` | YARAdec's arena parser: length fields read from a file and used as allocation or slice bounds |

Test them with semgrep's own fixture format:

```
semgrep --test --config rules/ rules/tests/
```

## Layout

```
normalizer/
  model.py             Finding, Coverage, Severity, SeveritySource
  runner.py            executes legs, collects INDEPENDENT coverage probes
  attest.py            coverage attestation + cross-checks
  normalize.py         merge, dedupe, sort (no policy)
  gate.py              policy + exceptions -> one verdict
  adapters/
    base.py            Adapter protocol, ScanRun, redaction boundary
    bandit.py  gitleaks.py  semgrep.py  trivy.py
policy.yaml            all thresholds, actions, taxonomy (no logic in Python)
exceptions.yaml        dated, attributed, expiring suppressions
tests/
  fixtures/            real baseline output; synthetic ones labelled inline
  test_adapters.py  test_attest.py
rules/
  *.yaml               custom rules (no registry dependency)
  tests/               semgrep --test fixtures, annotated ruleid:/ok:
  semgrepignore.template   the scope declaration installed during a scan
```

Run tests: `python3 -m pytest tests/ -q`

Run end-to-end: `python3 -m normalizer /path/to/repo --out out/`

See [AI-USE.md](AI-USE.md) for disclosure of AI assistance.
