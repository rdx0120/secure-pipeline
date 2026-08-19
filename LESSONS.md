# Lessons

Five instances of one failure: **a check that runs cleanly and verifies
nothing.** All five are from building this pipeline. None announced itself.
Each was found by asking a tool to prove what it examined rather than reading
its exit code.

They are ordered by how self-implicating they are. The last two are about my
own code and my own rule, and they are the ones worth reading.

---

## 1. Semgrep silently skipped every test file

**Symptom.** `Scan completed successfully. Findings: 0.` Exit 0.

**Reality.** 15 of 21 tracked Python files. Every file under `tests/` was
skipped, and the count of skipped paths appeared *only* in the human-readable
summary — `paths.skipped` is absent from the JSON output unless `--verbose` is
passed. A machine consumer had no way to see it.

**Cause.** Semgrep applies a built-in `.semgrepignore` template, which excludes
`tests/`, whenever a project has no `.semgrepignore` of its own. Neither
`--semgrepignore-v2` nor the internal `--x-semgrepignore-filename` suppresses
it; writing a real file is the only stable override.

**Why it matters.** The exclusion was nobody's decision. Ratifying it because
it was already there would have been retrofitting intent onto an accident — the
exact failure this project exists to catch. And it is not a harmless default
here: this repository's test tree holds synthetic credential material and
scanner fixtures, so the one directory containing planted secrets was the one
directory never examined.

**Fix.** The orchestrator installs an explicit scope declaration for the
duration of a scan, and leaves alone any project that ships its own — because
that project made a real decision. Noise is suppressed by rule ID, never by
path: exclude the behaviour, not the software.

---

## 2. Finding fingerprints depended on the checkout directory

**Symptom.** None locally. Everything worked.

**Reality.** Semgrep prefixes rule IDs with the resolved config path:
`root.proj.secure-pipeline.rules.untrusted-xml-parse`. Since a finding's
identity is `sha256(tool | rule_id | path | snippet_sha256)`, the same finding
would carry a *different* id on a CI runner than on a laptop.

**Consequence.** Every entry in `exceptions.yaml` matches by id. On the first CI
run, all of them would match nothing, the staleness check would fire, and the
build would fail with `STALE -- matches no current finding` for four
suppressions that were perfectly valid. The error message would point at the
exceptions file; the cause would be the working directory.

**Why it matters.** This is the one that would have cost the most to debug six
months later, and it was findable only by running on a real path with real
config. It never appears in a unit test, because a unit test loads a fixture
from a fixed relative path.

**Fix.** Strip the locally-derived namespace; leave registry namespaces
(`python.lang.security.*`) alone, since those are meaningful.

---

## 3. Taint mode looked correct and could not reach the sink

**Symptom.** A taint rule with source `struct.unpack(...)` and sink
`$BUF[:$SINK]`. Valid YAML, sensible logic, and its allocation-sink fixtures
passed.

**Reality.** Semgrep OSS taint does not propagate into slice-bound positions. A
minimal source/sink pair matches **nothing** on `buf[:length]`, while the
identical sink pattern matches fine in search mode.

**Consequence.** The rule would have shipped missing slices entirely — the most
important sink it has, for a rule about arena parsers — while appearing healthy
because the `bytearray()` cases still fired. Partial function is worse than
total failure: it produces findings, so it looks alive.

**Also found.** `by-side-effect` sanitizers are a Semgrep Pro feature. Under the
OSS engine they do not error — every result silently degrades to `requires
login`.

**Fix.** Rewritten in search mode with statement-sequence patterns, which also
express the guard more precisely: a check *between* the decode and the use
clears the finding, where a function-level exclusion would wrongly clear a use
that precedes its own check.

---

## 4. A shallow clone made secret scanning a false pass

**Symptom.**

```
gitleaks  commits  1  1  1  0  PASS
```

Examined equals total. Floor cleared. Green.

**Reality.** The checkout was `--depth 1`. `git rev-list --count HEAD` returns
`1` on a shallow clone, so the "population" being compared against was
*measuring the truncation*, not the history. gitleaks scanned one commit of an
unknown-length history and the attestation agreed with it.

**Why it generalises.** `actions/checkout` defaults to `fetch-depth: 1`. This is
not an exotic misconfiguration — it is what happens by default in GitHub Actions
unless someone knows to set `fetch-depth: 0`. A secret committed and then
removed three commits ago is invisible, and every layer of the stack reports
success.

**Why the attestation caught it.** Only because `examined` and `denominator` are
required to be two *independent* measurements. An earlier design read the
population back from the same probe that produced the count, which would have
produced `1 of 1 — PASS` and told me nothing. A row where both numbers come
from the same source cannot disagree with itself, and a check that cannot fail
is not a check.

**Fix.** Shallow checkouts report `FAIL_UNVERIFIABLE` — distinct from
`FAIL_NO_COVERAGE`, because "the scanner examined nothing" and "I cannot prove
what the scanner examined" have different fixes.

---

## 5. My own rule passed its own tests and was blind to its target

The most self-implicating, and the most credible for it.

**Symptom.** `unbounded-binary-read` — written specifically for YARAdec's arena
parser, which reads length and offset fields out of attacker-controlled `.yarc`
files — shipped with five annotated fixtures and passed all five. Run against
that parser, it fired **zero times**.

**What I did instead of accepting it.** Silence is not success applies to your
own tooling too. I wrote a probe containing three deliberately-unsafe functions
in the idioms that codebase actually uses:

```
probe matches: 1 / 3
```

**Reality.** It matched only `length = struct.unpack(...)[0]` followed by a
direct use — the exact shape of its own fixture. It could not see:

- **Tuple targets:** `b_off, b_size = struct.unpack_from("<QI", data, off)`
- **Derived bounds:** `end = b_off + b_size`, then `data[b_off:end]`

Both are the dominant idioms in real binary parsers.

**Why the tests could not catch this.** The fixture and the rule were written by
the same person, in the same hour, encoding the same assumption about what the
code would look like. A passing test suite measured agreement between two
expressions of one misconception. Test coverage is not idiom coverage, and a
rule is only as good as the imagination of whoever wrote its fixtures.

**Then the guard broke in the opposite direction.** With the rule finally able
to see the code, it fired on YARAdec's *correct* logic, because the real bounds
check is on a derived value inside a boolean op:

```python
end = b_off + b_size
if b_size and end > len(data):
    raise ArenaError(f"buffer {i} runs past end of file ...")
```

The guard matched only a bare `if $LEN > $LIMIT`. Two structural blind spots, in
opposite directions, in one rule.

**The true negative, stated outright.** YARAdec's parser bounds-checks every
length field before use: it validates the buffer table against `len(data)`, and
checks `pos + 8 > len(data)` before each relocation read. I established that by
reading the parser, not by trusting the rule's silence. No fixes were required
and no exceptions were written.

**The claim this supports.** The custom rules in this repository did not catch a
planted bug in someone else's code. They caught two real bugs *in themselves* —
and only because they were run against real code instead of their own fixtures.

---

## The through-line

Every instance has the same shape: a mechanism that was present, ran without
error, and verified less than it appeared to. In four of the five, the reported
output was indistinguishable from success. In the fifth, the reported output was
a passing test suite.

The generalisation is not "scanners are unreliable." It is that **absence of
findings carries no information unless you separately establish what was
examined** — and that the thing establishing it must be measured independently,
or it will agree with whatever it is auditing.

That is why this pipeline emits a coverage attestation alongside its findings,
why `examined` and `denominator` are never two readings of the same source, and
why the gate can exit non-zero on zero findings.
