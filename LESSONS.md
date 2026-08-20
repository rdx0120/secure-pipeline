# Lessons

Eight instances of one failure: **a check that runs cleanly and verifies
nothing.** Seven are from building this pipeline; the eighth is from writing
it up. None announced itself. Each was found by asking a tool to prove what
it examined rather than reading its exit code.

They are ordered by how self-implicating they are. The last three are about my
own rule, my own fixture, and my own tooling — and they are the ones worth
reading. The final one was found in the tooling of the session that wrote up
the other seven, which is the best evidence available that this is a live pattern
and not hindsight.

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

## 6. A realistic fixture tripped the control the project exists to uphold

**Symptom.** `git push` rejected. GitHub Push Protection flagged a Slack bot
token in `tests/fixtures/gitleaks.sarif`.

**Reality.** The fixture was synthetic — generated for this repository, never a
live credential — but it was shaped like a real `xoxb-` token, because the whole
point of a gitleaks fixture is to look like the thing gitleaks detects. A
detector fixture and a detected secret are the same shape by construction.

**The offered remedy was the problem.** Push Protection offers a bypass, and
taking it would have worked immediately. It would also have written a permanent,
documented override of a secret-scanning control into the history of a repository
whose entire argument is that such controls must not be waved through. The audit
trail would have read: *the author of the secret-scanning pipeline bypassed
secret scanning.*

**Fix.** The bypass was **not** taken. The unpushed history was rewritten to use
an obviously non-token-shaped placeholder, `xoxb-` was confirmed absent across
all history, and the branch was then pushed clean. Rewriting unpushed history is
cheap; a bypass in the log is forever.

**The generalisable rule.** A fixture for a secret-scanning tool must be
*obviously* non-token-shaped — recognisable as a placeholder by a human and by
the platform — because a realistic one will trip the very control the project
exists to uphold, and the path of least resistance out of that is an override
that contradicts the project.

---

## 7. The signed release SBOM catalogued zero Python packages

The one that should not have happened, in the repository built to catch it.

**Symptom.** `release.yml` generates a CycloneDX and an SPDX SBOM, signs both
keyless, verifies both against a pinned identity, and uploads them. Green. Six
artifacts, all signed, all verifying.

**Reality.** The SBOMs listed **zero Python packages.** What they contained was
`actions/checkout` (three times), `actions/setup-python`,
`actions/upload-artifact`, `anchore/sbom-action/download-syft`,
`aws-actions/configure-aws-credentials`, `sigstore/cosign-installer`, a
Terraform provider, and four absolute runner paths. An SBOM for a Python project
describing its own CI actions and nothing it depends on.

**Cause.** `secure-pipeline` had no `requirements.txt`, no `pyproject.toml`, and
no lockfile. Syft had nothing to resolve, so it cataloged what it could find —
GitHub Actions references in workflow YAML — and reported success.

**This is the Session 1 baseline finding, recurring.** The very first run found
trivy and syft returning exit 0 over an unpinned `requirements.txt`: *0 packages,
0 components, nothing at all.* That finding is why the coverage attestation
exists. The fix — commit a lockfile so dependencies resolve — was applied to
`kev-epss-prioritizer`, the consumer repo, and **never to this one.** The
orchestrator that gates other projects on resolvable dependencies did not gate
itself.

Nothing caught it, because nothing was watching. The attestation runs against
repositories this pipeline *scans*; the release workflow is a separate path with
no coverage floor of its own. A signed, verified artifact described nothing, and
every signature over it was valid.

**Fix.** A `pyproject.toml` and `uv.lock` (8 packages resolved), and Syft pointed
at the extracted archive rather than the build directory, with the SBOM's subject
pinned to the artifact's sha256. Measured: **0 Python packages before, 8 after.**

**What is still not fixed, and is documented rather than claimed.** Four
components are named by absolute path. Pointing Syft at the archive does *not*
remove them — it replaces the workspace path with Syft's own temp extraction
path, and `--base-path` does not relativize them either. It is a Syft behaviour
present in every scan mode tested. Extracting to a fixed path at least makes them
deterministic instead of a fresh random directory per run.

**The generalisable rule.** A supply-chain artifact can be signed, verified, and
empty. Signature validity says nothing about content adequacy — they are
independent properties, and the pipeline checked only the first. Before trusting
an SBOM, count what is in it.

---

## 8. A signing configuration that named a key that did not exist

Found in the container tooling of the session writing up the seven instances
above. That is not a flourish: it is the point. The pattern is not something I
found once and learned; it is something that keeps happening, including to the
person writing the list.

**Symptom.** `git config commit.gpgsign` returns `true`. `user.signingkey`
points at a file. `git commit` exits 0. Everything reads as a working signing
setup.

**Reality.** The file that `user.signingkey` names is **0 bytes**:

```
$ git config --get user.signingkey
/home/claude/.ssh/commit_signing_key.pub
$ stat -c %s /home/claude/.ssh/commit_signing_key.pub
0
```

There is no key there, no ssh-agent, and no other key on disk. The commit
nevertheless carries a valid `gpgsig` header — because signing is actually
performed by a separate helper named in `gpg.ssh.program`, which ignores the
configured path entirely.

**So the configured value describes nothing.** If you audited this repository's
configuration to answer *"which key signs our commits?"*, the field whose entire
job is to answer that question would give you a wrong answer, and every commit
would still be signed and verified. The config is not evidence of the control;
it is adjacent to it.

**And the verification side reports the same thing for both failure modes:**

```
$ git log --format='%h %G?' -1
ab8a393 N
error: gpg.ssh.allowedSignersFile needs to be configured and exist
```

`%G?` returns `N` — the same value it returns for a genuinely unsigned commit —
even though this commit *is* signed and shows as Verified on GitHub. Locally,
"this commit has no signature" and "I am not configured to check signatures" are
indistinguishable. A gate scripted on `%G?` would draw a confident conclusion
from a check that never ran.

**The generalisable rule.** A signing setup that reports success proves that
*something* signed, not that the thing you configured did. Verify the artifact
(`git cat-file commit HEAD | grep gpgsig`, or the platform's Verified badge), not
the configuration — and never read a verification command's output without first
establishing that the verification could run at all.

**Postscript — how this instance was nearly recorded wrong.** The first version
of this entry claimed that commits were silently coming out *unsigned*. That
claim was written into the project's handoff brief from an unverified report and
restated as established fact — in a document whose subject is not restating
unverified things as fact. It survived until someone ran
`git cat-file commit HEAD | grep gpgsig`, found a valid signature, and traced the
real cause to `gpg.ssh.program` and an unset `allowedSignersFile`.

The other seven instances were found in tooling. This one was found in the
write-up *of* those seven, on the second pass, by the same discipline the
write-up describes — and the near-miss is the more useful half of it. **The
correction is the instance.** A pattern you can only recognise in hindsight is a
story; one that catches you while you are actively documenting it is a pattern.

---

## The through-line

Every instance has the same shape: a mechanism that was present, ran without
error, and verified less than it appeared to. In most of them the reported output
was indistinguishable from success. In one, the reported output was a passing
test suite. In one, the reported output was a validly signed artifact describing
nothing. In the last, the reported output was a configuration file that named
something which did not exist.

The generalisation is not "scanners are unreliable." It is that **absence of
findings carries no information unless you separately establish what was
examined** — and that the thing establishing it must be measured independently,
or it will agree with whatever it is auditing.

That is why this pipeline emits a coverage attestation alongside its findings,
why `examined` and `denominator` are never two readings of the same source, and
why the gate can exit non-zero on zero findings.
