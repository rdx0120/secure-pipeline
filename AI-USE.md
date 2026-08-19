# AI use in this project

AI (Claude, via Claude Code) was used for scaffolding and iteration speed:
generating adapter boilerplate, writing test cases from an agreed spec, drafting
rule YAML, and running the scanner baseline that informed the design.

The claim this repository makes is **design, validation, and judgment** — not
authorship of every line.

## What that means concretely

The decisions below are the substance of the project, and each one was a
judgment call that changed what got built:

- **The two-repo split** — orchestrator separate from the scanned project — and
  the later ruling that exceptions are *federated* to consumer repos while
  policy stays centrally governed. That followed from noticing that
  `kev-epss-prioritizer`'s suppression text ("not attacker-supplied in the
  current deployment") is *false* about YARAdec, where `.yarc` input is
  attacker-controlled by definition. The same rule at an identical-looking sink
  has opposite verdicts in the two codebases.
- **The coverage attestation exists at all** because the Session 1 baseline was
  read closely enough to notice four scanners reporting success while examining
  little or nothing.
- **Checking that coverage evidence existed in the tool output before
  specifying floors against it.** No scanner records what it examined in its
  SARIF; that discovery changed the adapter interface before a line of it was
  written.
- **Requiring `examined` and `denominator` to be independent measurements.**
  This is the decision that caught the shallow-clone false pass. A design that
  read both from the same probe would have reported `1 of 1 — PASS`.
- **Refusing to accept a rule's silence as a true negative.** When
  `unbounded-binary-read` found nothing in YARAdec, the response was to write a
  probe proving the rule *could* fire before believing that it hadn't. That is
  what surfaced its two structural blind spots — and the rule, the fixtures,
  and the blind spot were all AI-drafted from my spec, which is precisely why
  the verification step mattered.

That last point is the honest shape of AI assistance here: it accelerated
producing a rule *and* its tests, and because both came from the same
assumption in the same sitting, they agreed with each other and were both
wrong. Generated tests do not validate generated code. Only real inputs did.

## Attribution

Commits are authored by the repository owner, who is responsible for the
contents and can defend every decision in [LESSONS.md](LESSONS.md) under
questioning. AI assistance is disclosed here as tooling, in the same way one
would not credit an editor as a co-author.
