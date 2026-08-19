# AI use in this project

AI (Claude, via Claude Code) was used for scaffolding and iteration speed:
generating adapter boilerplate, writing test cases from an agreed spec, and
running the scanner baseline that informed the design.

The claim being made by this repository is **design, validation, and judgment** —
not authorship of every line:

- The two-repo split (orchestrator separate from the scanned project) is a
  design decision made here, not a generated default.
- The coverage attestation exists because the Session 1 baseline was read
  carefully enough to notice that four scanners reported success while
  examining little or nothing. That observation drove the architecture.
- The decision to verify that coverage evidence *existed in the tool output*
  before specifying floors against it changed the adapter interface.
- Per-tool severity extraction, and the refusal to write a generic
  `get_severity()`, follows from reading real SARIF and finding that bandit
  omits `level` exactly where it matters.

Commits are authored by the repository owner, who is responsible for the
contents. AI assistance is disclosed here as tooling, in the same way one would
not credit an editor as co-author.
