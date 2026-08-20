# Signing release artifacts and SBOMs

Release artifacts are signed **keyless** with Cosign, using the GitHub Actions
workload identity — no long-lived signing key exists anywhere in this project.
`.github/workflows/release.yml` produces and signs three files:

| Artifact | Signature bundle |
|---|---|
| `secure-pipeline-source.tar.gz` (via `git archive HEAD`) | `secure-pipeline-source.sigstore.json` |
| `sbom.cdx.json` (CycloneDX, via Syft) | `sbom.cdx.sigstore.json` |
| `sbom.spdx.json` (SPDX, via Syft) | `sbom.spdx.sigstore.json` |

The workflow requests `id-token: write` — that permission is the entire
mechanism. Without it there is no OIDC token to present to Fulcio and nothing to
bind a certificate to. It signs each file, then **verifies each one in the same
run** before uploading, so a signing step that silently produced an unverifiable
signature fails the job rather than shipping.

## The identity pin is the control

Verification passes two flags, and only one of them is doing real work:

```
--certificate-identity   "https://github.com/rdx0120/secure-pipeline/.github/workflows/release.yml@refs/heads/main"
--certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

`--certificate-oidc-issuer` alone asserts only *"a GitHub Actions run signed
this."* Every public repository on GitHub satisfies that. Fulcio will issue a
certificate to anyone who asks with a valid OIDC token, so a verification pinned
only to the issuer **accepts a signature from any workflow in any repository on
the platform** — including a fork of this one, and including a repository created
this morning by someone else.

`--certificate-identity` is what narrows it to this workflow file, on this
branch, in this repository. Note the pin is to `release.yml@refs/heads/main`
specifically — not to the repository, and not to any workflow in it. A signature
produced by a different workflow in this same repo, or by `release.yml` on a
different branch, does not verify.

Omitting it does not error. It does not warn. Verification simply succeeds
against signatures it should have rejected — **a verification step that always
passes**, which is the same shape as `%G?` returning `N` for both "unsigned" and
"could not check" (see [LESSONS.md](../LESSONS.md) instance 8), and the same
shape as the OIDC `sub` condition in `main.tf` written as `repo:org/*`. A control
that cannot fail is not a control.

## How to verify a release

Download the artifact and its `.sigstore.json` bundle from the workflow run, then:

```sh
IDENTITY="https://github.com/rdx0120/secure-pipeline/.github/workflows/release.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"

cosign verify-blob secure-pipeline-source.tar.gz \
  --bundle secure-pipeline-source.sigstore.json \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

The same two lines verify either SBOM — substitute `sbom.cdx.json` /
`sbom.cdx.sigstore.json` or `sbom.spdx.json` / `sbom.spdx.sigstore.json`.

### Prove the check can fail before believing it passed

A verify command that returns `Verified OK` tells you nothing until you have seen
it reject something. Run it again with a deliberately wrong identity — this
**must** fail:

```sh
cosign verify-blob secure-pipeline-source.tar.gz \
  --bundle secure-pipeline-source.sigstore.json \
  --certificate-identity "https://github.com/rdx0120/secure-pipeline/.github/workflows/nope.yml@refs/heads/main" \
  --certificate-oidc-issuer "$ISSUER"
# expected: none of the expected identities matched what was in the certificate
```

If that command *succeeds*, your verification is not checking identity and every
`Verified OK` you have seen from it is meaningless.

Verification contacts Sigstore's transparency log and TUF root
(`rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev`), so it needs network access.
It cannot be run air-gapped.

## Where the artifacts live, and why that matters

The signed files are currently uploaded with `actions/upload-artifact`, which
means they are **workflow-run artifacts, not release assets**. Two consequences a
reader should know before trying the commands above:

- They expire (90 days by default) and disappear with the run.
- Downloading them requires being signed in to GitHub; they are not
  anonymously fetchable.

So a stranger reviewing this repository cannot presently run the verification
themselves. Attaching the six files to a GitHub Release is what would make these
signatures independently checkable by someone who does not have access to the
Actions tab — and until that happens, the signing story is verifiable by the
maintainer and taken on trust by everyone else. **Signed artifacts nobody outside
can verify are a claim about the pipeline, not a property of it.**

## What is deliberately absent

No `--tlog-upload=false`, and no `--insecure-ignore-tlog`. Both disable the
transparency log, which is the property that makes Sigstore worth using: without
it a signature proves only that *someone* signed *something*, not that the
signing event is publicly auditable. They belong in a local demo and nowhere near
CI.

There is also no signing key to protect, rotate, or leak. That is the point of
keyless: the certificate is short-lived, bound to the workflow identity, and the
evidence lives in a public log rather than in a secret.
