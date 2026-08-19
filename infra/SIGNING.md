# Signing release artifacts and SBOMs

## Status: mechanism verified locally, keyless NOT performed

Keyless signing was not possible in this environment, for two independent
reasons — either alone would block it:

1. **No OIDC identity exists yet.** Keyless signing uses the workload identity
   from the role in `infra/main.tf`, and that module has not been applied (no
   AWS credentials here). There is nothing to present to Fulcio.
2. **Sigstore is unreachable.** `fulcio.sigstore.dev`, `rekor.sigstore.dev`,
   `oauth2.sigstore.dev` and `tuf-repo-cdn.sigstore.dev` are all refused by
   this environment's network policy.

Keyless signing also writes a **permanent, public entry to the Rekor
transparency log**, bound to a real identity. That is not something to do
speculatively on someone's behalf — it cannot be retracted.

## What was verified

The signing and tamper-detection mechanism, with a local key pair and the
transparency log disabled:

```
syft . -o cyclonedx-json=sbom.cdx.json
cosign sign-blob --key cosign.key --tlog-upload=false \
  --output-signature sbom.sig sbom.cdx.json

cosign verify-blob --key cosign.pub --signature sbom.sig \
  --insecure-ignore-tlog sbom.cdx.json
# -> Verified OK

# after editing one field of the SBOM:
# -> Error: invalid signature when validating ASN.1 encoded signature
```

`--tlog-upload=false` and `--insecure-ignore-tlog` are **demo-only flags**. They
remove the transparency log, which is the property that makes Sigstore worth
using: without it a signature proves only that someone holding the key signed
something, not that the signing event is publicly auditable. Do not carry these
flags into CI.

## The real path, once the OIDC role is applied

```yaml
permissions:
  id-token: write        # required for keyless; the whole mechanism hinges on it
  contents: read

steps:
  - uses: sigstore/cosign-installer@v3
  - run: syft . -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
  - run: |
      cosign sign-blob --yes \
        --output-signature sbom.cdx.json.sig \
        --output-certificate sbom.cdx.json.pem \
        sbom.cdx.json
```

Verification pins the identity, which is the point — an unpinned
`verify-blob` accepts a signature from *anyone* Fulcio will issue a
certificate to:

```
cosign verify-blob \
  --certificate-identity "https://github.com/rdx0120/secure-pipeline/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature sbom.cdx.json.sig --certificate sbom.cdx.json.pem \
  sbom.cdx.json
```

Note that `--certificate-identity` carries the same failure mode as the OIDC
`sub` condition in `main.tf`: a loose or omitted identity makes verification
succeed against signatures it should reject. A verification step that always
passes is the same class of problem this repo is built around.
