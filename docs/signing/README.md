# Image signing with Cosign

Task 5 (Person B). Produced by the `sign` job in
`.github/workflows/build-security.yml`, which runs after the `image` job on
every pull request and push to `main`.

## Why sign the image

The image scan (Task 4) tells us the image is acceptable at build time. Signing
proves, at deploy time, that the image we are about to run is **exactly the one
this pipeline built**: not a copy pushed by someone else to the registry, and
not an image modified after the build. It protects against a compromised
registry account, a typo-squatted image name, or a tag silently moved to
another image.

## How it works

| Item | Where it lives |
|---|---|
| Private key `cosign.key` (encrypted with a password) | Repository secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`. Never committed: `cosign.key` is in `.gitignore`, and the pre-commit hook and Gitleaks would block it. |
| Public key `cosign.pub` | Committed at the repository root, so anyone can verify our images. |
| Signature | Stored in GHCR next to the image, and recorded in the public Sigstore transparency log (Rekor). |

The keys were generated once with `cosign generate-key-pair` (Cosign 3.1.4,
checksum verified) on a developer machine, outside the repository folder.

Pipeline steps:

1. **Install Cosign** 3.1.4 from the official release, checking its SHA-256
   against the published checksum file.
2. **Check that the secrets exist**, with a clear error if they do not.
3. **Sign by digest**: `cosign sign --key env://COSIGN_PRIVATE_KEY <image>@sha256:...`.
   The digest comes from the `image` job. We sign the digest, not the tag,
   because a tag can be moved to another image while a digest is the hash of
   the content. The key is read from an environment variable (`env://`), so it
   is never written to the runner's disk.
4. **Verify**: `cosign verify --key cosign.pub <image>@sha256:...`. This step
   fails the build if the signature is missing or does not match the key.
5. **Negative test**: verifying the upstream `bkimminich/juice-shop` image from
   Docker Hub, which we never signed, must fail with `no signatures found`.
   If it passed, or failed for another reason (network error, rate limit), the
   job fails: a check that cannot fail proves nothing.

## Results

- Signed and verified image: see `docs/screenshots/18-cosign-verify-ok.png`.
- Unsigned upstream image rejected with `Error: no signatures found`: see
  `docs/screenshots/19-cosign-verify-fail.png`.

## Limits and next steps

- **Key management.** A long-lived key pair must be protected and rotated, and
  whoever holds `cosign.key` can sign. The alternative is **keyless signing**
  (Cosign with the workflow's OIDC identity): no key to store, and the
  signature proves which repository and workflow built the image.
- **Enforcement at deploy time.** Today the pipeline verifies its own
  signature. In production, the deployment platform (for example a Kubernetes
  admission controller such as Sigstore policy-controller or Kyverno) would
  refuse to run any image without a valid signature from `cosign.pub`.
