# Remediation: two supply chain fixes

Task 7 (Person B). Each fix went through the full loop: **detected** by the
pipeline, **fixed** in its own pull request, **verified** by the pipeline,
which closed the alerts automatically after the merge.

| | Fix 1: vulnerable dependency | Fix 2: Dockerfile hardening |
|---|---|---|
| Pull request | #23 `fix/crypto-js-override` | #24 `fix/pin-base-images` |
| Detected by | Trivy (`sca` and `image` jobs) | Hadolint and Checkov (`iac_scan` job) |
| Finding | `crypto-js` 3.3.0, 2 CRITICAL CVEs | Untagged base image, no health check |
| Files changed | `package.json` (+3 lines) | `Dockerfile` (2 lines changed, 3 added) |

## Fix 1: CRITICAL vulnerabilities in `crypto-js`

**Finding.** Trivy reported `crypto-js` 3.3.0 as CRITICAL:
CVE-2023-46233 (PBKDF2 is 1,000 times weaker than specified in 1993 and
1.3 million times weaker than current standards) and CVE-2026-71851
(insufficient entropy when generating secrets). It was found **twice**: in the
resolved dependency tree (`sca` job, alert #217) and inside the built image
(`image` job, alert #434), which proves the vulnerable code was actually
shipped (`docs/screenshots/22-fix1-before.png`).

**Cause.** `crypto-js` is not a direct dependency of Juice Shop. It comes in
through `pdfkit` ^0.11.0, which generates the order confirmation PDFs and
accepts any `crypto-js` ^3.1.9. Bumping a direct dependency was therefore not
possible, and waiting for a new `pdfkit` release was not an option.

**Fix.** An npm `overrides` entry in `package.json` forces one version of the
transitive dependency everywhere in the tree:

```json
"overrides": {
  "crypto-js": "4.2.0"
}
```

Before merging, we checked that `pdfkit` 0.11 still generates both plain and
encrypted PDFs with `crypto-js` 4.2.0 (encryption is the code path that
actually uses `crypto-js`).

**Verification.**
- `sca` job: backend HIGH/CRITICAL findings went from **36 to 34**, CRITICAL
  from **9 to 7** (`docs/screenshots/23-fix1-after.png`).
- After the merge, the pipeline on `main` closed **both** alerts, #217 (source)
  and #434 (image), as *fixed* (`docs/screenshots/23b-fix1-closed.png`).

## Fix 2: base images pinned by digest, health check added

**Findings.**
- Hadolint **DL3006** (warning, alert #80) and Checkov **CKV_DOCKER_7**: the
  runtime image `gcr.io/distroless/nodejs24-debian13` had no tag at all, so
  every build silently pulled `latest`. The builder image `node:24` was a
  moving major-version tag (`docs/screenshots/09-hadolint-findings.png`).
- Checkov **CKV_DOCKER_2**: no `HEALTHCHECK` instruction. This one surfaced
  during the review: once the pull request touched the Dockerfile, GitHub
  code scanning counted the existing *Error*-level alert as "in code changed
  by this pull request" and failed the Checkov check. We fixed it rather than
  dismissing it.

**Risk.** With moving tags the build is not reproducible: two builds of the
same commit can use different base images, and a changed or compromised
upstream image enters our product without any change in our repository
(OWASP Top 10:2025 A03, Software Supply Chain Failures).

**Fix.**

```dockerfile
FROM node:24@sha256:8fa96264f302f58bbb13aa7339c541547b56975766ce956c875da149452a3e40 AS installer
...
FROM gcr.io/distroless/nodejs24-debian13@sha256:b770c59f44ed459329508a73794e6d284f6c10143f83c8012a8f775cd514eca2
...
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "require('http').get('http://127.0.0.1:3000/rest/admin/application-version', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]
```

The distroless image has no shell and no `curl`, so the health check uses the
image's own Node.js binary to call a lightweight endpoint.

**Verification.**
- Hadolint: DL3006 gone, only the 11 informational DL3059 notes remain.
- Checkov: **0 failed** Dockerfile checks, down from 2.
- The `image`, `sign` and `dast` jobs stayed green: the pinned image still
  builds, scans, signs and runs.
- After the merge, alert #80 was closed as *fixed* on `main`
  (`docs/screenshots/24-fix2-after.png`).

## Follow-up

Pinning by digest means updates no longer happen by accident; they have to
happen on purpose. The next step is a Dependabot (or Renovate) configuration
for the `docker` and `github-actions` ecosystems, so that new digests and
action versions arrive as reviewed pull requests that run through this
pipeline.
