# Container build and image scan

Task 4 (Person B). Produced by three jobs of `.github/workflows/devsecops.yml`
on every pull request and push to `main`: `package` (stage 5, build),
`image_scan` (stage 6, scan and gate) and `publish` (stage 7, push). The
package stage passes the image to the next two as a one-day artifact, so the
image that is scanned is exactly the image that is published.

## What the stages do

1. **Build** the Juice Shop image from the repository Dockerfile, tagged with
   the commit SHA (`ghcr.io/bichiouyahya/devsecops-project/juice-shop:<sha>`).
   A SHA tag is never reused, so every image can be traced back to one commit.
2. **Scan** it with Trivy 0.76.0 for HIGH and CRITICAL vulnerabilities. The
   image is exported with `docker save` and scanned offline from the tar file,
   so the scanner never gets access to the Docker socket (mounting the socket
   would give a third-party container root access to the runner).
3. **Push** it to GitHub Container Registry with the job's own short-lived
   `GITHUB_TOKEN` (`packages: write` for this job only, no stored password).
4. **Export the digest** (`sha256:...`), shown in the run summary. The digest
   identifies the exact image content; the signing step (Task 5) signs the
   digest, not the tag, because a tag can be moved to another image.

The order build, scan, push is deliberate: once the gate is switched on, a
vulnerable image is stopped before it reaches the registry.

Reports: `trivy-image.sarif` (Security tab, category `trivy-image`) and
`trivy-image.json`, kept as the `image-scan-reports` artifact.

## Results (first run, PR for Task 4)

| Layer | Target | HIGH | CRITICAL | Total |
|---|---|---|---|---|
| Operating system | `gcr.io/distroless/nodejs24-debian13` (Debian 13.7) | 1 | 0 | 1 |
| Application | Node.js packages inside the image (`node_modules`) | 27 | 9 | 36 |
| **Total** | | **28** | **9** | **37** |

### Operating system layer: 1 finding

- `zlib1g` 1.3.1, CVE-2026-76844, HIGH, status *affected* (no fixed Debian
  package yet). Trivy's title for this CVE refers to `webpack-dev-middleware`,
  which does not match a zlib vulnerability: this needs to be checked against
  the Debian security tracker before acting on it. It is the kind of finding
  that should be triaged, not blindly fixed, and it shows why the gate uses
  `--ignore-unfixed`: blocking on a CVE with no available fix would stop every
  build without giving the team anything to do.

The OS layer is almost clean because Juice Shop already uses a **distroless**
runtime image: it contains Node.js and its system libraries, but no shell, no
package manager and no build tools. A full `node:24` base image typically
carries hundreds of OS packages and dozens of CVEs. The multi-stage Dockerfile
keeps npm, TypeScript and the build tooling in the `installer` stage, which is
not shipped, and the container runs as a non-root user (`USER 65532`).

### Application layer: 36 findings

The Node.js packages inside the image give exactly the same result as the
source SCA scan of Task 2 (36 HIGH/CRITICAL in the backend dependencies, for
example `jsonwebtoken` 0.1.0, `express-jwt` 0.1.3, `crypto-js` 3.3.0,
`lodash` 2.4.2, `marsdb`). This confirms that the dependencies resolved by the
`sca` and `sbom` jobs are the ones actually shipped in the image. The frontend
finding from Task 2 (`ws`) is absent: the image only contains the compiled
Angular bundle, not the frontend's `node_modules`.

## What the image scan adds to the source scan

- It sees the **OS packages** of the base image, which no source scanner can
  see.
- It scans **what is shipped**, not what is declared: dev dependencies and
  build tools that stay in the builder stage do not appear.
- It runs on the exact artifact that is pushed and later signed and deployed.
