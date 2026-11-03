# SCA tool comparison: Trivy vs npm audit vs Dependabot

Task 2 (Person B). Target: OWASP Juice Shop backend (`package.json`) and frontend
(`frontend/package.json`).

## Starting point: there is no lockfile

Juice Shop sets `package-lock=false` in `.npmrc`. The dependency tree is resolved
again on every install, so two builds of the same commit can ship different
package versions. This is a supply chain weakness on its own (OWASP Top 10:2025
A03, Software Supply Chain Failures): the build is not reproducible and a newly
published malicious version can enter without any code change.

Trivy and npm audit both need a lockfile to see the full tree. The `sca` job
generates one in CI with `npm install --package-lock-only --ignore-scripts`
(nothing is installed, no install script runs) and keeps it in the
`sca-reports` artifact as evidence of what was scanned.

## Results

| | Trivy fs 0.76.0 | npm audit | Dependabot |
|---|---|---|---|
| **What it reads** | Generated `package-lock.json` (full tree) | Generated `package-lock.json` (full tree) | `package.json` only (no lockfile in the repo) |
| **Where it runs** | CI job `sca` | CI job `sca` | GitHub, continuously |
| **Database** | Trivy DB (NVD, GitHub Advisories, vendor feeds) | GitHub Advisory Database | GitHub Advisory Database |
| **Backend, all severities** | 71 (9 critical, 27 high, 32 medium, 3 low) | 40 production (7 critical, 20 high, 11 moderate, 2 low); 65 including dev deps | 20 (2 critical, 5 high, 13 moderate) |
| **Backend packages with HIGH/CRITICAL** | 15 | 27 | 7 alerts (2 critical, 5 high), all on direct dependencies |
| **Frontend, all severities** | 3 (1 high: `ws`) | 33 including dev/build deps | to fill from the Security tab |
| **Counts by** | Vulnerability (one row per CVE per package) | Package (every package on the path to a vulnerable one is listed) | Advisory per manifest dependency |
| **Fix advice** | Fixed version per CVE | `npm audit fix` command | Opens a pull request that bumps the version |
| **Output used** | SARIF to Security tab, JSON artifact | JSON artifact | Security tab, PRs |
| **Can gate the build** | Yes (`--exit-code 1 --severity CRITICAL`) | Yes (`--audit-level`) | No, alerts only |

Note: the Trivy HIGH/CRITICAL count is confirmed by the CI run of PR #12
(37 alerts in the Security tab: 36 backend + 1 frontend, see
`docs/screenshots/11-trivy-fs-findings.png`), and the frontend npm audit count
by its job log (33: 12 low, 20 moderate, 1 high, see
`docs/screenshots/12-npm-audit.png`). The other Trivy and npm audit
figures were produced with the same commands and Trivy version; cross-check
them against the `sca-reports` artifact of that run. Dependabot figures are
from the Security tab (`docs/screenshots/13-dependabot-alerts.png`); every
Dependabot alert is labelled **Direct**, which confirms it only sees the
dependencies declared in `package.json`.

## What the comparison shows

1. **Direct vs transitive dependencies.** Dependabot finds 20 alerts because,
   without a lockfile, it only knows the direct dependencies declared in
   `package.json`. Trivy and npm audit resolve the full tree; 11 of the 15
   backend packages Trivy flags as HIGH/CRITICAL are transitive. A project
   relying only on Dependabot would miss most of them.
2. **Trivy and npm audit agree on the core findings.** 14 packages are flagged
   HIGH/CRITICAL by both, including the four vulnerable direct dependencies:
   `jsonwebtoken` 0.1.0 (CVE-2015-9235, signature verification bypass),
   `express-jwt` 0.1.3 (CVE-2020-15084, authorization bypass), `marsdb`
   (command injection, no fix available) and `sanitize-html` 1.4.2.
3. **npm audit counts more packages because it counts paths.** The 13 packages
   only npm audit flags (`got`, `proxy-agent`, `pdfkit`, `sqlite3`, ...) are
   mostly parents of a vulnerable package, not vulnerable code themselves.
   Trivy reports the vulnerable package and CVE directly, which is easier to
   triage and to gate on.
4. **Trivy only reports `base64url`** (advisory NSWG-ECO-428), which comes from
   the Node Security Working Group feed that npm audit does not use. Different
   databases give slightly different coverage, which is an argument for
   running more than one tool.
5. **Frontend:** npm audit's 33 findings are mostly Angular build tooling
   (dev dependencies that never reach the browser). Trivy reports 3, with one
   HIGH in `ws`.

## Decision for the pipeline

- **Trivy is the gate** (blocking on CRITICAL with a fix available, after
  tuning): CVE-level results, SARIF into the Security tab, same tool as the
  container scan (Task 4).
- **npm audit stays as a report**, a second opinion from another database.
- **Dependabot stays on** for continuous monitoring and automatic fix PRs
  between pipeline runs.
- **Recommendation for the project:** commit a lockfile and use `npm ci`, so
  that what is scanned is exactly what is built and shipped.
