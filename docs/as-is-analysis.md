# As-is analysis: the original OWASP Juice Shop pipeline

Brief §2. This describes the CI/CD that came with OWASP Juice Shop when we
imported it, **before** any change by our team, and compares it with the
pipeline we built (to-be).

**Source:** the 16 upstream workflow files in `.github/workflows/`, removed in
commit `31c8f13` ("Remove upstream workflows"); they can be read with
`git show 31c8f13^:.github/workflows/<file>`. They were removed because almost
every job is guarded by `if: github.repository == 'juice-shop/juice-shop'` and
needs the upstream project's secrets (Docker Hub, Heroku, Slack…), so they do
nothing useful in our copy, and because we wanted a clean baseline.

> Juice Shop is deliberately vulnerable and its pipeline serves a training
> project, not a production service. The weaknesses below are judged against
> the professor's brief (secure CI/CD), not as criticism of the maintainers.

---

## 1. Inventory of the 16 workflows

| Category | Workflows | Purpose |
|---|---|---|
| **CI/CD** | `ci.yml` (406 lines), `release.yml` | Lint, tests, build, Docker image, deployment, release packaging |
| **Security** | `codeql-analysis.yml` | CodeQL SAST (the only security scan) |
| Code/asset automation | `lint-fixer.yml`, `image_actions.yml`, `frontend-bundle-analysis.yml` | Auto-commit lint fixes, compress images, analyse bundle size |
| Repository housekeeping | `pr-compliance.yml`, `issue-compliance.yml`, `lock.yml`, `stale.yml`, `rebase.yml` | Check PR/issue templates, lock/close old threads, rebase on comment |
| Website / content | `update-challenges-ebook.yml`, `update-challenges-www.yml`, `update-challenges-www-legacy.yml`, `update-news-www.yml`, `update-news-www-legacy.yml` | Publish challenge lists and news to the project websites |

## 2. Stages of the main pipeline (`ci.yml`, "CI/CD Pipeline")

Triggered on every push (except tags and a few branches) and pull request.

| Stage | Jobs | Tools |
|---|---|---|
| Lint | `lint`, `coding-challenge-rsn` | ESLint (`npm run lint`), Juice Shop's own challenge checker |
| Unit and API tests | `frontend-test`, `server-test`, `api-test` | Matrix 3 OS (Ubuntu, macOS, Windows) × Node 22/24/26 |
| Integration / E2E | `custom-config-test`, `e2e-test`, `smoke-test`, `docker-test` | Cypress, `docker compose` test stack |
| Coverage | `coverage-report` | Coveralls |
| Build and package | `docker` | Buildx multi-arch (amd64, arm64), **push to Docker Hub** `bkimminich/juice-shop:latest` (master) or `:snapshot` (develop) |
| Deploy | `heroku` | Heroku: `juice-shop` (master) and **`juice-shop-staging`** (develop) |
| Notify | `notify-slack` | Slack webhook on success or failure |

`release.yml` adds, on tags: a GitHub release, packaged archives for several
OS/Node combinations, and a Docker image pushed to Docker Hub.

## 3. Security controls already present

- **CodeQL** (`security-extended` queries) on every push and pull request,
  results in the GitHub Security tab.
- Most actions **pinned by commit SHA** (checkout, setup-node, Docker actions,
  Cypress, Heroku deploy, release).
- Explicit least-privilege `permissions` in `codeql-analysis.yml` and the
  housekeeping workflows.
- An **SBOM is generated inside the Docker build** (`npm run sbom` with
  CycloneDX), but it stays inside the image.
- Deployment and Docker push **depend on the tests passing** (`needs:`).
- **Slack notifications** on pipeline results.

## 4. Security weaknesses (against the brief)

| # | Weakness | Where | Risk |
|---|---|---|---|
| W1 | **No secrets scanning** at all (no Gitleaks/TruffleHog, no pre-commit hook) | whole pipeline | Leaked keys go unnoticed; the repo really contains a hardcoded RSA key (`terraform/networking.tf`) and a JWT signing key (`lib/insecurity.ts`) |
| W2 | **No dependency scanning (SCA)**, and **no lockfile** (`.npmrc`: `package-lock=false`) | `ci.yml` | Vulnerable dependencies ship unnoticed (we found 37 HIGH/CRITICAL); builds are not reproducible |
| W3 | **Docker image pushed with no scan and no signature**, under **mutable tags** (`latest`, `snapshot`) | `ci.yml` `docker`, `release.yml` | Users pull an image nobody checked; a tag can be moved to another image; no way to prove origin |
| W4 | **No IaC / Dockerfile scanning** | whole pipeline | `terraform/` (113 Checkov failures) and the Dockerfile (untagged base image) never checked |
| W5 | **No DAST**, although a **staging environment exists** (`juice-shop-staging` on Heroku) | `ci.yml` `heroku` | Runtime issues (missing CSP, wildcard CORS, browsable `/ftp`) only visible from outside |
| W6 | **No security gate**: CodeQL reports but nothing blocks a merge or a deployment on a vulnerability | `codeql-analysis.yml` | A new SQL injection could be merged and deployed |
| W7 | **Some actions pinned by mutable tag or branch**: `github/codeql-action/*@v3`, `coverallsapp/github-action@v2`, `actions/checkout@v6`, `peter-evans/create-pull-request@v8`, **`calibreapp/image-actions@main`** | `codeql-analysis.yml`, `ci.yml`, `image_actions.yml` | A compromised or moved tag runs attacker code with the job's token (the March 2026 `trivy-action` incident) |
| W8 | **No `permissions:` block** in `ci.yml`, `release.yml`, `lint-fixer.yml`, `image_actions.yml` | those files | The `GITHUB_TOKEN` gets the repository's default permissions, possibly write access, in jobs that run third-party actions |
| W9 | **`curl … \| sh`**: the Heroku CLI install script is downloaded and executed without any verification, in the job that holds `HEROKU_API_KEY` | `ci.yml` `heroku` | A compromised download host or script steals the deployment key |
| W10 | **Bots write to the repository**: `lint-fixer.yml` auto-commits lint fixes on every push; `image_actions.yml` opens PRs | those files | Code changes not written or reviewed by a human |
| W11 | `pull_request_target` with `pull-requests: write` | `pr-compliance.yml` | Risky trigger (runs with write permissions on PRs from forks). Mitigated here because the PR's code is never checked out |
| W12 | **Long-lived, broad secrets**: `DOCKERHUB_TOKEN`, `HEROKU_API_KEY`, `BOT_TOKEN`, **`ORG_ADMIN_TOKEN`**, `SLACK_WEBHOOK_URL`, `ALCHEMY_API_KEY` | several files | An organisation-admin token in CI has a very large blast radius if leaked |
| W13 | **No shift-left**: no threat model, no pre-commit hooks, no IDE guidance | process | Developers learn about problems late, if at all |

## 5. As-is vs to-be

| Stage | As-is (upstream) | To-be (our pipeline) | Blocking? |
|---|---|---|---|
| Design | — | Threat model, 26 STRIDE threats mapped to pipeline stages | – |
| Developer workstation | — | Pre-commit hooks (Gitleaks, Semgrep, private keys); IDE plugins | Locally |
| Secrets | — | **Gitleaks**, full history, reviewed baseline | ✅ Yes |
| SAST | CodeQL, report only | **CodeQL + Semgrep + SonarQube Cloud** | ✅ New High+ alerts / quality gate |
| SCA | — | **Trivy** (+ npm audit, Dependabot) on a generated lockfile | ✅ CRITICAL with a fix |
| SBOM | Inside the image only | **Syft**, CycloneDX, published per commit | – |
| IaC / Dockerfile | — | **Hadolint + Checkov** | ✅ Dockerfile we ship |
| Image | Build + push, mutable tags | Build → **Trivy scan → gate → push** to GHCR, tagged by commit SHA | ✅ Before the push |
| Signing | — | **Cosign** sign by digest + verify + negative test | ✅ Yes |
| DAST | — | **OWASP ZAP** baseline on the signed image | ✅ New Medium+ alerts |
| Security tests | — | Attack tests (SQLi, forged JWT, IDOR, stack trace) | ✅ After the fixes |
| Supply chain of the pipeline | Mostly SHA-pinned, some tags/branches, no `permissions` in CI | **Everything SHA/digest-pinned**, least-privilege `permissions` per job, checksums verified for downloaded tools | – |
| Reporting | Security tab (CodeQL), Slack | Security tab for all tools, SonarQube dashboard, SARIF/JSON/HTML artifacts | – |
