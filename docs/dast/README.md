# DAST with OWASP ZAP

Task 6 (Person B). Produced by the `dast` job (stage 9) of
`.github/workflows/devsecops.yml`, which runs after `publish` and `sign` and
BEFORE the staging deployment (stage 10): an image with a new Medium or higher
alert is never deployed.

## How the scan runs

1. The job pulls the image built and **signed** in the same run, by digest, so
   the scan targets exactly the artifact we would deploy.
2. It starts the image in an isolated test container inside the CI runner,
   reachable only on `127.0.0.1:3000`, as the image's non-root user and without
   Linux capabilities, and waits until the application answers.
3. It runs the **ZAP 2.17.0 baseline scan** (`zap-baseline.py`): ZAP spiders
   the application for one minute and passively inspects every response
   (headers, cookies, page content). Baseline mode sends no attack payloads,
   and the scan only ever targets the container inside the job.
4. Reports `zap-report.html`, `zap-report.json` and `zap-report.md` are kept as
   the `zap-reports` artifact, and the alert summary is written to the run's
   Summary page.

## Results (first run)

ZAP crawled 93 endpoints and raised 9 alerts: **0 high, 2 medium, 4 low,
3 informational** (`docs/screenshots/21-zap-alerts.png`).

| Alert | Risk | Where | What it means |
|---|---|---|---|
| Content Security Policy header not set | Medium | Every page, including `/ftp` | No CSP, so the browser has no second line of defence if an XSS payload gets into a page. Juice Shop has several XSS challenges that CSP would mitigate. |
| Cross-domain misconfiguration | Medium | Every response | `Access-Control-Allow-Origin: *` (the app calls `cors()` with no options): any website can read the responses from a visitor's browser. |
| Cross-Origin-Embedder-Policy missing | Low | Main pages, `/ftp` | Missing isolation header. |
| Cross-Origin-Opener-Policy missing | Low | Main pages, `/ftp` | Another site that opens Juice Shop in a window can keep a reference to it. |
| Dangerous JS functions | Low | `main.js` and one chunk | Angular's `bypassSecurityTrustHtml(` is used: it switches off Angular's built-in HTML sanitising, the root cause of Juice Shop's DOM XSS challenges. |
| Deprecated Feature-Policy header | Low | Every response | The app still sends `Feature-Policy`, which browsers replaced with `Permissions-Policy`. |
| Modern web application, storable / cacheable content | Info | Various | Informational, no action needed. |

### What the static tools could not see

- **Exposed `/ftp` directory listing.** ZAP's spider found
  `http://127.0.0.1:3000/ftp` and followed it to
  `/ftp/coupons_2013.md.bak`: anyone can browse the folder and download
  backup files. It is listed in `robots.txt` as `Disallow: /ftp`, which only
  tells search engines where the sensitive files are. In the code it is a
  `serve-index` middleware on `/ftp` (`server.ts`).
- **Stack traces in error pages.** ZAP's spider also picked up internal paths
  such as `/juice-shop/build/routes/fileServer.js:68:18`, which can only come
  from an error page that prints the server's stack trace (the `errorhandler`
  middleware). This tells an attacker the framework, file layout and code
  lines.
- **The real runtime headers.** SAST reads the code; only DAST sees which
  headers the running server actually sends. Here it shows that the app sets
  `X-Content-Type-Options` and `X-Frame-Options` (via `helmet`) but no CSP,
  COOP or COEP, and an outdated `Feature-Policy`.

None of these is a vulnerable dependency or a misconfigured Dockerfile, which
is why SCA, the image scan and IaC scanning found none of them.

## Gate for later

Baseline mode does not attack, so it produces no "High" alerts on its own.
Once the expected alerts are triaged (a rules file passed with `-c`), the job
fails on any new **Medium or higher** alert: a page served without CSP or with
a wildcard CORS policy is then blocked before release.

## Candidates for Task 7 (fix 2)

- **Restrict `/ftp`**: remove the directory listing so the folder cannot be
  browsed. The `/ftp` URLs should disappear from the next ZAP report.
- **Add a Content-Security-Policy header** with `helmet.contentSecurityPolicy()`
  (and `Permissions-Policy` instead of `Feature-Policy`): the Medium CSP alert
  should disappear.
