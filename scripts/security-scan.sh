#!/usr/bin/env bash
# =============================================================================
# Targeted local security scan, to run before a push (brief §5: "possibilité
# d'exécution ciblée en local avant push").
#
# It applies the SAME rules as the CI gates, on what you are about to push:
#   1. Gitleaks : secrets in your commits not yet on the base branch, and in
#                 staged changes (same config and baseline as CI)
#   2. Semgrep  : NEW findings of severity ERROR compared to the base branch
#                 (same 4 rule packs as CI; old findings are not reported)
#   3. Trivy    : CRITICAL dependency vulnerabilities with a fix available,
#                 except those accepted in .trivyignore (same gate as CI)
#
# Usage:
#   scripts/security-scan.sh              targeted scan against origin/main
#   scripts/security-scan.sh --base REF   compare with another base ref
#   scripts/security-scan.sh --full       full report (whole history and code),
#                                         informative, like the CI reports
#   scripts/security-scan.sh --no-trivy   skip the dependency scan (faster)
#
# Requirements (same versions as the pipeline, a warning is shown otherwise):
#   gitleaks 8.30.1, semgrep 1.183.0 (pipx install semgrep==1.183.0),
#   docker (Trivy runs from the image pinned by digest in devsecops.yml),
#   npm (to generate the lockfiles Trivy needs, without installing anything).
# Works on Linux, macOS and Git Bash on Windows. Run `git fetch` first so the
# base branch is up to date.
# =============================================================================
set -uo pipefail

GITLEAKS_VERSION="8.30.1"
SEMGREP_VERSION="1.183.0"
TRIVY_IMAGE="aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
SEMGREP_RULES=(--config p/javascript --config p/typescript --config p/nodejsscan --config p/owasp-top-ten)

BASE="origin/main"
FULL=0
RUN_TRIVY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="${2:?--base needs a git ref}"; shift 2 ;;
    --full) FULL=1; shift ;;
    --no-trivy) RUN_TRIVY=0; shift ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)"; exit 2 ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "Run this inside the repository."; exit 2; }
cd "$ROOT" || exit 2
export MSYS_NO_PATHCONV=1                      # Git Bash: keep docker paths as written
HOST_ROOT="$(pwd -W 2>/dev/null || pwd)"       # Git Bash: C:/... path for docker -v

if [ -t 1 ]; then RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
else RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""; fi

declare -a SUMMARY=()
FAILED=0
record() {  # record <tool> <PASS|FAIL|SKIP|INFO> <message>
  local colour="$YELLOW"
  [ "$2" = "PASS" ] && colour="$GREEN"
  [ "$2" = "FAIL" ] && { colour="$RED"; FAILED=1; }
  SUMMARY+=("$(printf '%-9s %s%-4s%s  %s' "$1" "$colour" "$2" "$RESET" "$3")")
}
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }
check_version() {  # check_version <name> <expected> <actual output>
  case "$3" in
    *"$2"*) ;;
    *) printf '%sWarning: %s %s is the pipeline version, found: %s%s\n' "$YELLOW" "$1" "$2" "$3" "$RESET" ;;
  esac
}

if [ "$FULL" -eq 0 ] && ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "Base ref '$BASE' not found. Run 'git fetch' or pass --base <ref>."; exit 2
fi
MERGE_BASE=""
[ "$FULL" -eq 0 ] && MERGE_BASE="$(git merge-base "$BASE" HEAD)"

# --- 1. Gitleaks --------------------------------------------------------------
section "1/3 Secrets (Gitleaks)"
if ! command -v gitleaks >/dev/null 2>&1; then
  record "Gitleaks" "SKIP" "gitleaks not installed"
else
  check_version "gitleaks" "$GITLEAKS_VERSION" "$(gitleaks version 2>&1)"
  if [ "$FULL" -eq 1 ]; then
    gitleaks git . --config .gitleaks.toml --redact --exit-code 1 --no-banner
    rc=$?
    if [ $rc -eq 0 ]; then record "Gitleaks" "PASS" "whole history, no secret outside the baseline"
    else record "Gitleaks" "FAIL" "whole history: secrets outside the baseline"; fi
  else
    gitleaks git . --config .gitleaks.toml --redact --exit-code 1 --no-banner --log-opts="${MERGE_BASE}..HEAD"
    rc_commits=$?
    gitleaks git . --config .gitleaks.toml --redact --exit-code 1 --no-banner --pre-commit --staged
    rc_staged=$?
    if [ $rc_commits -eq 0 ] && [ $rc_staged -eq 0 ]; then
      record "Gitleaks" "PASS" "no secret in unpushed commits or staged changes"
    else
      record "Gitleaks" "FAIL" "secret found: revoke it, remove it, never push it"
    fi
  fi
fi

# --- 2. Semgrep ---------------------------------------------------------------
section "2/3 SAST (Semgrep)"
if ! command -v semgrep >/dev/null 2>&1; then
  record "Semgrep" "SKIP" "semgrep not installed (pipx install semgrep==$SEMGREP_VERSION)"
else
  check_version "semgrep" "$SEMGREP_VERSION" "$(semgrep --version 2>&1)"
  if [ "$FULL" -eq 1 ]; then
    semgrep scan "${SEMGREP_RULES[@]}" --metrics off
    record "Semgrep" "INFO" "full report above (informative, like the CI report)"
  elif [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    # --baseline-commit refuses a dirty tree: scan only the files you changed.
    mapfile -t files < <(git diff --name-only --diff-filter=ACMR "$MERGE_BASE" -- '*.ts' '*.js' '*.mjs' '*.cjs')
    if [ "${#files[@]}" -eq 0 ]; then
      record "Semgrep" "PASS" "no changed JavaScript/TypeScript file"
    else
      echo "Uncommitted changes: scanning the ${#files[@]} changed file(s) (old findings in them are shown too)."
      if semgrep scan "${SEMGREP_RULES[@]}" --metrics off --error --severity ERROR "${files[@]}"; then
        record "Semgrep" "PASS" "no ERROR finding in the changed files"
      else
        record "Semgrep" "FAIL" "ERROR findings in the changed files (commit, then rerun to see only new ones)"
      fi
    fi
  else
    if semgrep scan "${SEMGREP_RULES[@]}" --metrics off --error --severity ERROR --baseline-commit "$MERGE_BASE"; then
      record "Semgrep" "PASS" "no new ERROR finding compared to $BASE"
    else
      record "Semgrep" "FAIL" "new ERROR finding(s) compared to $BASE"
    fi
  fi
fi

# --- 3. Trivy -----------------------------------------------------------------
section "3/3 Dependencies (Trivy)"
if [ "$RUN_TRIVY" -eq 0 ]; then
  record "Trivy" "SKIP" "skipped with --no-trivy"
elif ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  record "Trivy" "SKIP" "docker not available"
elif ! command -v npm >/dev/null 2>&1; then
  record "Trivy" "SKIP" "npm not available (needed to generate the lockfiles)"
else
  # Juice Shop disables lockfiles (.npmrc), so Trivy would see almost nothing.
  # Resolve them like the CI job: no package installed, no install script run.
  # Both files are gitignored, so nothing is added to the repository.
  [ -f package-lock.json ] || npm install --package-lock-only --package-lock=true --ignore-scripts --no-audit --no-fund >/dev/null
  if [ ! -f frontend/package-lock.json ]; then
    (cd frontend && npm install --package-lock-only --package-lock=true --ignore-scripts --no-audit --no-fund --legacy-peer-deps >/dev/null)
  fi
  if [ "$FULL" -eq 1 ]; then
    docker run --rm -v trivy-cache:/root/.cache/trivy -v "$HOST_ROOT:/src:ro" "$TRIVY_IMAGE" \
      fs --scanners vuln --severity HIGH,CRITICAL --ignorefile /dev/null --exit-code 0 /src
    record "Trivy" "INFO" "full HIGH/CRITICAL report above (informative)"
  elif docker run --rm -v trivy-cache:/root/.cache/trivy -v "$HOST_ROOT:/src:ro" "$TRIVY_IMAGE" \
      fs --scanners vuln --severity CRITICAL --ignore-unfixed --ignorefile /src/.trivyignore --exit-code 1 /src; then
    record "Trivy" "PASS" "no fixable CRITICAL outside .trivyignore"
  else
    record "Trivy" "FAIL" "fixable CRITICAL vulnerability: upgrade it, or get an exemption approved"
  fi
fi

# --- Summary ------------------------------------------------------------------
section "Summary"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
if [ "$FAILED" -eq 1 ]; then
  printf '\n%sBlocked: fix the findings above before pushing (the CI gates would fail too).%s\n' "$RED" "$RESET"
  exit 1
fi
printf '\n%sReady to push: the same checks pass in CI.%s\n' "$GREEN" "$RESET"
