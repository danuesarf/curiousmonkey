#!/usr/bin/env bash
# The same checks as .github/workflows/security.yml, with whichever tools are installed here.
#   npm run security            all of them
#   npm run security -- semgrep one of them (audit | trivy | semgrep | gitleaks | checkov)
# Install: brew install trivy semgrep gitleaks checkov   (or pip install semgrep checkov)
set -uo pipefail
cd "$(dirname "$0")/.."
want="${1:-all}"; failed=(); skipped=()
run() { local name="$1"; shift
  [[ "$want" == all || "$want" == "$name" ]] || return 0
  if ! command -v "$1" >/dev/null 2>&1; then skipped+=("$name"); echo "== $name: skipped ($1 not installed)"; return 0; fi
  echo "== $name"; if "$@"; then echo "== $name: ok"; else failed+=("$name"); echo "== $name: FAILED"; fi; }

run audit    npm audit --audit-level=moderate
run trivy    trivy fs --scanners vuln,secret,misconfig --skip-dirs node_modules,bench --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
run semgrep  semgrep scan --metrics=off --disable-version-check \
               --config p/javascript --config p/nodejs --config p/expressjs --config p/xss --config p/secrets \
               --config p/dockerfile --config p/kubernetes --config p/github-actions --config p/insecure-transport \
               --exclude node_modules --exclude bench --severity ERROR --severity WARNING --error
run gitleaks gitleaks git --no-banner --redact --exit-code 1 .
run checkov  checkov -d . --config-file .checkov.yaml

echo
[[ ${#skipped[@]} -gt 0 ]] && echo "skipped (not installed): ${skipped[*]}"
if [[ ${#failed[@]} -gt 0 ]]; then echo "failed: ${failed[*]}"; exit 1; fi
echo "all checks that ran passed"
