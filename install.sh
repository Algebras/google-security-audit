#!/usr/bin/env bash
# One-line install:  curl -fsSL https://raw.githubusercontent.com/Algebras/google-security-audit/main/install.sh | bash
set -euo pipefail
REPO="git+https://github.com/Algebras/google-security-audit.git"

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "google-security-audit[browser] @ ${REPO}"
  pipx runpip google-security-audit install -q playwright >/dev/null 2>&1 || true
  PW="$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/google-security-audit/bin/playwright"
else
  python3 -m pip install --user --upgrade "google-security-audit[browser] @ ${REPO}"
  PW="python3 -m playwright"
fi

# Browser used for the interactive login step (uses your installed Chrome when available).
$PW install chromium >/dev/null 2>&1 || echo "Note: run 'playwright install chromium' if the login browser fails to open."

echo
echo "Installed. Next, start your app locally and run:"
echo "  gsa scan /path/to/your-app http://localhost:3000"
