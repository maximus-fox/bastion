#!/bin/bash
# Installs dev tooling (ESLint, Playwright) for Claude Code cloud sessions.
# Chromium is preinstalled there (PLAYWRIGHT_BROWSERS_PATH), so no browser download.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"
npm install --no-audit --no-fund
