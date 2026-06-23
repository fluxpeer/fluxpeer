#!/usr/bin/env bash
# Publish: push a branch + all tags to BOTH the public primary (GitHub) and an internal
# backup mirror, so the two stay aligned and history is never lost on one side.
#
#   scripts/mirror.sh [branch]      # default: main
#
# Expects remotes named `origin` (primary) and `backup` (mirror). See docs/REPO-GOVERNANCE.md.
set -euo pipefail
BRANCH="${1:-main}"

pushed=0
for r in origin backup; do
  if ! git remote get-url "$r" >/dev/null 2>&1; then
    echo "→ skip: remote '$r' not configured"
    continue
  fi
  echo "==> $r ($(git remote get-url "$r"))"
  git push "$r" "$BRANCH"
  git push "$r" --tags
  pushed=$((pushed + 1))
done

[ "$pushed" -gt 0 ] && echo "✓ mirrored $BRANCH to $pushed remote(s)" || { echo "✗ no remotes pushed" >&2; exit 1; }
