#!/usr/bin/env bash
# build-eng.sh — rebuild kali-claude-eng:latest from Dockerfile.eng.
# The watchdog entrypoint is COPYd into the image (never bind-mounted), so entrypoint
# edits are INVISIBLE to newly launched containers until this runs — the exact trap
# that left the Sep 21 mouse/scrollback fix and Sep 22 wedge detection unbaked for
# 24h+. Run after ANY kali-resume-entrypoint.sh change.
#   bash build-eng.sh           # rebuild + report
#   bash build-eng.sh --check   # diff running image's entrypoint vs the stack copy
set -euo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" = "--check" ]; then
  # byte-compare the entrypoint inside the current image vs the stack copy
  tmp=$(mktemp -d)
  cid=$(docker create "kali-claude-eng:latest" 2>/dev/null)
  docker cp "$cid:/opt/kali-resume-entrypoint.sh" "$tmp/in-image.sh" >/dev/null 2>&1
  docker rm "$cid" >/dev/null 2>&1
  if cmp -s "$tmp/in-image.sh" kali-resume-entrypoint.sh; then
    echo "[build-eng] image entrypoint is current"
    rm -rf "$tmp"; exit 0
  else
    echo "[build-eng] STALE: image entrypoint differs from stack copy — rebuild needed (diff below)"
    diff "$tmp/in-image.sh" kali-resume-entrypoint.sh | head -20 || true
    rm -rf "$tmp"; exit 1
  fi
fi

docker build -t kali-claude-eng:latest -f Dockerfile.eng . | tail -3
echo "[build-eng] rebuilt kali-claude-eng:latest — running containers keep the old image;"
echo "[build-eng] recreate (docker-compose up -d --force-recreate eng-<tag>) to pick it up"
