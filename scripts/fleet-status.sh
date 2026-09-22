#!/usr/bin/env bash
# fleet-status.sh — status table for fleet runs. Usage:
# Deployed at /root/pentest-stack/ with the docker-compose engagement stack;
# this is the tracked copy.
#   fleet-status.sh [--run DIR|RUNID] [--watch]
# Defaults to the `active` symlink run.
set -euo pipefail
FLEET_DIR=/root/pentest-stack/fleet

RUN=""; WATCH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run) RUN="${2%/}"; shift 2 ;;
    --watch) WATCH=1; shift ;;
    *) echo "usage: fleet-status.sh [--run DIR|RUNID] [--watch]" >&2; exit 1 ;;
  esac
done

resolve() {
  local r="$1"
  [ -d "$FLEET_DIR/$r" ] && { echo "$FLEET_DIR/$r"; return; }
  [ -d "$r" ] && { echo "$r"; return; }
  echo ""
}

if [ -z "$RUN" ]; then
  [ -e "$FLEET_DIR/active" ] || { echo "no fleet runs under $FLEET_DIR (pass --run)"; exit 1; }
  RUN_DIR=$(readlink -f "$FLEET_DIR/active")
else
  RUN_DIR=$(resolve "$RUN") || true
  [ -n "$RUN_DIR" ] || { echo "no such run: $RUN" >&2; exit 1; }
fi

render() {
  clear 2>/dev/null || true
  echo "═══ fleet run: $(basename "$RUN_DIR") ═══ $(date '+%F %T')"
  printf '%-14s %-14s %-9s %-10s %8s %8s %9s  %s\n' \
    "TAG" "STATUS" "DOCKER" "AGE" "OSINT-h" "ACT-h" "BYTES-Δ" "LAST EVENT"
  local f tag st c age1 age2 bytes runalive agestr
  for f in "$RUN_DIR"/state/*.json; do
    [ -f "$f" ] || continue
    tag=$(jq -r .tag "$f"); st=$(jq -r .status "$f")
    c="eng-$tag"
    runalive="-"   # up | stop (exists, parked) | - (removed)
    case "$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)" in
      running) runalive=up ;;
      exited|created|paused|restarting) runalive=stop ;;
    esac
    age1=$(ts_age_s "$(jq -r '.ts.launched // empty' "$f")")
    age2=$(ts_age_s "$(jq -r '.ts.injected // empty' "$f")")
    bytes=$(transcript_bytes "$tag" 2>/dev/null)
    if [ "$age1" = 999999999 ]; then agestr="-"; else
      agestr=$(printf '%dd%02dh' $((age1/86400)) $(((age1%86400)/3600))); fi
    printf '%-14s %-14s %-9s %-10s %8s %8s %9s  %s\n' \
      "$tag" "$st" "$runalive" "$agestr" \
      "$( [ "$age1" = 999999999 ] && echo - || echo $((age1/3600)) )" \
      "$( [ "$age2" = 999999999 ] && echo - || echo $((age2/3600)) )" \
      "$bytes" "$(jq -r '.last_event // ""' "$f" | cut -c1-50)"
  done
  echo "────────────────────────────────────────────────────────────────────────"
  # parked/wedge visibility — the stale-class canary line
  for f in "$RUN_DIR"/state/*.json; do
    jq -r 'select(.status=="active" or .status=="launched-osint")
           | select((.park.n // 0) > 0 or .wedge)
           | "⚠ \(.tag) parked (nudge \(.park.n // 0)/2)\(if .wedge then " — WEDGE seen" else "" end)"' "$f" 2>/dev/null
  done
  echo "monitor: tmux attach -t pentest   |   log: tail -f $RUN_DIR/fleet.log"
}

# need fleet-lib for transcript_bytes/ts_age_s
# shellcheck disable=SC1091
source /root/pentest-stack/fleet-lib.sh 2>/dev/null || true

if [ "$WATCH" = 1 ]; then
  while :; do render; sleep 10; done
else
  render
fi
