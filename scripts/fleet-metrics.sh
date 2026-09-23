#!/usr/bin/env bash
# fleet-metrics.sh — context-saturation + latency evidence for the autocompact rollout.
# Read-only. Per active tag:
#   ctx% (live pane) | armed wording | compacts | round-trip gap median/p90/max |
#   transcript bytes | WEDGE-R/NUDGE/MCOMPACT counts from this run's fleet.log
# Usage: fleet-metrics.sh [runid]   (default: active run)
set -euo pipefail
STACK=/root/pentest-stack
RUNID="${1:-$(basename "$(readlink -f "$STACK/fleet/active" 2>/dev/null)" 2>/dev/null || true)}"
[ -n "$RUNID" ] || { echo "no run id"; exit 1; }
RUN_DIR="$STACK/fleet/$RUNID"
# shellcheck disable=SC1091
source "$STACK/fleet-lib.sh"

printf '%-14s %5s %-6s %5s  %7s %7s %7s  %9s  %s\n' \
  "TAG" "CTX%" "ARMED" "CMP" "GAP-med" "GAP-p90" "GAP-max" "BYTES" "LOG EVENTS"
for f in "$RUN_DIR"/state/*.json; do
  [ -f "$f" ] || continue
  tag=$(jq -r .tag "$f"); st=$(jq -r .status "$f")
  case "$st" in active|launched-osint) ;; *) continue ;; esac
  c="eng-$tag"
  ctxp=$(pane_context_pct "$c" 2>/dev/null || echo 0)
  arm=$(pane_autocompact_armed "$c" 2>/dev/null && echo yes || echo no)
  cmpn=$(compact_count "$tag")
  gaps=$(python3 - "$tag" <<'PY'
import json,glob,sys,statistics,os
from datetime import datetime
# newest session file wins; records must have timestamps
files=sorted(glob.glob(f"/root/kali-state/{sys.argv[1]}/claude/projects/*/*.jsonl"),key=os.path.getmtime)
ts=[]
if files:
    for line in open(files[-1],errors='ignore'):
        try: d=json.loads(line)
        except: continue
        t=d.get('timestamp')
        if t: ts.append(datetime.fromisoformat(t.replace('Z','+00:00')))
ts=ts[-500:]
if len(ts)>=3:
    g=[(b-a).total_seconds() for a,b in zip(ts,ts[1:])]
    g=[x for x in g if x<3600]
    print(f"{statistics.median(g):5.0f} {sorted(g)[int(len(g)*.9)]:7.0f} {max(g):7.0f}")
else: print("    -       -       -")
PY
)
  bytes=$(transcript_bytes "$tag")
  # grep exits 1 on zero matches — `|| true` keeps pipefail from killing
  # the assignment for healthy tags (the exact bug that truncated early rows)
  ev=$(grep -hE "WEDGE-R $tag|NUDGE   $tag|MCOMPACT $tag|RETRY   $tag" "$RUN_DIR/fleet.log" 2>/dev/null | wc -l || true)
  printf '%-14s %5s %-6s %5s  %7s  %9s  %s\n' "$tag" "$ctxp" "$arm" "$cmpn" "$gaps" "$bytes" "$ev"
done
