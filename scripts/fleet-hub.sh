#!/usr/bin/env bash
# fleet-hub.sh — merged read-only view across fleet boxes (the wall of screens).
# Pull model: ONE ssh round-trip per box per poll, running an inline read-only
# snippet (state JSONs + fleet.log tail) through the shared ControlMaster — no
# files are ever deployed to a worker box, so a box joins the fleet by alias
# alone. A box that doesn't answer renders as a UNREACHABLE canary row, never
# kills the view.
#
#   fleet-hub.sh status [--watch]         merged table: BOX | TAG | STATUS | CTX |
#                                        CMP | PARK | LAST EVENT + cross-box
#                                        canaries (park / wedge / ctx≥90)
#   fleet-hub.sh logs [-n N]              merged tail of every box's fleet.log
#   fleet-hub.sh split <targets> N [--round-robin|--chunk]
#                                        sharding preview: writes <targets>.2, .3, …
#                                        (round-robin default; dedupes by host;
#                                        preserves trailing `|instructions`)
#   fleet-hub.sh which <tag>              print the exact attach command per box
#   fleet-hub.sh relay <tag> "<text>" [--force]   guarded injection (delegates
#                                        to fleet-remote.sh)
#   fleet-hub.sh reports [--pull DIR]     finished-report filenames across boxes
#                                        (paths only; --pull rsyncs them into DIR)
#   fleet-hub.sh boxes                   per-box health card (host, disk, mem,
#                                        active run, image-drift check)
#
# Boxes come from FLEET_BOXES (default "local"): `local` or ssh-config aliases,
# space-separated. FLEET_STACK overrides the stack root (default
# /root/pentest-stack); FLEET_WS the workspace root (default
# /root/communitytools/projects/pentest).
set -euo pipefail
STACK=${FLEET_STACK:-/root/pentest-stack}
FLEET_WS=${FLEET_WS:-/root/communitytools/projects/pentest}
FLEET_BOXES=${FLEET_BOXES:-local}
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
err()   { echo "fleet-hub: $*" >&2; }

box_ssh_opts=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=15
              -o ControlMaster=auto -o ControlPath="$HOME/.ssh/fleet-cm-%C"
              -o ControlPersist=10m)

# Snippets are built as quoted heredocs (nothing expands at build time) with
# __STACK__/__WS__ placeholders swapped for the hub-side roots, then shipped to
# the box over stdin (`bash -s`) — zero nested-shell quoting to get wrong.
snippet_out() {  # <name> → final snippet text (roots substituted)
  local s
  case "$1" in
    pull) s=$(cat <<'SNIP'
BD="__STACK__/fleet"
D=$(readlink -f "$BD/active" 2>/dev/null || true)
if [ -z "$D" ] || [ ! -d "$D" ]; then
  # no active symlink → newest run dir (mtime), else nothing to report
  D=$(ls -1dt "$BD"/20* 2>/dev/null | head -1 || true)
fi
[ -n "$D" ] && [ -d "$D" ] || exit 0
for f in "$D"/state/*.json; do
  [ -f "$f" ] || continue
  jq -c --arg box "$(hostname -s)" '. + {box:$box}' "$f" 2>/dev/null
done
[ -f "$D/fleet.log" ] && tail -n 40 "$D/fleet.log" 2>/dev/null \
  | jq -Rsc --arg box "$(hostname -s)" '{kind:"log",box:$box,data:.}'
SNIP
) ;;
    reports) s=$(cat <<'SNIP'
find "__WS__" -maxdepth 6 -type f \
     \( -name '*.pdf' -o -name '*report*.md' -o -name 'monetization-chain.md' \) \
     -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -80 | cut -d' ' -f2-
SNIP
) ;;
    boxes) s=$(cat <<'SNIP'
printf '  host:  '; hostname -s
printf '  disk:  '; df -h / | awk 'NR==2{print $4" free of "$2}'
printf '  mem:   '; free -h | awk '/^Mem:/{print $7" avail of "$2}'
D=$(readlink -f "__STACK__/fleet/active" 2>/dev/null || true)
if [ -n "$D" ] && [ -d "$D" ]; then
  printf '  fleet: %s — %s targets\n' "$(basename "$D")" "$(ls "$D"/state/*.json 2>/dev/null | wc -l)"
else
  echo '  fleet: no active run'
fi
if [ -x "__STACK__/build-eng.sh" ]; then
  if out=$(bash __STACK__/build-eng.sh --check 2>&1); then
    echo "$out" | sed 's|^|  |' | head -4
  else
    echo "  IMAGE DRIFT (build-eng.sh --check failed)" | head -4
  fi
fi
SNIP
) ;;
    *) return 1 ;;
  esac
  s=${s//__STACK__/$STACK}
  s=${s//__WS__/$FLEET_WS}
  printf '%s' "$s"
}

run_snippet() {  # <box> <snippet-text>
  if [ "$1" = local ]; then bash -s <<< "$2"; else
    printf '%s' "$2" | ssh "${box_ssh_opts[@]}" "$1" bash -s 2>/dev/null
  fi
}

pull_all() {  # every box's NDJSON + LOG lines; unreachable boxes emit an error row
  local b out
  for b in $FLEET_BOXES; do
    if out=$(run_snippet "$b" "$(snippet_out pull)" 2>/dev/null); then
      printf '%s\n' "$out"
    else
      printf '{"box":"%s","kind":"error","error":"unreachable"}\n' "$b"
    fi
  done
}

# ---- rendering ------------------------------------------------------------
render() {
  local n=${1:-30}
  clear 2>/dev/null || true
  echo "═══ fleet hub ═══ boxes: $FLEET_BOXES ═══ $(date '+%F %T')"
  printf '%-10s %-17s %-15s %5s %4s %5s  %s\n' \
    "BOX" "TAG" "STATUS" "CTX%" "CMP" "PARK" "LAST EVENT"
  pull_all | jq -r 'select(.status) |
      [(.box//"?")[:10], (.tag//"?")[:17], (.status//"-")[:15],
       ((.ctx // "-")|tostring)[:5], ((.compact // "-")|tostring)[:4],
       ((.park.n // 0)|tostring)[:5], ((.last_event//"")[:58])] | @tsv' \
    2>/dev/null | while IFS=$'\t' read -r box tag st ctx cmp park ev; do
      printf '%-10s %-17s %-15s %5s %4s %5s  %s\n' \
        "$box" "$tag" "$st" "$ctx" "$cmp" "$park" "$ev"
    done
  echo "────────────────────────────────────────────────────────────────────────"
  # cross-box canaries — same classes as fleet-status.sh: parked / wedge / ctx
  pull_all | jq -r 'select(.status=="active" or .status=="launched-osint") |
      select((.park.n // 0) > 0 or .wedge or ((.ctx // 0) >= 90)) |
      (.box) + "/" + (.tag) + ": " +
      ([ (if ((.park.n // 0) > 0) then "parked (\(.park.n // 0)/2)" else empty end),
         (if .wedge then "WEDGE" else empty end),
         (if ((.ctx // 0) >= 90) then "\(.ctx)% ctx" else empty end) ] | join(", "))' \
    2>/dev/null || true
  pull_all | jq -r 'select(.kind=="error") | "⚠ " + .box + ": UNREACHABLE"' 2>/dev/null || true
}

render_logs() {  # <n>
  local n=${1:-30}
  pull_all | jq -r 'select(.kind=="log") | .box as $b |
      (.data | split("\n")[] | select(length>0) | $b + " " + .)' 2>/dev/null \
    | tail -n "$n" || true
}

# ---- split: targets-file sharding preview ---------------------------------
do_split() {  # <file> N <mode>
  local file=$1 n=$2 mode=$3
  [ -f "$file" ] || { err "no such targets file: $file"; return 1; }
  [ "$n" -ge 2 ] 2>/dev/null || { err "N must be ≥ 2 (a single box uses the file as-is)"; return 1; }
  local line host h dup idx i per
  local -a lines=() hosts=()
  # dedupe by host, keep comments/blank lines out of the split
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    host=$(printf '%s' "${line%%|*}" | tr -d '[:space:]')
    dup=0; for h in "${hosts[@]:-}"; do [ "$h" = "$host" ] && dup=1; done
    [ "$dup" = 0 ] || continue
    lines+=("$line"); hosts+=("$host")
  done < "$file"
  [ "${#lines[@]}" -ge "$n" ] || err "note: fewer unique targets (${#lines[@]}) than boxes ($n)"
  local -a outs=()
  for ((i=1; i<=n; i++)); do : > "$file.$i"; outs+=("$file.$i"); done
  case "$mode" in
    round-robin)
      i=0
      for line in "${lines[@]}"; do echo "$line" >> "${outs[$((i % n))]}"; i=$((i+1)); done ;;
    chunk)
      per=$(( ( ${#lines[@]} + n - 1 ) / n ))
      i=0
      for line in "${lines[@]}"; do echo "$line" >> "${outs[$(( i / per ))]}"; i=$((i+1)); done ;;
    *) err "mode must be round-robin or chunk"; return 1 ;;
  esac
  echo "split $file → $n files (mode=$mode, ${#lines[@]} unique targets):"
  for ((i=0; i<n; i++)); do
    echo "  ${outs[$i]}: $(grep -c . "${outs[$i]}") targets"
  done
}

# ---- which/relay/reports/boxes ----------------------------------------------
do_reports() {
  local pull=0 dir="" b list
  while [ $# -gt 0 ]; do case "$1" in
    --pull) pull=1; dir=$2; shift 2 ;;
    *) err "unknown flag: $1"; exit 1 ;; esac; done
  for b in $FLEET_BOXES; do
    echo "── $b"
    list=$(run_snippet "$b" "$(snippet_out reports)") \
      || { echo "  UNREACHABLE"; continue; }
    [ -n "$list" ] || { echo "  (no report files found)"; continue; }
    printf '%s\n' "$list" | sed 's|^|  |'
    if [ "$pull" = 1 ]; then
      mkdir -p "$dir/$b"
      printf '%s\n' "$list" | rsync -av --files-from=- \
        ${b/#local/:}:"$FLEET_WS/" "$dir/$b/" 2>/dev/null \
        && echo "  pulled into $dir/$b/" || echo "  PULL FAILED for $b"
    fi
  done
}

do_boxes() {
  local b
  for b in $FLEET_BOXES; do
    echo "── $b"
    run_snippet "$b" "$(snippet_out boxes)" || echo "  UNREACHABLE"
  done
}

# ---- main ------------------------------------------------------------------------------------------------
cmd=${1:-}; [ -n "$cmd" ] || usage 1
case "$cmd" in -h|--help|help) usage 0 ;; esac
shift
watch=0 n=30 mode=round-robin

case "$cmd" in
  status)
    while [ $# -gt 0 ]; do case "$1" in
      --watch) watch=1; shift ;; *) err "unknown flag: $1"; exit 1 ;; esac; done
    if [ "$watch" = 1 ]; then while :; do render; sleep 10; done; else render; fi
    ;;
  logs)
    while [ $# -gt 0 ]; do case "$1" in
      -n) n=$2; shift 2 ;; *) err "unknown flag: $1"; exit 1 ;; esac; done
    render_logs "$n"
    ;;
  split)
    [ $# -ge 2 ] || { err "usage: fleet-hub.sh split <targets> N [--round-robin|--chunk]"; exit 1; }
    [ $# -ge 3 ] && case "$3" in
      --round-robin) mode=round-robin ;; --chunk) mode=chunk ;;
      *) err "unknown mode: $3"; exit 1 ;; esac
    do_split "$1" "$2" "$mode"
    ;;
  which)   [ $# -ge 1 ] || { err "usage: fleet-hub.sh which <tag>"; exit 1; }
           bash "$SELF_DIR/fleet-remote.sh" which "$@" ;;
  relay)   [ $# -ge 2 ] || { err 'usage: fleet-hub.sh relay <tag> "<text>" [--force]'; exit 1; }
           bash "$SELF_DIR/fleet-remote.sh" relay "$@" ;;
  reports) do_reports "$@" ;;
  boxes)   do_boxes ;;
  *) err "unknown command: $cmd"; usage 1 ;;
esac
