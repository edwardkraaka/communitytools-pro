#!/usr/bin/env bash
# kali-mon.sh — one host tmux session ("pentest") with a pane per running eng-*
# engagement, each attached to that container's live claude TUI.
#
#   bash kali-mon.sh                     # (re)build the monitor from scratch
#   bash kali-mon.sh --add eng-<tag>     # add ONE pane (safe while attached)
#   bash kali-mon.sh --remove eng-<tag>  # kill pane by title, drop empty windows
#   bash kali-mon.sh --prune             # reconcile panes to running containers
#   bash kali-mon.sh tiled               # rebuild with a given layout
#   tmux attach -t pentest               # then view it
#
# Windows hold up to MAXPANES panes; overflow spills into fleet-N windows.
# Scope rule: pane membership is ALWAYS `list-panes -s -t pentest` — every
# window of THIS session, nothing else. Two proven-wrong alternatives in
# tmux 3.4: no flag lists only the ACTIVE window (panes elsewhere become
# invisible to --add/--remove — the duplicate-pane bug), and `-a` ignores
# -t and lists every pane on the server, session 0 included.
#
# Inside:  switch panes = Ctrl-b <arrow> ;  next/prev tab = Ctrl-b n / Ctrl-b p ;  detach = Ctrl-b d
# To send a key to the INNER claude (nested tmux), press the prefix TWICE: Ctrl-b Ctrl-b <key>
set -euo pipefail
S=pentest
# Panes per window (a fleet "tab", tiled 2x2). More engagements than this
# spill into fleet-N windows — flip tabs with Ctrl-b n / Ctrl-b p.
# MON_MAXPANES env overrides when a different chunking is wanted.
MAXPANES="${MON_MAXPANES:-4}"

# all windows of session S (see scope rule above)
panes_of_session() { tmux list-panes -t "$S" -s -F "$1" 2>/dev/null; }

# per-window pane listing (window-target form "$S:<idx>")
panes_of_window() { tmux list-panes -t "$1" -F "#{pane_id}" 2>/dev/null; }

set_session_opts() {
  tmux set -t "$S" pane-border-status top >/dev/null 2>&1 || true
  tmux set -t "$S" mouse on >/dev/null 2>&1 || true
}

add_pane() {
  local c="$1" target win n

  # create the session (fresh first pane) if missing
  if ! tmux has-session -t "$S" 2>/dev/null; then
    tmux new-session -d -s "$S" -x 250 -y 62 "exec docker exec -it $c tmux attach -t eng"
    tmux select-pane -t "$S" -T "$c"
    set_session_opts
    echo "Built '$S' with pane $c"
    return
  fi

  # already present? (match pane by title, all windows of the session)
  if panes_of_session '#{pane_title}' | grep -qxF "$c"; then
    echo "$c already has a pane"
    return
  fi

  # first window with fewer than MAXPANES panes, else a new fleet-N window
  target=""
  for win in $(tmux list-windows -t "$S" -F '#{window_index}'); do
    n=$(panes_of_window "$S:$win" | wc -l)
    if [ "$n" -lt "$MAXPANES" ]; then target="$S:$win"; break; fi
  done
  if [ -z "$target" ]; then
    # every window full: new fleet-N window with the pane as ITS first pane —
    # new-window WITHOUT a command would open a stray default shell next to
    # the split (the "high"-titled ghost panes this monitor used to leak)
    win=$(tmux new-window -t "$S" -P -F '#{window_index}' "exec docker exec -it $c tmux attach -t eng")
    target="$S:$win"
    tmux rename-window -t "$target" "fleet-$win" >/dev/null 2>&1 || true
    tmux select-pane -t "$target" -T "$c"
    echo "Added pane $c (window $target, new)"
    return
  fi
  tmux split-window -t "$target" "exec docker exec -it $c tmux attach -t eng"
  tmux select-pane -t "$target" -T "$c"
  tmux select-layout -t "$target" tiled >/dev/null 2>&1 || true
  echo "Added pane $c (window $target)"
}

remove_pane() {
  local c="$1" idx w
  while read -r idx; do
    [ -z "$idx" ] && continue
    tmux kill-pane -t "$idx" 2>/dev/null || true
  done < <(panes_of_session '#{pane_id} #{pane_title}' | awk -v t="$c" '$2==t{print $1}')
  # drop windows left with zero panes
  while read -r w; do
    [ -z "$w" ] && continue
    tmux kill-window -t "$w" 2>/dev/null || true
  done < <(tmux list-windows -t "$S" -F '#{window_index} #{window_panes}' 2>/dev/null | awk '$2==0{print $1}')
}

prune_panes() {
  local c present
  # add panes for containers without one
  while read -r c; do
    [ -z "$c" ] && continue
    present=$(panes_of_session '#{pane_title}' | grep -cx "$c" || true)
    [ "${present:-0}" -eq 0 ] && add_pane "$c"
  done < <(docker ps --filter name=eng- --filter status=running --format '{{.Names}}' | sort)
  # remove panes whose container is gone OR not running — a stopped container's
  # pane is dead weight (frozen frame; the attach client died with the stop) and
  # must NOT hold a spot. Running containers only: that's what the monitor shows.
  while read -r c; do
    [ -z "$c" ] && continue
    if ! docker ps --filter "name=^${c}$" --filter status=running --format '{{.Names}}' | grep -q .; then
      remove_pane "$c"
    fi
  done < <(panes_of_session '#{pane_title}' | sort -u)
  # drop the session entirely if no panes remain
  if [ -z "$(panes_of_session '#{pane_id}')" ]; then
    tmux kill-session -t "$S" 2>/dev/null || true
    echo "no panes left — session '$S' closed"
  fi
}

case "${1:-}" in
  --add)    [ -n "${2:-}" ] || { echo "usage: kali-mon.sh --add <container>"; exit 1; }; add_pane "$2";  exit ;;
  --remove) [ -n "${2:-}" ] || { echo "usage: kali-mon.sh --remove <container>"; exit 1; }; remove_pane "$2"; exit ;;
  --prune)  prune_panes; exit ;;
esac

LAYOUT="${1:-even-vertical}"   # even-vertical (stacked, full width) | tiled (grid)
LAYOUT=${LAYOUT//_/-}          # accept either spelling; tmux wants hyphens

mapfile -t CS < <(docker ps --filter name=eng- --filter status=running --format '{{.Names}}' | sort)
[ "${#CS[@]}" -gt 0 ] || { echo "no eng-* containers running"; exit 1; }

# from-scratch build, chunked like --add: window 0 holds up to MAXPANES panes,
# overflow spills into fleet-N windows (never one giant unreadable window)
tmux kill-session -t "$S" 2>/dev/null || true
tmux new-session -d -s "$S" -x 250 -y 62 "exec docker exec -it ${CS[0]} tmux attach -t eng"
tmux select-pane  -t "$S" -T "${CS[0]}"
tmux rename-window -t "$S:0" fleet-0 >/dev/null 2>&1 || true
set_session_opts
w=1; wn=0
for ((i=1; i<${#CS[@]}; i++)); do
  if [ "$w" -lt "$MAXPANES" ]; then
    tmux split-window -t "$S" "exec docker exec -it ${CS[$i]} tmux attach -t eng"
    w=$((w+1))
  else
    wn=$((wn+1))
    tmux new-window -t "$S" -n "fleet-$wn" "exec docker exec -it ${CS[$i]} tmux attach -t eng"
    w=1
  fi
  tmux select-pane  -t "$S" -T "${CS[$i]}"
  tmux select-layout -t "$S" "$LAYOUT"
done
tmux select-window -t "$S":0 >/dev/null 2>&1 || true

echo "Built '$S' with ${#CS[@]} panes in $((wn+1)) window(s): ${CS[*]}"
echo "Attach:  tmux attach -t $S"
echo "Detach:  Ctrl-b d   |  switch panes: Ctrl-b <arrow>   |  switch windows: Ctrl-b <n>   |  key to inner claude: Ctrl-b Ctrl-b <key>"
