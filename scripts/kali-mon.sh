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
# Inside:  switch panes = Ctrl-b <arrow> ;  detach = Ctrl-b d
# To send a key to the INNER claude (nested tmux), press the prefix TWICE: Ctrl-b Ctrl-b <key>
set -euo pipefail
S=pentest
MAXPANES=4

panes_of_session() { tmux list-panes -t "$S" -F "$1" 2>/dev/null; }

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

  # already present? (match pane by title — pentest session panes only)
  if panes_of_session '#{pane_title}' | grep -qxF "$c"; then
    echo "$c already has a pane"
    return
  fi

  # first window with fewer than MAXPANES panes, else a new window
  target=""
  for win in $(tmux list-windows -t "$S" -F '#{window_index}'); do
    n=$(panes_of_window "$S:$win" | wc -l)
    if [ "$n" -lt "$MAXPANES" ]; then target="$S:$(echo "$win" | cut -d: -f1)"; break; fi
  done
  if [ -z "$target" ]; then
    target="$S:$(tmux new-window -t "$S" -n fleet -P -F '#{window_index}')"
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
    present=$(tmux list-panes -t "$S" -a -F '#{pane_title}' 2>/dev/null | grep -cx "$c" || true)
    [ "${present:-0}" -eq 0 ] && add_pane "$c"
  done < <(docker ps --filter name=eng- --filter status=running --format '{{.Names}}' | sort)
  # remove panes whose container is gone
  while read -r c; do
    [ -z "$c" ] && continue
    if ! docker ps -a --filter "name=^${c}$" --format '{{.Names}}' | grep -q .; then
      remove_pane "$c"
    fi
  done < <(tmux list-panes -t "$S" -a -F '#{pane_title}' 2>/dev/null | sort -u)
  # drop the session entirely if no panes remain
  if [ -z "$(tmux list-panes -t "$S" -a -F '#{pane_id}' 2>/dev/null)" ]; then
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

mapfile -t CS < <(docker ps --filter name=eng- --filter status=running --format '{{.Names}}' | sort)
[ "${#CS[@]}" -gt 0 ] || { echo "no eng-* containers running"; exit 1; }

tmux kill-session -t "$S" 2>/dev/null || true
tmux new-session -d -s "$S" -x 250 -y 62 "exec docker exec -it ${CS[0]} tmux attach -t eng"
tmux select-pane  -t "$S" -T "${CS[0]}"
for ((i=1; i<${#CS[@]}; i++)); do
  tmux split-window -t "$S" "exec docker exec -it ${CS[$i]} tmux attach -t eng"
  tmux select-pane  -t "$S" -T "${CS[$i]}"
  tmux select-layout -t "$S" "$LAYOUT"
done
tmux select-layout -t "$S" "$LAYOUT"
set_session_opts

echo "Built '$S' with ${#CS[@]} panes: ${CS[*]}"
echo "Attach:  tmux attach -t $S"
echo "Detach:  Ctrl-b d   |  switch panes: Ctrl-b <arrow>   |  key to inner claude: Ctrl-b Ctrl-b <key>"
