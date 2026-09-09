#!/usr/bin/env bash
# kali-mon.sh — one host tmux session ("pentest") with a pane per running eng-*
# engagement, each attached to that container's live claude TUI.
#
#   bash kali-mon.sh          # (re)build the monitor
#   tmux attach -t pentest    # then view it
#
# Inside:  switch panes = Ctrl-b <arrow> ;  detach = Ctrl-b d
# To send a key to the INNER claude (nested tmux), press the prefix TWICE: Ctrl-b Ctrl-b <key>
set -euo pipefail
S=pentest
LAYOUT="${1:-even-vertical}"   # even-vertical (stacked, full width) | tiled (grid)

mapfile -t CS < <(docker ps --filter name=eng- --format '{{.Names}}' | sort)
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
tmux set -t "$S" pane-border-status top >/dev/null 2>&1 || true
tmux set -t "$S" mouse on >/dev/null 2>&1 || true

echo "Built '$S' with ${#CS[@]} panes: ${CS[*]}"
echo "Attach:  tmux attach -t $S"
echo "Detach:  Ctrl-b d   |  switch panes: Ctrl-b <arrow>   |  key to inner claude: Ctrl-b Ctrl-b <key>"
