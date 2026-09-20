#!/usr/bin/env bash
# kali-eng.sh <tag> "<kickoff-command>" [country]
# Register and launch a crash/reboot-resilient pentest engagement.
#
#   kali-eng.sh acme-osint "/osint acme.example"
#   kali-eng.sh acme-full  "/pentest-engagement acme.example" "Sweden"
#
# Each engagement gets a pinned claude session id, a persisted ~/.claude on the host,
# and an entry in the compose stack (auto-restart + auto-resume, brought up on boot by
# the pentest-stack systemd unit). See /root/pentest-stack/.
set -euo pipefail

TAG="${1:?usage: kali-eng.sh <tag> \"<kickoff>\" [country]}"
KICKOFF="${2:?usage: kali-eng.sh <tag> \"<kickoff>\" [country]}"
COUNTRY="${FLEET_COUNTRY:-${3:-South Africa}}"
[[ "$TAG" =~ ^[a-zA-Z0-9_.-]+$ ]] || { echo "tag must match [a-zA-Z0-9_.-]"; exit 1; }

STACK=/root/pentest-stack
# VPN sidecar for this engagement's egress. FLEET_GLUETUN env override wins (fleet
# runner sets it after its egress preflight), else the flag, else the SE sidecar —
# gluetun-za (Johannesburg) has been dark since Sep 16-17; `gluetun` (Sweden) is live.
GLUETUN="${FLEET_GLUETUN:-gluetun}"
CWD=/workspace               # skills load from the ancestor projects/pentest/.claude
STATE="/root/kali-state/${TAG}/claude"
ENVF="$STACK/engagements/${TAG}.env"

if [ -f "$ENVF" ]; then
  echo "[kali-eng] engagement '$TAG' already registered ($ENVF) — reusing its pinned session."
  SESSION_ID=$(bash -c "set -a; source '$ENVF'; echo \$SESSION_ID")
else
  SESSION_ID=$(cat /proc/sys/kernel/random/uuid)
  mkdir -p "$STACK/engagements" "$STATE"
  chown -R 1000:1000 "/root/kali-state/${TAG}"
  # values are shell-quoted because the registry file is `source`d by render/up/watchdog
  cat > "$ENVF" <<EOF
TAG=$(printf %q "$TAG")
SESSION_ID=$(printf %q "$SESSION_ID")
KICKOFF=$(printf %q "$KICKOFF")
CWD=$(printf %q "$CWD")
GLUETUN=$(printf %q "$GLUETUN")
COUNTRY=$(printf %q "$COUNTRY")
EOF
  echo "[kali-eng] registered '$TAG' (session $SESSION_ID)"
fi

"$STACK/up.sh"

# Refresh the all-engagements tmux monitor so this one gets a pane. --add is
# safe while a client is attached (no kill-session); fall back to the old
# attached-guard behavior only if the subcommand is unavailable.
MON="$(dirname "$(readlink -f "$0")")/kali-mon.sh"
if [ -x "$MON" ]; then
  if grep -q -- '--add' "$MON"; then
    "$MON" --add "eng-${TAG}" >/dev/null 2>&1 \
      && echo "[kali-eng] monitor pane added — tmux attach -t pentest"
  elif [ -z "$(tmux list-clients -t pentest 2>/dev/null)" ]; then
    "$MON" >/dev/null 2>&1 && echo "[kali-eng] monitor refreshed — tmux attach -t pentest"
  else
    echo "[kali-eng] monitor 'pentest' is attached — run 'bash $MON' to add this engagement's pane."
  fi
fi

echo "[kali-eng] '$TAG' is up. Observe/interact with:"
echo "    docker exec -it eng-${TAG} tmux attach -t eng      (detach: Ctrl-b then d)"
echo "    docker logs -f eng-${TAG}"
