#!/bin/bash
# kali-vpn.sh [se|za] - Kali container with ALL egress via Mullvad (gluetun sidecar)
#   se = Sweden      (default; sidecar container: gluetun)
#   za = South Africa (sidecar container: gluetun-za)
# Credentials: ~/.config/mullvad-gluetun.key + .addr (shared by both sidecars)
set -euo pipefail

KEY_FILE="$HOME/.config/mullvad-gluetun.key"
ADDR_FILE="$HOME/.config/mullvad-gluetun.addr"
LOC="se"
if [ $# -gt 0 ]; then
  case "$1" in
    se|za) LOC="$1"; shift ;;
    -*) :;;  # no location given - first arg is a flag, keep the se default
    *) echo "usage: $(basename "$0") [se|za] [-s NAME] [-r]"; exit 1 ;;
  esac
fi

case "$LOC" in
  se) NAME=gluetun;    COUNTRY="Sweden" ;;
  za) NAME=gluetun-za; COUNTRY="South Africa" ;;
esac

if [ ! -s "$KEY_FILE" ] || [ ! -s "$ADDR_FILE" ]; then
  echo "Missing $KEY_FILE or $ADDR_FILE"
  exit 1
fi

start_sidecar() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --cap-add NET_ADMIN --restart unless-stopped \
    -v "${NAME}-data:/gluetun" \
    -e VPN_SERVICE_PROVIDER=mullvad -e VPN_TYPE=wireguard \
    -e WIREGUARD_PRIVATE_KEY="$(cat "$KEY_FILE")" \
    -e WIREGUARD_ADDRESSES="$(cat "$ADDR_FILE")" \
    -e "SERVER_COUNTRIES=$COUNTRY" \
    qmcgaw/gluetun >/dev/null
}

wait_healthy() {
  for i in $(seq 1 45); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)" = healthy ] && return 0
    sleep 2
  done
  return 1
}

# start (or reuse) the VPN sidecar for this location
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  start_sidecar
fi

# A running-but-unhealthy sidecar (e.g. stale image with outdated server list)
# never recovers on its own - recreate it once with a fresh image before giving up.
if ! wait_healthy; then
  echo "$NAME unhealthy - recreating with fresh image..."
  docker pull -q qmcgaw/gluetun >/dev/null
  start_sidecar
  if ! wait_healthy; then
    echo "$NAME unhealthy - last logs:"; docker logs --tail 25 "$NAME"; exit 1
  fi
fi
echo "VPN up: $(docker run --rm --network=container:$NAME alpine:latest sh -c 'apk add -q curl >/dev/null 2>&1; curl -s --max-time 8 https://am.i.mullvad.net/ip' 2>/dev/null)"

# Optional flags (must come after the location argument):
#   -s/--session NAME   mount host dir ~/kali-sessions/NAME as the container's
#                       $HOME, so Claude transcripts persist across containers
#   -r/--resume         pass --continue to claude (resume newest session there)
SESS=""
RESUME=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s|--session) SESS="$2"; shift 2 ;;
    -r|--resume)  RESUME="--continue"; shift ;;
    *) echo "unknown flag: $1 (usage: $(basename "$0") [se|za] [-s NAME] [-r])" >&2; exit 1 ;;
  esac
done
HOME_MOUNT=()
if [ -n "$SESS" ]; then
  SESS_DIR="$HOME/kali-sessions/$SESS"
  mkdir -p "$SESS_DIR"
  chown 1000:1000 "$SESS_DIR" 2>/dev/null || true
  HOME_MOUNT=(-v "$SESS_DIR:/home/claude")
fi

# ENGAGEMENT KICKOFF TEMPLATE (paste as the first claude input after launch;
# use -s <tag> so transcripts + subagents persist in ~/kali-sessions/<tag>):
#   Use the pentest-engagement skill: full penetration engagement on example.com
#   (WEB). Run as a lean coordinator per the coordination skill: no experiment or
#   scan tool calls inline; orchestrate phases by spawning 3-5 background executors
#   on independent surfaces as ONE message of parallel Agent blocks; collect via
#   TaskOutput; sole writer of the ledgers; validate each candidate on fresh blind
#   agents; command output and screenshots go to engagement artifact files referenced
#   by path. Where the Workflow tool is unavailable, spawn the coordinator as a
#   background subagent instead — never run phases inline in the parent.
#
# Kali shares the sidecar's netns: all traffic exits via Mullvad.
# If the tunnel dies, gluetun's kill switch blocks egress (no host-IP leak).
# Memory cap: a ballooning claude session dies at 6G alone instead of OOM-ing the box.
exec docker run --rm -it --user 1000 \
  --network=container:"$NAME" \
  --memory "${KALI_MEM_LIMIT:-6g}" --memory-swap "${KALI_MEM_LIMIT:-6g}" \
  -v "$HOME/communitytools/projects/pentest:/workspace" \
  "${HOME_MOUNT[@]}" \
  -w /workspace \
  kali-claude:latest \
  bash -c 'source /workspace/.env.deepinfra && export CLAUDE_CODE_TMPDIR=/tmp/cr && mkdir -p /tmp/cr && claude '"$RESUME"' --dangerously-skip-permissions --disallowedTools "EnterPlanMode,EnterWorktree,ExitPlanMode,ExitWorktree,CronList,ListAgents,ScheduleWakeup,TaskList,TaskStop,Workflow"'
