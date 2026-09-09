#!/bin/bash
# kali-vpn.sh [se|za] - Kali container with ALL egress via Mullvad (gluetun sidecar)
#   se = Sweden      (default; sidecar container: gluetun)
#   za = South Africa (sidecar container: gluetun-za)
# Credentials: ~/.config/mullvad-gluetun.key + .addr (shared by both sidecars)
set -euo pipefail

KEY_FILE="$HOME/.config/mullvad-gluetun.key"
ADDR_FILE="$HOME/.config/mullvad-gluetun.addr"
LOC="${1:-se}"

case "$LOC" in
  se) NAME=gluetun;    COUNTRY="Sweden" ;;
  za) NAME=gluetun-za; COUNTRY="South Africa" ;;
  *)  echo "usage: $(basename "$0") [se|za]"; exit 1 ;;
esac

if [ ! -s "$KEY_FILE" ] || [ ! -s "$ADDR_FILE" ]; then
  echo "Missing $KEY_FILE or $ADDR_FILE"
  exit 1
fi

# start (or reuse) the VPN sidecar for this location
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --cap-add NET_ADMIN --restart unless-stopped \
    -v "${NAME}-data:/gluetun" \
    -e VPN_SERVICE_PROVIDER=mullvad -e VPN_TYPE=wireguard \
    -e WIREGUARD_PRIVATE_KEY="$(cat "$KEY_FILE")" \
    -e WIREGUARD_ADDRESSES="$(cat "$ADDR_FILE")" \
    -e "SERVER_COUNTRIES=$COUNTRY" \
    qmcgaw/gluetun >/dev/null
fi

echo "Waiting for tunnel ($COUNTRY)..."
for i in $(seq 1 45); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)" = healthy ] && break
  sleep 2
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)" != healthy ]; then
  echo "$NAME unhealthy - last logs:"; docker logs --tail 25 "$NAME"; exit 1
fi
echo "VPN up: $(docker run --rm --network=container:$NAME alpine:latest sh -c 'apk add -q curl >/dev/null 2>&1; curl -s --max-time 8 https://am.i.mullvad.net/ip' 2>/dev/null)"

# Kali shares the sidecar's netns: all traffic exits via Mullvad.
# If the tunnel dies, gluetun's kill switch blocks egress (no host-IP leak).
exec docker run --rm -it --user 1000 \
  --network=container:"$NAME" \
  -v "$HOME/communitytools/projects/pentest:/workspace" \
  -w /workspace \
  kali-claude:latest \
  bash -c 'source /workspace/.env.deepinfra && export CLAUDE_CODE_TMPDIR=/tmp/cr && mkdir -p /tmp/cr && claude --dangerously-skip-permissions'
