#!/usr/bin/env bash
# mobsf-up.sh — launch the MobSF scanner container for the mobile-app-farm pipeline.
#
# Runs MobSF pinned to a tested digest, bound ONLY to the docker0 bridge IP (default
# 172.17.0.1): reachable from the host and from plain `docker run` hops on the default
# bridge, never from the public internet. This host's docker0 binding IS the access
# control for the web UI (which is unauthenticated) — do not widen it.
#
# API key resolution, first match wins:
#   1. "$1"                       — explicit argument
#   2. $MOBSF_API_KEY             — environment
#   3. MOBSF_KEY=… in ./.env      — the durable home (name apk-pipeline.sh reads)
# If none is found a key is generated for this run and — when ./.env already exists —
# written there (blank MOBSF_KEY=/MOBSF_URL= lines are filled, missing ones appended),
# so REST always requires auth and re-runs keep the same key.
#
# Env overrides: MOBSF_IMAGE (digest), DOCK0_IP, MOBSF_PORT (default 8000)
set -euo pipefail
cd "$(dirname "$0")/.."

MOBSF_IMAGE="${MOBSF_IMAGE:-opensecurity/mobile-security-framework-mobsf@sha256:83bc8aaf940d66344b7c10ebc12e921086bec43369a8259582e6dc258f2924b0}"  # 4.5.4 — pin a tested digest; :latest moves
MOBSF_PORT="${MOBSF_PORT:-8000}"
DOCK0_IP="${DOCK0_IP:-$(ip -4 addr show docker0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)}"
DOCK0_IP="${DOCK0_IP:-172.17.0.1}"

KEY="${1:-${MOBSF_API_KEY:-}}"
KEY_SRC="argument/environment"
if [[ -z "$KEY" && -f .env ]]; then
  KEY="$(grep -E '^MOBSF_KEY=' .env | tail -1 | cut -d= -f2-)"
  KEY="${KEY%\"}"; KEY="${KEY#\"}"   # strip surrounding quotes if the .env used them
  [[ -n "$KEY" ]] && KEY_SRC=".env"
fi
if [[ -z "$KEY" ]]; then
  KEY="$(openssl rand -hex 32)"
  KEY_SRC="generated"
  echo "[mobsf-up] no API key found — generated one: MOBSF_KEY=$KEY" >&2
  if [[ -f .env ]]; then
    grep -q '^MOBSF_KEY=$' .env && sed -i "s|^MOBSF_KEY=.*|MOBSF_KEY=$KEY|" .env \
      || printf 'MOBSF_KEY=%s\n' "$KEY" >> .env
    grep -q '^MOBSF_URL=$' .env && sed -i "s|^MOBSF_URL=.*|MOBSF_URL=http://${DOCK0_IP}:${MOBSF_PORT}|" .env \
      || grep -q '^MOBSF_URL=' .env || printf 'MOBSF_URL=http://%s:%s\n' "$DOCK0_IP" "$MOBSF_PORT" >> .env
    echo "[mobsf-up] wrote MOBSF_KEY (+ MOBSF_URL) into .env — re-runs now reuse it." >&2
  else
    echo "[mobsf-up] no .env yet — record the key somewhere durable or pass it as \$1 next" >&2
    echo "           time, or a re-run will mint a NEW key and old reports become unreachable." >&2
  fi
fi

docker volume create mobsf-data >/dev/null
# Fresh docker volumes mount root-owned, but the container runs as uid 9901 (mobsf)
# whose HOME it must mkdir/write — without this chown MobSF dies at startup with
# "TypeError: ... not NoneType" from get_mobsf_home (one-time, ~1s on an empty volume).
if [ "$(docker run --rm -v mobsf-data:/hm --entrypoint sh opensecurity/mobile-security-framework-mobsf:latest -c 'stat -c %u /hm' 2>/dev/null)" != "9901" ]; then
  docker run --rm --user 0 -v mobsf-data:/hm --entrypoint sh opensecurity/mobile-security-framework-mobsf:latest \
    -c 'chown -R 9901:9901 /hm' || echo "[mobsf-up] chown failed — MobSF may fail to start" >&2
fi
docker rm -f mobsf >/dev/null 2>&1 || true
docker run -d --name mobsf \
  --restart unless-stopped \
  -p "${DOCK0_IP}:${MOBSF_PORT}:8000" \
  -v mobsf-data:/home/mobsf/.MobSF \
  -e MOBSF_API_KEY="$KEY" \
  "$MOBSF_IMAGE" >/dev/null

echo "[mobsf-up] waiting for the REST API on ${DOCK0_IP}:${MOBSF_PORT} ..."
up=""
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "X-Mobsf-Api-Key: $KEY" \
    "http://${DOCK0_IP}:${MOBSF_PORT}/api/v1/scans" || true)"
  if [[ "$code" == "200" ]]; then up=1; break; fi
  sleep 2
done
if [[ -z "$up" ]]; then
  echo "[!] REST API did not answer within 60s — check: docker logs mobsf" >&2
  exit 4
fi

echo "[+] MobSF is up:    http://${DOCK0_IP}:${MOBSF_PORT}   (${MOBSF_IMAGE})"
echo "    data:           named volume mobsf-data (recent scans survive re-creation)"
echo "    restart policy: unless-stopped (dedicated container, not compose-integrated;"
echo "                    render-compose output must stay idempotent)"
echo "    pipeline env:   MOBSF_URL=http://${DOCK0_IP}:${MOBSF_PORT}"
if [[ "$KEY_SRC" == "generated" ]]; then
  echo "                    MOBSF_KEY=$KEY   <- generated this run, record it"
else
  echo "                    MOBSF_KEY=(from ${KEY_SRC})"
fi
