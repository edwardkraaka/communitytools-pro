#!/usr/bin/env bash
# fleet-deploy-check.sh — run before ANY fleet-code deploy (runner bounce, entrypoint
# edit, render change). Green = safe to bounce/relaunch. This gate exists because four
# same-family set-e/seeding bugs shipped on Sep 23 by editing + eyeballing alone.
set -uo pipefail
cd /root/pentest-stack
echo "[deploy-check] bash -n syntax sweep"
for f in fleet-lib.sh fleet-runner.sh fleet-status.sh fleet-metrics.sh \
         render-compose.sh kali-resume-entrypoint.sh build-eng.sh up.sh; do
  bash -n "$f" 2>&1 | sed "s|^|  $f: |" && echo "  ok $f" || exit 1
done
echo "[deploy-check] stack-vs-repo twin drift (BOX_IP line expected to differ)"
for f in fleet-lib.sh fleet-runner.sh fleet-status.sh fleet-metrics.sh kali-resume-entrypoint.sh; do
  if ! diff -q "$f" "/root/communitytools/scripts/$f" >/dev/null 2>&1; then
    d=$(diff "$f" "/root/communitytools/scripts/$f" \
        | grep -vE 'BOX_IP|# Deployed at|engagement stack|tracked copy|^---$|^[0-9,]+[acd][0-9,]+$|^<|^>' | wc -l)
    [ "$d" = 0 ] && echo "  ok $f (sanctioned diffs only)" || { echo "  DRIFT $f — unsynced twin ($d lines)"; exit 1; }
  else
    echo "  ok $f identical"
  fi
done
echo "[deploy-check] gate twins (build-eng / deploy-check must match stack byte-for-byte — no sanctioned diffs)"
for f in build-eng.sh fleet-deploy-check.sh; do
  cmp -s "$f" "/root/communitytools/scripts/$f" \
    && echo "  ok $f identical" || { echo "  DRIFT $f — unsynced twin"; exit 1; }
done
echo "[deploy-check] contract selftest"
bash /root/pentest-stack/fleet-selftest.sh || exit 1
echo "[deploy-check] ALL GREEN — safe to deploy"
