#!/usr/bin/env bash
# ipatool-mass.sh — batch-run ipa-pipeline.sh over a list of bundle ids, then index
# the results for agent-assisted review. Resumable and bounded-parallel; the same
# shape as apk-farm.sh (skip-by-anchor, per-app log, farm-style index).
#
# Usage:
#   ./ipatool-mass.sh bundle-ids.txt [out-root] [parallelism]
#
# bundle-ids.txt: one bundle id per line; blank lines and #comments ignored.
# Inherits ipa-pipeline.sh env (APPLE_ID / APPLE_PASSWORD or a prior `ipatool auth login`).
# STATIC-ONLY by design: App Store IPAs are FairPlay-encrypted; decryption stays a
# manual jailbroken-device step (see skills/mobile-app-farm/reference/acquisition.md).
# Only run against applications you are authorized to test.
set -euo pipefail

LIST="${1:?usage: ipatool-mass.sh bundle-ids.txt [out-root] [parallelism]}"
ROOT="${2:-./engagement-ios}"
JOBS="${3:-2}"
HERE="$(dirname "$(readlink -f "$0")")"
PIPE="$HERE/ipa-pipeline.sh"
[[ -x "$PIPE" ]] || { echo "ipa-pipeline.sh not found next to ipatool-mass.sh" >&2; exit 1; }
command -v ipatool >/dev/null 2>&1 || { echo "[!] ipatool not found on PATH" >&2; exit 2; }
mkdir -p "$ROOT"

# de-duplicate while preserving order (a repeated id would otherwise re-run or
# double-index; apk-farm tolerates it because its skip-anchor makes the rerun a
# no-op, but the INDEX should carry one row per app)
mapfile -t BIDS < <(grep -vE '^\s*(#|$)' "$LIST" | awk '{print $1}' | awk '!seen[$0]++')
echo "[*] ${#BIDS[@]} bundle id(s), parallelism=$JOBS, out=$ROOT"

for bid in "${BIDS[@]}"; do
  if [[ -f "$ROOT/$bid/ipa.sha256" ]]; then
    echo "[=] skip $bid (already acquired: $(cut -d' ' -f1 "$ROOT/$bid/ipa.sha256"))"
    continue
  fi
  # throttle to $JOBS concurrent pipelines
  while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
  ( "$PIPE" "$bid" "$ROOT/$bid" >"$ROOT/$bid.log" 2>&1 && echo "[+] done $bid" \
      || echo "[!] FAILED $bid (see $ROOT/$bid.log)" ) &
done
wait
echo "[*] all pipelines finished"

# --- Aggregate a machine-readable index for the agent -------------------------
python3 - "$ROOT" "${BIDS[@]}" <<'PY' > "$ROOT/ipa-index.json"
import json, os, re, sys
root, bids = sys.argv[1], sys.argv[2:]
out = []
for bid in bids:
    d = os.path.join(root, bid)
    rec = {"bundle_id": bid, "acquired": os.path.isfile(os.path.join(d, "ipa.sha256"))}
    try: rec["sha256"] = open(os.path.join(d, "ipa.sha256")).read().split()[0]
    except Exception: rec["sha256"] = None
    art = os.path.join(d, "artifact.json")
    if os.path.isfile(art):
        try:
            j = json.load(open(art))
            rec["version"] = j.get("version")
            rec["format"] = j.get("format")
        except Exception: rec["format"] = "unparseable"
    tri = os.path.join(d, "triage.md")
    rec["endpoints"] = len(re.findall(r'https?://', open(tri).read())) if os.path.isfile(tri) else 0
    out.append(rec)
json.dump({"root": root, "count": len(out), "apps": out}, sys.stdout, indent=2)
PY
echo "[+] index: $ROOT/ipa-index.json"
echo "[+] Point the agent at $ROOT/<bundle-id>/{unzipped,triage.md,artifact.json}"
echo "[i] FairPlay: the Mach-O in each Payload/*.app is still encrypted — decrypt on a"
echo "    jailbroken device (bagbak / frida-ios-dump) before code analysis."
