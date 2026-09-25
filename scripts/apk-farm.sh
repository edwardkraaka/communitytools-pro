#!/usr/bin/env bash
# apk-farm.sh — batch-run apk-pipeline.sh over a list of packages, then index the results
# for agent-assisted review. Resumable and bounded-parallel.
#
# Usage:
#   ./apk-farm.sh packages.txt [out-root] [parallelism]
#
# packages.txt: one package name per line; blank lines and #comments ignored.
# Inherits the same optional env as apk-pipeline.sh (GOOGLE_PLAY_*, MOBSF_URL/KEY, ...).
# Only run against applications you are authorized to test.
set -euo pipefail

LIST="${1:?usage: apk-farm.sh packages.txt [out-root] [parallelism]}"
ROOT="${2:-./engagement}"
JOBS="${3:-3}"
HERE="$(dirname "$(readlink -f "$0")")"
PIPE="$HERE/apk-pipeline.sh"
[[ -x "$PIPE" ]] || { echo "apk-pipeline.sh not found next to apk-farm.sh" >&2; exit 1; }
mkdir -p "$ROOT"

mapfile -t PKGS < <(grep -vE '^\s*(#|$)' "$LIST" | awk '{print $1}')
echo "[*] ${#PKGS[@]} package(s), parallelism=$JOBS, out=$ROOT"

for pkg in "${PKGS[@]}"; do
  if [[ -f "$ROOT/$pkg/apk.sha256" ]]; then
    echo "[=] skip $pkg (already acquired: $(cut -d' ' -f1 "$ROOT/$pkg/apk.sha256"))"
    continue
  fi
  # throttle to $JOBS concurrent pipelines
  while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
  ( "$PIPE" "$pkg" "$ROOT/$pkg" >"$ROOT/$pkg.log" 2>&1 && echo "[+] done $pkg" \
      || echo "[!] FAILED $pkg (see $ROOT/$pkg.log)" ) &
done
wait
echo "[*] all pipelines finished"

# --- Aggregate a machine-readable index for the agent -------------------------
python3 - "$ROOT" "${PKGS[@]}" <<'PY' > "$ROOT/farm-index.json"
import json, os, re, sys
root, pkgs = sys.argv[1], sys.argv[2:]
out = []
for pkg in pkgs:
    d = os.path.join(root, pkg)
    rec = {"package": pkg, "acquired": os.path.isfile(os.path.join(d, "apk.sha256"))}
    try: rec["sha256"] = open(os.path.join(d, "apk.sha256")).read().split()[0]
    except Exception: rec["sha256"] = None
    try: rec["version"] = open(os.path.join(d, "apk.version")).read().strip()
    except Exception: rec["version"] = None
    tri = os.path.join(d, "triage.md")
    rec["endpoints"] = len(re.findall(r'https?://', open(tri).read())) if os.path.isfile(tri) else 0
    mob = os.path.join(d, "mobsf-report.json")
    if os.path.isfile(mob):
        try:
            j = json.load(open(mob)); sev = j.get("appsec", {}) or {}
            rec["mobsf"] = {k: len(sev.get(k, [])) for k in ("high", "warning", "info", "secure") if k in sev}
        except Exception: rec["mobsf"] = "unparseable"
    out.append(rec)
json.dump({"root": root, "count": len(out), "apps": out}, sys.stdout, indent=2)
PY
echo "[+] index: $ROOT/farm-index.json"
echo "[+] Point the agent at $ROOT/<package>/{jadx/sources,apktool,triage.md,mobsf-report.json}"
