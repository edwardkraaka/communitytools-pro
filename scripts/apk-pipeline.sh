#!/usr/bin/env bash
# apk-pipeline.sh — acquire, normalize, decompile, and triage one Android app for
# agent-assisted source review. Built for the kali-claude container workflow.
#
# Usage:
#   ./apk-pipeline.sh com.example.app [output-dir]
#
# Optional env:
#   GOOGLE_PLAY_EMAIL / GOOGLE_PLAY_AAS_TOKEN  — use Google Play instead of APKPure
#   APKEEP_SOURCE     — override apkeep source (default: apk-pure; or google-play, f-droid)
#   APKEDITOR_JAR     — path to APKEditor.jar (default: /opt/APKEditor.jar) for split/XAPK merge
#   MOBSF_URL         — e.g. http://mobsf:8000  (enables MobSF static scan)
#   MOBSF_KEY         — MobSF API key
#
# Only run against applications you are authorized to test.
set -euo pipefail

PKG="${1:?usage: apk-pipeline.sh <package.name> [output-dir]}"
OUT="${2:-./engagement/${PKG}}"
APKEDITOR_JAR="${APKEDITOR_JAR:-/opt/APKEditor.jar}"
mkdir -p "$OUT/raw"
# apkeep's F-Droid source builds AND extracts its package index under $TMPDIR; the
# kali-claude image exports TMPDIR=/workspace/.tmp, which only exists under the fleet
# entrypoint (a dangling TMPDIR aborts at "Could not create temporary directory", and
# mktemp -d would trip over the same dangling dir). Fall back to /tmp — absolute and
# container-local, which both index steps handle — so plain `docker run` works.
if [ -n "${TMPDIR:-}" ] && [ ! -d "$TMPDIR" ]; then TMPDIR=/tmp; export TMPDIR; fi

have() { command -v "$1" >/dev/null 2>&1; }
for t in apkeep jadx apktool; do
  have "$t" || { echo "[!] '$t' not found on PATH — install it (see mobile-app-farm skill) or run this pipeline inside the kali-claude image" >&2; exit 2; }
done
have aapt || echo "[!] aapt not found — apk.version anchor will be empty" >&2

# --- Acquire ------------------------------------------------------------------
# Google Play (authenticated) is PREFERRED when creds are present: it serves the CURRENT
# build for a real device profile and can reach apps mirrors do not carry. APKPure is the
# credential-free default — fast, but may serve an OLDER build and misses unlisted/rare apps.
raw_has_artifact() {
  compgen -G "$OUT/raw/*.apk" >/dev/null || compgen -G "$OUT/raw/*.xapk" >/dev/null \
    || compgen -G "$OUT/raw/*.apkm" >/dev/null || compgen -G "$OUT/raw/*.apks" >/dev/null
}
gplay_fetch() {
  echo "[*] Acquiring ${PKG} via Google Play (authenticated, device=${GOOGLE_PLAY_DEVICE:-px_3a})..."
  apkeep -a "$PKG" -d google-play \
    -e "$GOOGLE_PLAY_EMAIL" -t "$GOOGLE_PLAY_AAS_TOKEN" \
    -o "device=${GOOGLE_PLAY_DEVICE:-px_3a},split_apk=1,include_additional_files=1" "$OUT/raw"
}
mirror_fetch() {
  local src="${APKEEP_SOURCE:-apk-pure}"
  echo "[*] Acquiring ${PKG} via apkeep (source: ${src}, no credentials)..."
  # apkeep's F-Droid index extraction is intermittently flaky upstream
  # (EFForg/apkeep#240 — "could not be extracted. Please try again"): retry a few
  # times; a download either lands in $OUT/raw or the attempts are exhausted.
  local attempt
  for attempt in 1 2 3 4 5; do
    apkeep -a "$PKG" -d "$src" "$OUT/raw" && return 0
    echo "[!] apkeep attempt ${attempt}/5 failed — retrying in ${attempt}0s..." >&2
    raw_has_artifact && return 0   # partial success (one split landed) is success
    sleep "${attempt}0"
  done
  return 1
}
if [[ -n "${GOOGLE_PLAY_EMAIL:-}" && -n "${GOOGLE_PLAY_AAS_TOKEN:-}" ]]; then
  gplay_fetch || true
  if ! raw_has_artifact; then
    if [[ "${APK_SOURCE_FALLBACK:-0}" == "1" ]]; then
      echo "[!] Google Play returned nothing — falling back to a mirror (may be an OLDER build)." >&2
      mirror_fetch || true
    else
      echo "[!] Google Play returned nothing. The account may not have acquired the app, or it is" >&2
      echo "    geo/device-restricted or paid. Free-install it once on that account, adjust" >&2
      echo "    GOOGLE_PLAY_DEVICE, or set APK_SOURCE_FALLBACK=1 to accept a mirror build." >&2
    fi
  fi
else
  mirror_fetch
fi

# --- Normalize (merge splits / XAPK / APKM → a single universal APK) ----------
shopt -s nullglob
bundles=( "$OUT"/raw/*.xapk "$OUT"/raw/*.apkm "$OUT"/raw/*.apks )
apks=( "$OUT"/raw/*.apk )
APK=""
# jadx resolves its input path AFTER chdir'ing to its install dir — hand every tool
# an absolute APK path so a relative OUT doesn't produce a silently-empty jadx tree.
abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
if (( ${#bundles[@]} > 0 )); then
  echo "[*] Split bundle detected (${bundles[0]##*/}) — merging to universal APK with APKEditor..."
  if [[ -f "$APKEDITOR_JAR" ]]; then
    java -jar "$APKEDITOR_JAR" m -i "${bundles[0]}" -o "$OUT/base.apk" -f >/dev/null
    APK="$OUT/base.apk"
  else
    echo "[!] APKEDITOR_JAR ($APKEDITOR_JAR) missing — cannot merge split bundle." >&2; exit 3
  fi
elif (( ${#apks[@]} > 1 )); then
  echo "[*] Multiple split APKs — merging directory to universal APK with APKEditor..."
  java -jar "$APKEDITOR_JAR" m -i "$OUT/raw" -o "$OUT/base.apk" -f >/dev/null
  APK="$OUT/base.apk"
elif (( ${#apks[@]} == 1 )); then
  APK="${apks[0]}"
else
  echo "[!] No APK/bundle found after download — aborting." >&2; exit 1
fi
APK="$(abs "$APK")"
echo "[+] Universal APK: $APK"
sha256sum "$APK" | tee "$OUT/apk.sha256"
aapt dump badging "$APK" 2>/dev/null | grep -oE "versionName='[^']*'" | head -1 > "$OUT/apk.version" || true

# --- Decompile ----------------------------------------------------------------
echo "[*] Decompile: resources / smali / manifest (apktool)..."
apktool d -q -f "$APK" -o "$OUT/apktool"
echo "[*] Decompile: Java/Kotlin source (jadx)..."
jadx --deobf -d "$OUT/jadx" "$APK" 2>"$OUT/jadx.errors.log" || \
  echo "[!] jadx exited non-zero — partial source may still be in $OUT/jadx"

# --- Triage summary -----------------------------------------------------------
echo "[*] Triage summary..."
{
  echo "## Package: $PKG"
  echo "## APK: $APK"
  echo "## Version: $(cat "$OUT/apk.version" 2>/dev/null)"
  echo "## SHA256: $(cut -d' ' -f1 "$OUT/apk.sha256")"
  echo
  echo "### Manifest permissions / exported components"
  { androguard axml "$APK" 2>/dev/null || cat "$OUT/apktool/AndroidManifest.xml" 2>/dev/null; } \
    | grep -Eo '(uses-permission[^>]*|android:exported="[^"]*"|android:name="[^"]*")' | sort -u | head -n 120 || true
  echo
  echo "### URLs / endpoints in decompiled source"
  rg -oNI 'https?://[^"'"'"' )>]+' "$OUT/jadx" 2>/dev/null | sort -u | head -n 200 || true
  echo
  echo "### Possible hardcoded secrets (heuristic — verify before reporting)"
  rg -n --no-heading -iE '(api[_-]?key|secret|token|password|bearer)\s*[=:]\s*"[^"]{8,}"' \
    "$OUT/jadx/sources" 2>/dev/null | head -n 80 || true
} > "$OUT/triage.md"
echo "[+] Triage: $OUT/triage.md"

# --- Optional MobSF static scan (REST) ----------------------------------------
if [[ -n "${MOBSF_URL:-}" ]]; then
  echo "[*] MobSF scan via ${MOBSF_URL}..."
  H="$(curl -s -X POST -H "X-Mobsf-Api-Key: ${MOBSF_KEY:-}" -F "file=@${APK}" "${MOBSF_URL}/api/v1/upload" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["hash"])' 2>/dev/null || true)"
  if [[ -n "$H" ]]; then
    curl -s -X POST -H "X-Mobsf-Api-Key: ${MOBSF_KEY:-}" --data "hash=${H}" "${MOBSF_URL}/api/v1/scan" >/dev/null
    curl -s -X POST -H "X-Mobsf-Api-Key: ${MOBSF_KEY:-}" --data "hash=${H}" "${MOBSF_URL}/api/v1/report_json" > "$OUT/mobsf-report.json"
    echo "[+] MobSF report: $OUT/mobsf-report.json (hash: $H)"
  else
    echo "[!] MobSF upload failed — skipping." >&2
  fi
fi

echo
echo "[+] Done. Point the agent at:"
echo "      $OUT/jadx/sources       — Java/Kotlin source"
echo "      $OUT/apktool            — manifest, resources, smali"
echo "      $OUT/triage.md          — quick triage summary"
[[ -f "$OUT/mobsf-report.json" ]] && echo "      $OUT/mobsf-report.json  — MobSF findings"
exit 0
