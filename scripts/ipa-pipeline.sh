#!/usr/bin/env bash
# ipa-pipeline.sh — acquire an iOS IPA and extract its STATIC attack surface
# (Info.plist, entitlements, strings, embedded URLs). App Store binaries are FairPlay-
# encrypted; decrypting the Mach-O for full analysis is a manual step (see notes below).
#
# Usage:
#   ./ipa-pipeline.sh com.example.bundleid [output-dir]
#
# Optional env:
#   APPLE_ID / APPLE_PASSWORD   — ipatool auth (or run `ipatool auth login` once beforehand)
#
# Only run against applications you are authorized to test.
set -euo pipefail

BID="${1:?usage: ipa-pipeline.sh <bundle.id> [output-dir]}"
OUT="${2:-./engagement/${BID}}"
mkdir -p "$OUT"
command -v ipatool >/dev/null 2>&1 || { echo "[!] ipatool not found on PATH" >&2; exit 1; }

if [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" ]]; then
  ipatool auth login -e "$APPLE_ID" -p "$APPLE_PASSWORD" --non-interactive >/dev/null 2>&1 || true
fi

echo "[*] Downloading IPA for ${BID} via ipatool..."
ipatool download -b "$BID" -o "$OUT/app.ipa" --non-interactive
shasum -a 256 "$OUT/app.ipa" 2>/dev/null | tee "$OUT/ipa.sha256" || sha256sum "$OUT/app.ipa" | tee "$OUT/ipa.sha256"

# --- Evidence record (artifact.json) ------------------------------------------
# Same artifact/v1 provenance contract as apk-pipeline.sh: identity + content-based
# format + acquisition source + timestamp + tool versions. The flat ipa.sha256
# anchor stays authoritative for existing consumers; this is the additive record.
IPA_SHA="$(cut -d' ' -f1 "$OUT/ipa.sha256")"
IPA_FMT="unknown"
if command -v python3 >/dev/null 2>&1; then
  _af="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../tools/artifact_format.py"
  [[ -f "$_af" ]] && IPA_FMT="$(python3 "$_af" "$OUT/app.ipa" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("format","unknown"))' 2>/dev/null)"
fi
[[ -n "$IPA_FMT" ]] || IPA_FMT="unknown"
ACQ_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
IPA_VER="$(unzip -p "$OUT/app.ipa" "Payload/*.app/Info.plist" 2>/dev/null | plutil -extract CFBundleShortVersionString raw - 2>/dev/null || true)"
IPATOOL_VER="$(ipatool version 2>/dev/null | head -1 || true)"
python3 - "$OUT/artifact.json" "$BID" "$IPA_SHA" "$IPA_VER" "$IPA_FMT" "ipatool" "$ACQ_AT" "$IPATOOL_VER" <<'PY'
import json, sys
out, bid, sha, ver, fmt, source, acq_at, ipatool_ver = sys.argv[1:9]
json.dump({
  "schema": "artifact/v1",
  "bundle_id": bid,
  "sha256": sha,
  "version": ver or None,
  "format": fmt,
  "source": source,
  "acquired_at": acq_at,
  "tool_versions": {"ipatool": ipatool_ver or None},
  "parent_sha256s": [],
}, open(out, "w"), indent=2)
PY
echo "[+] Evidence: $OUT/artifact.json"

echo "[*] Unpacking + static surface..."
unzip -q -o "$OUT/app.ipa" -d "$OUT/unzipped"
APPDIR="$(find "$OUT/unzipped/Payload" -maxdepth 1 -name '*.app' | head -1)"
{
  echo "## Bundle: $BID"
  echo "## SHA256: $(cut -d' ' -f1 "$OUT/ipa.sha256")"
  echo
  echo "### Info.plist (key config)"
  plutil -p "$APPDIR/Info.plist" 2>/dev/null | grep -iE 'BundleIdentifier|Version|URLScheme|Transport|Queries|Background' || \
    strings "$APPDIR/Info.plist" 2>/dev/null | head -40
  echo
  echo "### Entitlements"
  codesign -d --entitlements :- "$APPDIR" 2>/dev/null | strings | grep -iE 'keychain|app-groups|associated-domains|get-task-allow' || echo '(codesign unavailable on this host)'
  echo
  echo "### URLs / endpoints (strings over the app bundle)"
  strings -a "$APPDIR"/* 2>/dev/null | grep -oE 'https?://[^"'"'"' )>]+' | sort -u | head -n 200 || true
} > "$OUT/triage.md"

echo "[+] Static triage: $OUT/triage.md"
echo
echo "[i] FairPlay note: the Mach-O binary is encrypted. For full static/dynamic analysis,"
echo "    decrypt on a JAILBROKEN device with bagbak or frida-ios-dump, then treat the"
echo "    decrypted .ipa like any other bundle. That step is intentionally manual."
