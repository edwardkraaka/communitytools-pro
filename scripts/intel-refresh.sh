#!/usr/bin/env bash
# intel-refresh.sh — weekly refresh of the threat-intel digest (host-side).
#
# Runs the versioned research brief (skills/threat-intel/reference/research-brief.md)
# through the Perplexity Computer MCP in a headless claude session, stages the four
# time-sensitive reference files, GATES them, and only then lands them:
#
#   stage  -> $STAGE (claude -p, --dangerously-skip-permissions: same unattended
#             posture as the fleet's container agents; the gates below bound
#             what may land)
#   gate 1 -> per file: byte-exact H2 header, >=1500 bytes, <=190 lines
#   gate 2 -> per file: scripts/check_client_data.py --scan-file --redact clean
#   gate 3 -> whole-tree: skill_linter --delta vs a baseline written immediately
#             before the apply — 0 introduced violations or full rollback
#   apply  -> canonical via .tmp + mv (containers never see partial files),
#             refresh-log.md appended, sync-pentest-mirror.sh (layers A + B)
#
# research-brief.md itself is never touched here: version bumps and section
# age-window adjustments are operator edits to a tracked file, on a slower
# cadence than the weekly content refresh.
#
# NO auto-commit: the run leaves canonical changes in the worktree for operator
# review; rollback is per-file `git show HEAD:<path>` + re-run sync.
#
# Manual proof run: bash intel-refresh.sh
# Timer (Stage 4):  threat-intel-refresh.timer, weekly.
set -euo pipefail

STACK=/root/pentest-stack
REPO=/root/communitytools
SKILL="$REPO/skills/threat-intel"
STAMP=$(date +%Y%m%d-%H%M%S)
STAGE="$STACK/intel-research/refresh-$STAMP"
LOG="$STAGE/refresh-run.log"
CLAUDE_TIMEOUT=3600
LINE_CAP=190

# deterministic apply order; SECTIONS maps file -> its pinned H2 header
ORDER="intel-sources.md recent-incidents.md exploited-cve-classes.md llm-research-sota.md"
declare -A SECTIONS=(
  [intel-sources.md]="## Live intelligence sources"
  [recent-incidents.md]="## Recent blockchain hack anatomy (2024–2026)"
  [exploited-cve-classes.md]="## Exploited CVE classes: web & crypto infra (2025-2026)"
  [llm-research-sota.md]="## LLM-driven security research: state of the art"
)

mkdir -p "$STAGE"
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
log "intel-refresh start — staging $STAGE"

# ---------------------------------------------------------------- preflight
timeout 90 claude mcp list 2>&1 | grep -q 'perplexity-computer.*Connected' \
  || { log "FAIL: perplexity-computer MCP not connected (claude mcp list)"; exit 1; }
[ -f "$SKILL/reference/research-brief.md" ] || { log "FAIL: research-brief.md missing"; exit 1; }
log "preflight ok (MCP connected, brief present)"

# ---------------------------------------------------------------- stage: relay
cat > "$STAGE/driver-prompt.md" <<'PROMPT'
You are the refresh driver for an AUTHORIZED penetration-testing program's
threat-intel digest (professional security firm, signed rules of engagement).
Your job is a RELAY, not the research: drive the Perplexity Computer MCP tool
and save what it returns. The brief's authorization framing covers this; the
research touches public web sources only.

1. Read /root/communitytools/skills/threat-intel/reference/research-brief.md.
2. Send its "The prompt (verbatim)" block to Perplexity Computer
   (call_perplexity_computer) as the opening message of a NEW thread.
3. Delivery mechanics are mandatory (long replies truncate in the MCP read
   path): ask the thread to re-emit ONE section per reply — "In THIS reply,
   emit ONLY section N complete. I will then say 'next'." Reply "next" on that
   same thread_id until all six sections have been received and captured.
4. If a model-refusal switch form appears in the Perplexity thread, answer it
   choosing GPT-6 Sol (the brief's model note).
5. From the received sections write EXACTLY four files, at EXACTLY these
   absolute paths, and create nothing else anywhere:
   - STAGEDIR/intel-sources.md          <- section 1
   - STAGEDIR/recent-incidents.md       <- section 2
   - STAGEDIR/exploited-cve-classes.md  <- section 3
   - STAGEDIR/llm-research-sota.md      <- section 5
   Per file:
   - First line = the established H2 header, byte-exact; read the current file
     at /root/communitytools/skills/threat-intel/reference/<name> for its title
     and structure.
   - At most 190 lines: dense tables, no filler, no disclaimers.
   - Keep the current files' neutral phrasing style for victim orgs (type
     description, e.g. "an Indian exchange", not names) — the digest is a
     public-repo-committable artifact.
   - Refresh the trailing summary blocks (ranked lists / taxonomy tables) in
     content; keep their presence and shape.
   - Sections 4 and 6 are received for comparability but written nowhere.
6. Write STAGEDIR/driver-summary.md: one line per section (number +
   received/blocked) and the thread_id used.

Boundaries: write only under STAGEDIR; modify nothing else in either
repository; no scans, probes, or any interaction with live targets — the only
network activity is the Perplexity MCP research itself.
PROMPT
sed -i "s|STAGEDIR|$STAGE|g" "$STAGE/driver-prompt.md"

log "running headless relay (cap ${CLAUDE_TIMEOUT}s)"
if timeout "$CLAUDE_TIMEOUT" claude -p --dangerously-skip-permissions \
     "$(cat "$STAGE/driver-prompt.md")" > "$STAGE/claude-output.txt" 2>&1; then
  log "relay completed"
else
  rc=$?
  log "FAIL: headless relay rc=$rc — see $STAGE/claude-output.txt"
  exit "$rc"
fi

# ---------------------------------------------------------------- gates 1+2
fail=0
for f in $ORDER; do
  p="$STAGE/$f"
  if [ ! -s "$p" ]; then log "FAIL: staged file missing: $p"; fail=1; continue; fi
  [ "$(head -n1 "$p")" = "${SECTIONS[$f]}" ] \
    || { log "FAIL: $f header mismatch — want: ${SECTIONS[$f]}"; fail=1; }
  lines=$(wc -l < "$p")
  [ "$lines" -le "$LINE_CAP" ] || { log "FAIL: $f = $lines lines (cap $LINE_CAP)"; fail=1; }
  bytes=$(wc -c < "$p")
  [ "$bytes" -ge 1500 ] || { log "FAIL: $f only $bytes bytes — truncated?"; fail=1; }
  if ! python3 "$REPO/scripts/check_client_data.py" --redact --scan-file "$p" >> "$LOG" 2>&1; then
    log "FAIL: $f tripped the client-data gate"
    fail=1
  fi
done
if [ "$fail" != 0 ]; then log "ABORT: per-file gates failed — nothing written"; exit 1; fi
log "gates 1+2 ok: headers/size/lines + client-data clean on all four files"

# ---------------------------------------------------------------- gate 3 + apply
BASE="$STAGE/lint-baseline.json"
( cd "$REPO" && python3 scripts/skill_linter.py --write-baseline "$BASE" >/dev/null ) \
  || { log "FAIL: linter baseline could not be written"; exit 1; }

for f in $ORDER; do
  dst="$SKILL/reference/$f"
  cp "$STAGE/$f" "$dst.tmp.$$" && mv "$dst.tmp.$$" "$dst"
done

if ( cd "$REPO" && python3 scripts/skill_linter.py --delta "$BASE" > "$STAGE/lint-delta.json" ) \
   && [ "$(jq -r '.introduced_count // 99' "$STAGE/lint-delta.json" 2>/dev/null || echo 99)" = 0 ]; then
  log "gate 3 ok: linter 0 introduced"
else
  log "FAIL: linter gate — rolling back the four canonical files"
  for f in $ORDER; do
    rel="skills/threat-intel/reference/$f"
    git -C "$REPO" show "HEAD:$rel" > "$REPO/$rel" && log "rolled back $rel" \
      || log "ROLLBACK BROKEN for $rel — restore manually from git"
  done
  printf -- '- %s — FAILED: linter gate rejected the refresh; canonical rolled back\n' \
    "$(date +%F)" >> "$SKILL/reference/refresh-log.md"
  exit 1
fi

printf -- '- %s — refreshed %s via Perplexity (research-brief.md); gates: client-data clean, linter 0-introduced\n' \
  "$(date +%F)" "$(echo $ORDER | tr ' ' ',')" >> "$SKILL/reference/refresh-log.md"

# ---------------------------------------------------------------- propagate
if bash "$REPO/scripts/sync-pentest-mirror.sh" >> "$LOG" 2>&1; then
  log "layers synced (A + B)"
else
  log "FAIL: sync-pentest-mirror refused — canonical updated, layers NOT; resolve mirror divergence"
  exit 1
fi

csum=$(md5sum "$SKILL/reference/intel-sources.md" | cut -d' ' -f1)
for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^eng-' || true); do
  if docker exec "$c" md5sum /workspace/skills/threat-intel/reference/intel-sources.md 2>/dev/null \
     | grep -q "$csum"; then
    log "propagated: $c"
  else
    log "WARN: $c not showing the refreshed digest (bind mount?)"
  fi
done

log "DONE — canonical + layers refreshed. Review and commit in $REPO (skills/threat-intel)."
