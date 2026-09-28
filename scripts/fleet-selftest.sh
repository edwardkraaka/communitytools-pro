#!/usr/bin/env bash
# fleet-selftest.sh — regression suite for the exit-status + seeding contracts that
# burned the fleet on Sep 23 (4 bugs, 1 family). Run BEFORE deploying any edit to
# fleet-lib/fleet-runner/render-compose/kali-resume-entrypoint. Exits nonzero on any FAIL.
#
#   1. pane_context_pct / grep-pipe helpers survive pipefail nomatch      (bug: metrics+telemetry died)
#   2. render-compose renders EVERY registered service, not just the first (bug: 1-service compose)
#   3. attempt_tick at cap returns 0 under set -e                          (bug: runner main-loop kill)
#   4. fail_target ownership-miss returns 0 under set -e                   (bug: runner main-loop kill)
#   5. entrypoint settings seed produces ALL FOUR keys on a partial file   (bug: bypass-prompt wipe)
#   6. artifact detection resolves truncated dir names + subdir-only cwds  (bug: one engagement stuck post-report)
#   7. runner timeout block falls THROUGH to the artifact branch when a
#      report exists (bug: two engagements frozen past the 6h ceiling)
#   8. MCP registration merge: state override > image default, opt-out, non-fatal
#   9. phase-3 stitch: report ARMS the stitch phase; done gates on
#      reports/monetization-chain.md (disjoint from the phase-2 matcher)
#  10. intel-first kickoff mandates render + threat-intel at all three layers
set -uo pipefail   # NOT -e: the suite itself must run every check
PASS=0; FAIL=0
ok()  { echo "  PASS $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
note(){ echo "== $1"; }
STACK=/root/pentest-stack

# ---------------------------------------------------------------- 1. helpers
note "1. pipefail-safe helpers (grep-nomatch must not kill callers)"
(
  set -euo pipefail
  # shellcheck disable=SC1091
  source "/root/pentest-stack/fleet-lib.sh"
  v=$(pane_context_pct definitely-not-a-container 2>/dev/null) && ok "pane_context_pct nomatch rc=0 ($v)" || bad "pane_context_pct killed its caller"
  v=$(compact_count definitely-not-a-tag) && ok "compact_count no-state rc=0 ($v)" || bad "compact_count killed its caller"
) || bad "helper subshell died under pipefail"

# ---------------------------------------------------------------- 2. render
note "2. render-compose full-registry render"
N_ENV=$(ls "$STACK"/engagements/*.env 2>/dev/null | wc -l)
before=$(md5sum "$STACK/docker-compose.yml" 2>/dev/null | cut -d' ' -f1)
if OUT=$(bash "$STACK/render-compose.sh" 2>&1); then
  N_SVC=$(grep -c 'container_name:' "$STACK/docker-compose.yml")
  if [ "$N_SVC" = "$N_ENV" ]; then
    ok "render complete ($N_SVC/$N_ENV services)"
  else
    bad "render INCOMPLETE: $N_SVC of $N_ENV services (the Sep-23 launch-freeze bug)"
  fi
  [ "$before" = "$(md5sum "$STACK/docker-compose.yml" | cut -d' ' -f1)" ] && ok "render idempotent" || bad "render not idempotent"
else
  bad "render-compose exited rc=$?: $OUT"
fi

# ---------------------------------------------------------------- 3+4. runner fns
note "3+4. runner exit contracts (simulated run dir — no live state touched)"
TD=$(mktemp -d); mkdir -p "$TD/state" "$TD/registry"
# the kelpdao condition: attempts=2, registry env WITHOUT the FLEET_RUN marker
cat > "$TD/state/mocktag.json" <<'J'
{"tag":"mocktag","url":"https://mock.test","status":"launched-osint",
 "attempts":2,"last_event":"x","ts":{}}
J
: > "$TD/registry/mocktag.env"
HARNESS="$TD/h.sh"
cat > "$HARNESS" <<'J'
DRY_RUN=0; ALLOW_COLLIDE=0; TARGETS_FILE=/dev/null
fleet_notify() { true; }
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >> "${LOGFILE:-/dev/null}"; }
J
# extract ONLY the named functions (col-0 closing brace terminates each)
extfn() { awk -v fn="$1" '$0 ~ "^"fn"\\(\\)" {p=1} p {print} p && /^}$/ {exit}' "$2"; }
for f in state_file state_get state_set state_set_status update_event; do
  extfn "$f" "/root/pentest-stack/fleet-lib.sh" >> "$HARNESS" || bad "extract $f failed"
done
for f in state_set_status attempt_tick fail_target; do
  extfn "$f" "$STACK/fleet-runner.sh" >> "$HARNESS" || bad "extract $f failed"
done
echo "RUNID=.; FLEET_DIR=\"$TD\"; ENGAGE_REG=\"$TD/registry\"" >> "$HARNESS"
# attempt #3 must NOT kill a set -e caller; state must land at failed (not retired: no marker)
OUT=$(LOGFILE="$TD/console.log" bash -c "set -euo pipefail; source '$HARNESS'; attempt_tick mocktag 'selftest simulated failure'" 2>"$TD/err")
RC=$?
[ "$RC" = 0 ] && ok "attempt_tick at cap returned 0 (caller survived)" \
               || bad "attempt_tick at cap killed its caller rc=$RC — $(tail -2 "$TD/err" 2>/dev/null)"
[ "$(jq -r .status "$TD/state/mocktag.json" 2>/dev/null)" = "failed" ] && ok "target marked failed (state intact)" \
  || bad "state not marked failed: $(jq -c .status "$TD/state/mocktag.json" 2>/dev/null)"
[ "$(jq -r .status "$TD/state/mocktag.json" 2>/dev/null)" = "retired" ] && bad "OWNERSHIP GUARD LEAK: retired a marker-less entry" \
  || ok "ownership guard held (marker-less entry not retired)"
rm -rf "$TD"

# ---------------------------------------------------------------- 5. entrypoint seed
note "5. entrypoint settings seed completeness (partial-file merge)"
SD=$(mktemp -d)
printf '{"autoCompactEnabled":true,"autoCompactWindow":140000}\n' > "$SD/settings.json"  # the rolled-out partial
python3 - "$SD/settings.json" 140000 <<'PY'
import json,sys,os
p,w=sys.argv[1],int(sys.argv[2])
try: d=json.load(open(p))
except Exception: d={}
if not isinstance(d,dict): d={}
d["theme"]="dark"; d["skipDangerousModePermissionPrompt"]=True
d["autoCompactEnabled"]=True; d["autoCompactWindow"]=w
open(p,"w").write(json.dumps(d,indent=2)+"\n")
PY
python3 -c "
import json,sys
d=json.load(open('$SD/settings.json'))
need={'theme','skipDangerousModePermissionPrompt','autoCompactEnabled','autoCompactWindow'}
sys.exit(0 if need.issubset(d) else 1)
" && ok "partial settings.json merged to all 4 keys" || bad "seed left keys missing (bypass-prompt wipe bug)"
sed -n '/<<'"'"'SEED'"'"'/,/^SEED$/p' "/root/pentest-stack/kali-resume-entrypoint.sh" | grep -q 'skipDangerousModePermissionPrompt' \
  && ok "entrypoint SEED block still seeds bypass-prompt skip" || bad "entrypoint SEED block lost the bypass-prompt key"
rm -rf "$SD"

# ------------------------------------------- 6. artifact matching (renzo class)
note "6. osint_artifact resolves truncated names + subdir-only cwds"
TD=$(mktemp -d); mkdir -p "$TD/state" "$TD/ws/projects/pentest"
mkdir -p "$TD/ws/projects/pentest/260923_205806_renzo_osint/reports"
echo done > "$TD/ws/projects/pentest/260923_205806_renzo_osint/reports/osint_report.md"
mkdir -p "$TD/kstate/renzoprotocol/claude/projects/-workspace"
# only a SUBDIR cwd is recorded, and the tag is truncated in the dir name —
# the two conditions that hid renzoprotocol's finished report on Sep 23
printf '%s\n' '{"cwd":"/workspace/projects/pentest/260923_205806_renzo_osint/recon/repos"}' \
  > "$TD/kstate/renzoprotocol/claude/projects/-workspace/sid.jsonl"
# assign AFTER source — the lib sets WS/KALI_STATE unconditionally, so an
# env-prefix override is clobbered mid-source and the fixture never engages
# (found while adding check 9; the check previously passed against live data)
OUT=$(bash -c "source /root/pentest-stack/fleet-lib.sh; WS='$TD/ws'; KALI_STATE='$TD/kstate'; osint_artifact renzoprotocol")
[ -n "$OUT" ] && ok "truncated-name + subdir-cwd artifact found ($OUT)" \
               || bad "artifact invisible under truncated name / subdir cwd"
rm -rf "$TD"

# ------------------------------------------- 7. timeout fall-through (maple/orca class)
note "7. runner timeout block: artifact outranks the 6h ceiling"
# Behavioral: extract the OSINT timeout block, wrap it in a loop, stub the
# helpers. A landed artifact must NOT hit the continue (falls through to the
# injection branch below); a missing artifact must keep the continue gate.
TD=$(mktemp -d)
awk '/# timeout ceiling/ && !done {p=1} p {print} p && /^        fi$/ {done=1; exit}' \
  /root/pentest-stack/fleet-runner.sh > "$TD/block.sh"
grep -q 'osint_artifact' "$TD/block.sh" || bad "timeout gate lost its osint_artifact check"
grep -qE '^[[:space:]]*continue$' "$TD/block.sh" || bad "extraction lost the continue line"
mk_case() {  # $1 = what osint_artifact yields: a path, or empty
  cat > "$TD/case.sh" <<'J'
RUNID=test; tag=mocktag; c=mockc; OSINT_TIMEOUT_H=6
ts_age_s() { echo 99999; }
state_get() { echo x; }
pane_idle() { return 0; }
osint_artifact() { printf '%s' "$ART"; }
attempt_tick() { return 0; }
state_set() { return 0; }
J
  echo "REACHED=0; ITER=0" >> "$TD/case.sh"
  echo 'while [ $ITER -lt 2 ]; do' >> "$TD/case.sh"
  echo '  ITER=$((ITER+1))' >> "$TD/case.sh"
  cat "$TD/block.sh" >> "$TD/case.sh"
  echo '  REACHED=1' >> "$TD/case.sh"
  echo '  break' >> "$TD/case.sh"
  echo 'done' >> "$TD/case.sh"
  echo 'echo "ITER=$ITER REACHED=$REACHED"' >> "$TD/case.sh"
}
mk_case "/tmp/fake_report.md"
R=$(ART="/tmp/fake_report.md" bash "$TD/case.sh" 2>&1)
case "$R" in *REACHED=1*) ok "artifact landed: falls through to injection (no freeze)";; *) bad "artifact landed but continue fired anyway (maple/orca freeze): $R";; esac
mk_case ""
R=$(ART="" bash "$TD/case.sh" 2>&1)
case "$R" in *REACHED=0*) ok "no artifact: timeout continue gates as designed";; *) bad "no-artifact path lost its continue: $R";; esac
rm -rf "$TD"

# ------------------------------------------- 8. MCP seed merge (context7 rollout)
note "8. MCP registration merge: state override > image default, opt-out, non-fatal"
# 8a. grep pins: the entrypoint carries the merge block with both precedence lines
grep -q "MCPMERGE" "$STACK/kali-resume-entrypoint.sh" \
  && grep -q 'MCP_SEED="$HOME/.claude/mcp-servers.json"' "$STACK/kali-resume-entrypoint.sh" \
  && grep -q 'MCP_SEED="/opt/mcp-default.json"' "$STACK/kali-resume-entrypoint.sh" \
  && grep -q "mcp-default.json" "$STACK/Dockerfile.eng" \
  && ok "entrypoint merge block + Dockerfile COPY pinned" \
  || bad "MCP merge wiring incomplete (entrypoint precedence lines / Dockerfile COPY)"
python3 -c "import json;d=json.load(open('$STACK/mcp-default.json'));assert 'mcpServers' in d" \
  && ok "mcp-default.json is valid JSON with mcpServers" \
  || bad "mcp-default.json missing or malformed"
# 8b. behavioral: extract the entrypoint's python block VERBATIM and run the 4 cases
TD=$(mktemp -d)
MCPC=$(awk '/<<.MCPMERGE./ {p=1; next} /^MCPMERGE$/ {p=0} p' "$STACK/kali-resume-entrypoint.sh")
[ -n "$MCPC" ] || bad "could not extract MCPMERGE python block"
run_probe() {  # $1=faux-HOME, $2=seed-file — runs the entrypoint's python verbatim
  HOME="$1" python3 - "/workspace" "$2" <<PYE
$MCPC
PYE
}
mkdir -p "$TD/home/.claude" "$TD/img"
printf '%s\n' '{"mcpServers":{"img-default":{"type":"http","url":"https://img.example/mcp"}}}' > "$TD/img/mcp-default.json"
# case 1: state file present -> sole authority (must replace a stale image default)
printf '%s\n' '{"mcpServers":{"stale-img":{"type":"http","url":"https://old.example/mcp"}}}' > "$TD/home/.claude.json"
printf '%s\n' '{"mcpServers":{"state-only":{"type":"http","url":"https://state.example/mcp"}}}' > "$TD/home/.claude/mcp-servers.json"
run_probe "$TD/home" "$TD/home/.claude/mcp-servers.json"
R=$(python3 -c "import json;print(sorted(json.load(open('$TD/home/.claude.json'))['mcpServers']))" 2>/dev/null)
[ "$R" = "['state-only']" ] && ok "state file wins, stale image default displaced" \
                          || bad "state-override case wrong: got ${R:-none}"
# case 2: no state file -> image default registers
rm "$TD/home/.claude/mcp-servers.json"
printf '%s\n' '{"hasCompletedOnboarding":true}' > "$TD/home/.claude.json"
run_probe "$TD/home" "$TD/img/mcp-default.json"
R=$(python3 -c "import json;print(sorted(json.load(open('$TD/home/.claude.json'))['mcpServers']))" 2>/dev/null)
[ "$R" = "['img-default']" ] && ok "no state file: image default registers" \
                          || bad "default case wrong: got ${R:-none}"
# case 3: opt-out {"mcpServers":{}} must leave nothing behind (and not crash)
printf '%s\n' '{"mcpServers":{}}' > "$TD/home/.claude/mcp-servers.json"
printf '%s\n' '{"hasCompletedOnboarding":true}' > "$TD/home/.claude.json"
run_probe "$TD/home" "$TD/home/.claude/mcp-servers.json"
R=$(python3 -c "import json;print(json.load(open('$TD/home/.claude.json')).get('mcpServers','ABSENT'))" 2>/dev/null)
[ "$R" = "ABSENT" ] && ok "opt-out {}: no mcpServers key left behind" \
                     || bad "opt-out left keys behind: $R"
# case 4: malformed seed must exit 0 and leave the config file valid
printf 'not json at all\n' > "$TD/home/.claude/mcp-servers.json"
printf '%s\n' '{"hasCompletedOnboarding":true}' > "$TD/home/.claude.json"
run_probe "$TD/home" "$TD/home/.claude/mcp-servers.json"
RC=$?
V=$(python3 -c "import json;json.load(open('$TD/home/.claude.json'));print('valid')" 2>/dev/null)
[ "$RC" = 0 ] && [ "$V" = "valid" ] && ok "malformed seed: non-fatal, config stays valid" \
                                   || bad "malformed seed broke something (rc=$RC valid=${V:-no})"
rm -rf "$TD"

# --------------------------------------- 9. phase-3 stitch (monetization chain)
note "9. phase-3 stitch: arm on phase-2 report, done gates on monetization-chain.md"
TD=$(mktemp -d)
# fixture: armed dir uses a BRAND name (no tag inside — the naming-miss class),
# tag dirs in BOTH layouts, plus a transcript-cwd walk-up dir, plus distractors
# that the OTHER gate must consume (technical_report.md) or ignore (chain file)
mkdir -p "$TD/ws/proj_active/reports" "$TD/ws/260926_100000_tg_active/reports" \
         "$TD/ws/projects/pentest/260926_120000_tg_active/reports" \
         "$TD/ws/projects/pentest/brandco_active/reports" \
         "$TD/kstate/tg/claude/projects/-workspace"
echo x > "$TD/ws/proj_active/reports/monetization-chain.md"
echo x > "$TD/ws/projects/pentest/260926_120000_tg_active/reports/monetization-chain.md"
echo x > "$TD/ws/projects/pentest/brandco_active/reports/monetization-chain.md"
echo x > "$TD/ws/260926_100000_tg_active/reports/technical_report.md"
printf '%s\n' '{"cwd":"/workspace/projects/pentest/brandco_active/recon"}' \
  > "$TD/kstate/tg/claude/projects/-workspace/sid.jsonl"
cat > "$TD/probe.sh" <<'J'
source /root/pentest-stack/fleet-lib.sh
WS="$1"; KALI_STATE="$2"
echo "armed:$(stitch_artifact "$3" "$4")"
echo "tagged:$(stitch_artifact "$3" "")"
echo "p2:$(active_artifact "$3")"
echo "empty:$(stitch_artifact no-such-tag "")"
J
R=$(bash "$TD/probe.sh" "$TD/ws" "$TD/kstate" tg "$TD/ws/proj_active")
case "$R" in
  *armed:*proj_active*monetization-chain.md*) ok "stitch gate: exact armed dir (brand-named)" ;;
  *) bad "armed-dir lookup missed: $R" ;;
esac
case "$R" in
  *tagged:*monetization-chain.md*) ok "stitch gate: tag dirs + transcript-cwd walk-up" ;;
  *) bad "tag-dir lookup missed: $R" ;;
esac
# disjointness, both directions: phase-2 gate eats its technical_report.md and
# NEVER the chain file; stitch gate stays empty with no chain anywhere
case "$R" in
  *p2:*technical_report.md*) ok "phase-2 gate: own report only" ;;
  *p2:*) bad "phase-2 gate returned something odd: $R" ;;
  *) bad "phase-2 gate missed its own report: $R" ;;
esac
case "$R" in
  *p2:*monetization-chain.md*) bad "phase-2 gate fired on the chain deliverable" ;;
esac
case "$R" in
  *empty:|*empty:$'\n'*) ok "stitch gate empty with no chain (never false-fires)" ;;
  *empty:*) bad "stitch gate false-fired: $R" ;;
esac
# stage3_message pins: explicit dir, exact deliverable file, and the STAGE 3 frame
M=$(bash -c "source /root/pentest-stack/fleet-lib.sh; WS='$TD/ws'; stage3_message https://x.example tg '$TD/ws/proj_active'")
if printf '%s' "$M" | grep -qF '/workspace/proj_active' \
   && printf '%s' "$M" | grep -qF 'monetization-chain.md' \
   && printf '%s' "$M" | grep -qF 'STAGE 3'; then
  ok "stage3_message names dir + deliverable"
else
  bad "stage3_message lost explicit dir/deliverable: ${M:0:120}"
fi
# behavioral: the runner's phase-3 block ARMS on a landed report (status stays
# active, .stage3.dir recorded) and marks done ONLY on the chain file
P3=$(grep -n '# PHASE 3' /root/pentest-stack/fleet-runner.sh | head -1 | cut -d: -f1)
WG=$(grep -n '# WEDGE FAST-PATH' /root/pentest-stack/fleet-runner.sh | head -1 | cut -d: -f1)
[ -n "$P3" ] && [ -n "$WG" ] && [ "$WG" -gt "$P3" ] \
  || bad "phase-3 block markers not found in runner (P3=$P3 WG=$WG)"
sed -n "${P3},$((WG-1))p" /root/pentest-stack/fleet-runner.sh > "$TD/block.sh"
cat > "$TD/case.sh" <<'J'
source /root/pentest-stack/fleet-lib.sh
FLEET_DIR="$1"; RUNID=testrun; tag=$2; c=mockc; IDLE_SAMPLE=0
log() { echo "LOG: $*"; }
fleet_notify() { :; }
docker() { return 1; }   # has-session false → mandate-injection branch skipped
state_init "$RUNID" "$tag" "https://x.example" ""
state_set "$RUNID" "$tag" '.status="active"'   # the block lives inside `case $st in active)`
state_set_status() {  # runner-local helper not in fleet-lib — minimal stub
  jq --arg st "$3" --arg ev "$4" --arg now "$(date -Is)" \
     '.status=$st | .ts[$st]=$now | .last_event=$ev' "$FLEET_DIR/$RUNID/state/$tag.json" \
    > "$FLEET_DIR/$RUNID/state/$tag.json.tmp" && mv "$FLEET_DIR/$RUNID/state/$tag.json.tmp" "$FLEET_DIR/$RUNID/state/$tag.json"
}
active_artifact() { printf '%s' "$ART"; }
stitch_artifact() { printf '%s' "$S3"; }
n=0
while [ $n -lt 1 ]; do
  n=$((n+1))
J
cat "$TD/block.sh" >> "$TD/case.sh"
echo 'done' >> "$TD/case.sh"
# case A: report landed, no chain yet → ARM (status stays active)
ART="$TD/ws/e_active/reports/technical_report.md" S3="" \
  bash "$TD/case.sh" "$TD/flt" tg > "$TD/outA" 2>&1
SA=$(jq -r '.stage3.dir // "MISSING"' "$TD/flt/testrun/state/tg.json" 2>/dev/null)
ST=$(jq -r '.status' "$TD/flt/testrun/state/tg.json" 2>/dev/null)
if [ "$SA" = "$TD/ws/e_active" ] && [ "$ST" = "active" ]; then
  ok "report arms phase 3 (dir recorded, status stays active)"
else
  bad "arming failed (stage3.dir=$SA status=$ST): $(cat "$TD/outA")"
fi
grep -q 'phase-3 armed' "$TD/outA" || bad "arming log line missing: $(cat "$TD/outA")"
# case B: chain landed → DONE (through the same block, armed state intact)
ART="" S3="$TD/ws/e_active/reports/monetization-chain.md" \
  bash "$TD/case.sh" "$TD/flt" tg > "$TD/outB" 2>&1
ST=$(jq -r '.status' "$TD/flt/testrun/state/tg.json" 2>/dev/null)
EV=$(jq -r '.last_event // ""' "$TD/flt/testrun/state/tg.json" 2>/dev/null)
[ "$ST" = "done" ] && case "$EV" in monetization*) ok "chain file marks done (monetization event)";; *) bad "done but wrong event: $EV";; esac \
  || bad "chain file did not mark done (status=$ST): $(cat "$TD/outB")"
rm -rf "$TD"

# --------------------------------------- 10. intel-first mandates (threat-intel)
note "10. threat-intel kickoff mandates + three-layer skill presence"
# render, not grep-the-source: a later edit could decouple the printf text from
# what agent containers actually receive
OS_MSG=$(bash -c "source $STACK/fleet-lib.sh; osint_kickoff https://x.example tg")
S2_MSG=$(bash -c "source $STACK/fleet-lib.sh; stage2_message https://x.example tg '' ''")
printf '%s' "$OS_MSG" | grep -qF 'threat-intel' && printf '%s' "$OS_MSG" | grep -qF 'TI Hypotheses' \
  && ok "osint_kickoff mandates the threat-intel triage handoff" \
  || bad "osint_kickoff lost the threat-intel / TI Hypotheses mandate"
printf '%s' "$S2_MSG" | grep -qF 'Hunt first' && printf '%s' "$S2_MSG" | grep -qF 'TI Hypotheses' \
  && printf '%s' "$S2_MSG" | grep -qF 'threat-intel' \
  && ok "stage2_message leads with the hunt-first mandate" \
  || bad "stage2_message lost the Hunt first / TI Hypotheses / threat-intel mandate"
# three layers: canonical (git) + layer A (/workspace/.claude/skills) + layer B
# (/workspace/skills) — all must exist for the mandate's container paths to
# resolve, and all three must be byte-identical (drift = stale digest)
TI_SKILL=/root/communitytools/skills/threat-intel/SKILL.md
TI_A=/root/communitytools/projects/pentest/.claude/skills/threat-intel/SKILL.md
TI_B=/root/communitytools/projects/pentest/skills/threat-intel/SKILL.md
if [ -f "$TI_SKILL" ] && [ -f "$TI_A" ] && [ -f "$TI_B" ]; then
  ok "threat-intel SKILL.md present at all three layers"
  TI_CK=$(md5sum "$TI_SKILL" | cut -d' ' -f1)
  [ "$(md5sum "$TI_A" | cut -d' ' -f1)" = "$TI_CK" ] && [ "$(md5sum "$TI_B" | cut -d' ' -f1)" = "$TI_CK" ] \
    && ok "three layer copies byte-identical" \
    || bad "threat-intel layer drift — run scripts/sync-pentest-mirror.sh"
else
  bad "threat-intel missing a layer copy (canonical / .claude mirror / skills mirror)"
fi

# --------------------------------------- 11. mobile-surface lane (apk handoff)
note "11. mobile-surface lane: kickoff mandate, verdict gate, conditional paragraph"
# 11a. render, not grep-the-source: kickoff must carry the detection mandate
OS_MSG=$(bash -c "source $STACK/fleet-lib.sh; osint_kickoff https://x.example tg")
printf '%s' "$OS_MSG" | grep -qF 'MOBILE-SURFACE CHECK' \
  && printf '%s' "$OS_MSG" | grep -qF 'mobile-surface.json' \
  && printf '%s' "$OS_MSG" | grep -qF 'verdict=present requires evidence' \
  && ok "osint_kickoff mandates the mobile-surface check + JSON schema" \
  || bad "osint_kickoff lost the mobile-surface mandate"
# 11b. verdict gate: present/absent/corrupt — render cars, not source grep
TD=$(mktemp -d)
printf '%s\n' '{"android":{"verdict":"present","packages":["com.example.app"],"direct_apk":[],"evidence":[]}}' > "$TD/p.json"
printf '%s\n' '{"android":{"verdict":"absent","packages":[],"direct_apk":[],"evidence":[]}}' > "$TD/a.json"
printf 'corrupt{' > "$TD/c.json"
GATE_P=$(bash -c "source $STACK/fleet-lib.sh; mobile_android_present '$TD/p.json'" && echo yes)
GATE_A=$(bash -c "source $STACK/fleet-lib.sh; mobile_android_present '$TD/a.json'" || echo no)
GATE_C=$(bash -c "source $STACK/fleet-lib.sh; mobile_android_present '$TD/c.json'" || echo no)
[ "$GATE_P" = "yes" ] && [ "$GATE_A" = "no" ] && [ "$GATE_C" = "no" ] \
  && ok "verdict gate: present passes, absent/corrupt fail-safe to web-only" \
  || bad "verdict gate wrong (p=$GATE_P a=$GATE_A c=$GATE_C)"
# 11c. conditional paragraph: present → MOBILE LANE with pipeline path; absent → none
MSG_P=$(bash -c "source $STACK/fleet-lib.sh; stage2_message https://x.example tg '' '' '$TD/p.json'")
MSG_A=$(bash -c "source $STACK/fleet-lib.sh; stage2_message https://x.example tg '' '' '$TD/a.json'")
printf '%s' "$MSG_P" | grep -qF 'MOBILE LANE' \
  && ok "stage2_message renders the mobile paragraph on present" \
  || bad "present: mobile paragraph missing"
printf '%s' "$MSG_A" | grep -qF 'MOBILE LANE' \
  && bad "absent: mobile paragraph rendered anyway" \
  || ok "stage2_message omits the mobile paragraph on absent"
printf '%s' "$MSG_P" | grep -qF '/workspace/scripts/apk-pipeline.sh' \
  && ok "mobile paragraph names the container-side pipeline path" \
  || bad "mobile paragraph lacks /workspace/scripts/apk-pipeline.sh"
# 11d. artifact reader on the fixture layouts (tag dir preferred, brand fallback)
mkdir -p "$TD/ws/260928_100000_tg_osint/reports" "$TD/ws/projects/pentest/brandco_osint/reports" "$TD/kstate/tg/claude/projects/-workspace"
printf '%s\n' '{"android":{"verdict":"present","packages":["com.example.app"],"direct_apk":[],"evidence":[]}}' > "$TD/ws/260928_100000_tg_osint/reports/mobile-surface.json"
printf '%s\n' '{"cwd":"/workspace/projects/pentest/brandco_osint/recon"}' > "$TD/kstate/tg/claude/projects/-workspace/sid.jsonl"
OUT=$(bash -c "source $STACK/fleet-lib.sh; WS='$TD/ws'; KALI_STATE='$TD/kstate'; mobile_artifact tg")
case "$OUT" in
  *tg_osint*mobile-surface.json) ok "mobile_artifact finds tag-layout dir" ;;
  *) bad "mobile_artifact missed the tag-layout dir: $OUT" ;;
esac
printf '%s\n' '{"android":{"verdict":"present","packages":["com.brandco.app"],"direct_apk":[],"evidence":[]}}' > "$TD/ws/projects/pentest/brandco_osint/reports/mobile-surface.json"
OUT=$(bash -c "source $STACK/fleet-lib.sh; WS='$TD/ws'; KALI_STATE='$TD/kstate'; mobile_artifact tg")
case "$OUT" in
  *tg_osint*mobile-surface.json) ok "mobile_artifact prefers the tag dir over the brand dir" ;;
  *brandco*mobile-surface.json) bad "mobile_artifact returned the brand dir though a tag dir matched: $OUT" ;;
  *) bad "mobile_artifact found neither dir: $OUT" ;;
esac
rm -rf "$TD"

echo "────────"
[ "$FAIL" = 0 ]
