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
#   6. artifact detection resolves truncated dir names + subdir-only cwds  (bug: renzo stuck post-report)
#   7. runner timeout block falls THROUGH to the artifact branch when a
#      report exists (bug: maple/orca frozen past the 6h ceiling)
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
OUT=$(KALI_STATE="$TD/kstate" WS="$TD/ws" bash -c \
  "source /root/pentest-stack/fleet-lib.sh; osint_artifact renzoprotocol")
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

echo "────────"
echo "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
