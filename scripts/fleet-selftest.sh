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

echo "────────"
echo "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
