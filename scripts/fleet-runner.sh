#!/usr/bin/env bash
# fleet-runner.sh — run a targets file of engagements through the 2-stage chain
# (OSINT → active pentest) across N parallel interactive containers.
#
#   fleet-runner.sh <targets-file> [options]
#     --slots N              concurrent fleet-owned containers (default 8)
#     --osint-timeout-h H    stage-1 wall-clock ceiling   (default 6)
#     --active-timeout-h H   stage-2 wall-clock ceiling   (default 12)
#     --gluetun NAME         VPN sidecar (default: probe gluetun then gluetun-za)
#     --launch-interval S    pacing between launches      (default 10)
#     --idle-sample S        dual idle-sample spacing     (default 90)
#     --allow-collide        suffix colliding tags instead of erroring
#     --dry-run / -n         print the plan; execute nothing
#     --run DIR              adopt/resume an existing run directory
#
#   fleet-runner.sh resume [--run DIR]   — adopt the active run (or DIR) using
#                                          its targets.txt snapshot; exits 0 if
#                                          there is none to resume
#   fleet-runner.sh status [--run DIR] [--watch]   — status table
#   fleet-runner.sh cleanup [--run DIR] [--all-done] — retire parked done
#                                          targets (stop+rm container, archive
#                                          the .env; outputs are never touched)
#
# The runner OWNS only containers it registered (state/<tag>.json + FLEET_RUN
# marker in the registry .env). The three manual engagements are never touched.
# State is restart-safe: on start it adopts launched-osint/osint-done/active
# targets whose containers still run; a missing container is re-registered via
# its pinned .env (kali-eng.sh resumes the pinned session).
set -euo pipefail
LIB=${FLEET_LIB:-/root/pentest-stack/fleet-lib.sh}
# shellcheck disable=SC1091
source "$LIB"

SLOTS=8; OSINT_TIMEOUT_H=6; ACTIVE_TIMEOUT_H=12
GLUETUN_OPT=""; LAUNCH_INTERVAL=10; IDLE_SAMPLE=90
ALLOW_COLLIDE=0; DRY_RUN=0; RUN_DIR=""

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

MODE="${1:-}"; [ -n "$MODE" ] || usage 1
if [ "$MODE" = "status" ]; then exec bash "${FLEET_STATUS:-/root/pentest-stack/fleet-status.sh}" "${@:2}"; fi
[ "$MODE" = "-h" ] || [ "$MODE" = "--help" ] && usage 0

# ------------------------------------------------------------------- cleanup --
# cleanup [--run DIR|RUNID] [--all-done] — the park-then-cleanup lifecycle:
# retire every `done` target of the active run (or a given run; every run with
# --all-done): stop+rm the container, archive the registry .env into the run's
# registry/, remove the monitor pane, state → retired. kali-state/ and
# workspace outputs are never touched. Postmortem runs are skipped (unresumable
# by design). Exits non-zero if any retire fails.
if [ "$MODE" = "cleanup" ]; then
  shift
  RUN_REF=""; ALL_DONE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --run) RUN_REF="$2"; shift 2 ;;
      --all-done) ALL_DONE=1; shift ;;
      *) echo "usage: $0 cleanup [--run DIR|RUNID] [--all-done]" >&2; exit 1 ;;
    esac
  done
  cleanup_one_run() {  # <run_dir> — retire its done targets, print per-target lines
    local rd=$1 f tag n=0 fails=0
    if [ -e "$rd/state.postmortem-no-resume" ]; then
      echo "  skip $(basename "$rd") (postmortem, unresumable)"; return 0
    fi
    for f in "$rd"/state/*.json; do
      [ -f "$f" ] || continue
      [ "$(jq -r '.status // empty' "$f" 2>/dev/null)" = "done" ] || continue
      tag=$(jq -r '.tag // empty' "$f" 2>/dev/null)
      [ -n "$tag" ] || continue
      if retire_engagement "$tag" "$rd/registry"          && jq --arg now "$(date -Is)" '.status="retired" | .ts.retired=$now | .last_event="cleanup retire"' "$f" > "$f.tmp" 2>/dev/null && mv "$f.tmp" "$f"; then
        echo "  retired $tag"
        n=$((n+1))
      else
        echo "  FAILED $tag" >&2
        fails=1
      fi
    done
    [ "$n" -gt 0 ] || echo "  (nothing to do — no done targets)"
    return "$fails"
  }
  rc=0
  if [ "$ALL_DONE" = 1 ]; then
    echo "cleanup --all-done: sweeping every run dir under $FLEET_DIR"
    for rd in "$FLEET_DIR"/[0-9]*/; do
      [ -d "$rd" ] || continue
      echo "$(basename "$rd"):"
      cleanup_one_run "${rd%/}" || rc=1
    done
  else
    if [ -n "$RUN_REF" ]; then
      case "$RUN_REF" in /*) rd="$RUN_REF" ;; *) rd="$FLEET_DIR/$RUN_REF" ;; esac
      [ -d "$rd" ] || { echo "no such run dir: $rd" >&2; exit 2; }
    else
      rd=$(readlink -f "$FLEET_DIR/active" 2>/dev/null) || true
      [ -n "$rd" ] && [ -d "$rd" ] || { echo "no active fleet run — pass --run DIR" >&2; exit 2; }
    fi
    echo "cleanup: $(basename "$rd")"
    cleanup_one_run "$rd" || rc=1
  fi
  exit "$rc"
fi

RESUME=0
if [ "$MODE" = "resume" ]; then RESUME=1; shift; else TARGETS_FILE="$MODE"; shift; fi

while [ $# -gt 0 ]; do
  case "$1" in
    --slots) SLOTS="$2"; shift 2 ;;
    --osint-timeout-h) OSINT_TIMEOUT_H="$2"; shift 2 ;;
    --active-timeout-h) ACTIVE_TIMEOUT_H="$2"; shift 2 ;;
    --gluetun) GLUETUN_OPT="$2"; shift 2 ;;
    --launch-interval) LAUNCH_INTERVAL="$2"; shift 2 ;;
    --idle-sample) IDLE_SAMPLE="$2"; shift 2 ;;
    --allow-collide) ALLOW_COLLIDE=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    --run) RUN_DIR="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

# ------------------------------------------------------------------ run dir --
mkdir -p "$FLEET_DIR"
if [ "$RESUME" = 1 ]; then
  # adopt the active run (or --run DIR): targets + allow-collide come from the
  # run's own snapshot, so the original targets file need not still exist.
  [ -n "$RUN_DIR" ] || RUN_DIR="$FLEET_DIR/active"
  RUN_DIR=$(readlink -f "$RUN_DIR" 2>/dev/null || true)
  [ -d "$RUN_DIR" ] || { echo "no fleet run to resume (no active run dir)"; exit 0; }
  [ -f "$RUN_DIR/targets.txt" ] || { echo "cannot resume: $RUN_DIR lacks targets.txt" >&2; exit 2; }
  RUNID=$(basename "$RUN_DIR")
  TARGETS_FILE="$RUN_DIR/targets.txt"
  [ -f "$RUN_DIR/opts.env" ] && . "$RUN_DIR/opts.env"
elif [ -n "$RUN_DIR" ]; then
  RUNID=$(basename "$RUN_DIR"); RUN_DIR="$FLEET_DIR/$RUNID"
  [ -d "$RUN_DIR" ] || { echo "no such run dir: $RUN_DIR" >&2; exit 2; }
  [ -f "$TARGETS_FILE" ] || { echo "no such targets file: $TARGETS_FILE" >&2; exit 2; }
else
  [ -f "$TARGETS_FILE" ] || { echo "no such targets file: $TARGETS_FILE" >&2; exit 2; }
  base=$(basename "$TARGETS_FILE"); base=${base%.*}
  RUNID="$(date +%Y%m%d_%H%M%S)_${base:0:20}"
  RUN_DIR="$FLEET_DIR/$RUNID"
  [ -d "$RUN_DIR" ] && { echo "run dir exists: $RUN_DIR (pass --run to adopt)" >&2; exit 2; }
fi

if [ "$DRY_RUN" = 0 ]; then
  mkdir -p "$RUN_DIR/state" "$RUN_DIR/registry"
  ln -sfn "$RUNID" "$FLEET_DIR/active"
  # snapshot targets + options into the run dir (fuel for `resume` adoption)
  [ -f "$RUN_DIR/targets.txt" ] || cp "$TARGETS_FILE" "$RUN_DIR/targets.txt"
  { echo "SLOTS=$SLOTS"
    echo "OSINT_TIMEOUT_H=$OSINT_TIMEOUT_H"
    echo "ACTIVE_TIMEOUT_H=$ACTIVE_TIMEOUT_H"
    echo "LAUNCH_INTERVAL=$LAUNCH_INTERVAL"
    echo "IDLE_SAMPLE=$IDLE_SAMPLE"
    [ -n "$GLUETUN_OPT" ] && echo "GLUETUN_OPT=$GLUETUN_OPT"
    [ "$ALLOW_COLLIDE" = 1 ] && echo "ALLOW_COLLIDE=1"
  } > "$RUN_DIR/opts.env"
  # single-instance guard per run dir
  exec 9>>"$RUN_DIR/.lock"
  flock -n 9 || { echo "another runner owns $RUN_DIR" >&2; exit 3; }
fi

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$RUN_DIR/fleet.log"; }

# ------------------------------------------------------------------- parse --
# in dry-run nothing is created, so the parser owns no registry entries — pass ""
PARSE_RUNID=""; [ "$DRY_RUN" = 0 ] && PARSE_RUNID="$RUNID"
PARSED=$(parse_targets "$TARGETS_FILE" "$PARSE_RUNID" "$([ $ALLOW_COLLIDE = 1 ] && echo --allow-collide)") \
  || { echo "target parsing failed" >&2; exit 2; }
[ -n "$(printf '%s' "$PARSED" | head -1)" ] || { echo "targets file has no targets" >&2; exit 2; }

if [ "$DRY_RUN" = 1 ]; then
  echo "════ DRY RUN — plan for $TARGETS_FILE (nothing executes) ════"
  printf '%s\n' "$PARSED" | awk -F'\t' '{printf "  %-24s %-32s %s\n", $1, $2, ($3==""?"(no instructions)":"instructions: "substr($3,1,60) (length($3)>60?"…":""))}'
  echo "slots: $SLOTS | timeouts: osint ${OSINT_TIMEOUT_H}h / active ${ACTIVE_TIMEOUT_H}h | launch-interval ${LAUNCH_INTERVAL}s | idle-sample ${IDLE_SAMPLE}s"
  echo "egress sidecar: ${GLUETUN_OPT:-auto-probe (gluetun, gluetun-za)}"
  echo "── stage-1 kickoff (all targets, identical):"
  printf '%s\n' "$PARSED" | head -1 | awk -F'\t' '{print "  " $1 ": " $2}'
  echo "── sample stage-2 message:"
  IFS=$'\t' read -r t u i <<< "$(printf '%s\n' "$PARSED" | head -1)"
  stage2_message "$u" "$t" "$i" | fold -sw 100 | sed 's/^/  /'
  echo "── colliding registry tags would error (pass --allow-collide to suffix); manual 3 never touched."
  exit 0
fi

# init state for new targets, and refresh capture-tag/instructions for adopted
# ones (resume with an edited targets.txt lets a queued target's instructions
# change; state/status is never modified here)
while IFS=$'\t' read -r tag url instr; do
  f=$(state_file "$RUNID" "$tag")
  if [ ! -f "$f" ] || [ "$(jq -r .url "$f" 2>/dev/null)" != "$url" ]; then
    state_init "$RUNID" "$tag" "$url" "$instr"
  else
    set_instructions "$RUNID" "$tag" "$instr"
  fi
done <<< "$PARSED"

# --------------------------------------------------------------- helpers --
pick_gluetun() {  # probe GLUETUN_OPT > gluetun > gluetun-za; prints name or fails
  local cands=()
  [ -n "$GLUETUN_OPT" ] && cands+=("$GLUETUN_OPT")
  cands+=(gluetun gluetun-za)
  local c
  for c in "${cands[@]}"; do
    docker inspect -f '{{.State.Running}}' "$c" >/dev/null 2>&1 || continue
    [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || continue
    local h; h=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo none)
    [ "$h" = unhealthy ] && continue
    echo "$c"; return 0
  done
  return 1
}

owned_running() {  # runner-owned containers currently running
  local f tag st c n=0
  for f in "$RUN_DIR"/state/*.json; do
    [ -f "$f" ] || continue
    tag=$(jq -r .tag "$f"); st=$(jq -r .status "$f")
    case "$st" in launched-osint|osint-done|active|done)
      [ "$(docker inspect -f '{{.State.Running}}' "eng-$tag" 2>/dev/null || echo false)" = true ] && n=$((n+1)) ;;
    esac
  done
  echo "$n"
}

net_progress_s() {  # transcript size + projects-dir mtime for manual stall triage
  echo "$(transcript_bytes "$1") $(stat -c %Y "$KALI_STATE/$1/claude/projects" 2>/dev/null || echo 0)"
}

fail_target() {  # fail_target <tag> <reason>
  local tag=$1; shift
  state_set_status "$RUNID" "$tag" failed "$*"
  log "FAILED  $tag — $*"; fleet_notify "$tag failed: $*"
}

state_set_status() {  # <runid> <tag> <status> <event> — quote-safe status+event write
  local f ts_key   # timeout logic reads .ts.launched for launched-osint
  case "$3" in launched-osint) ts_key=launched ;; *) ts_key=$3 ;; esac
  f=$(state_file "$1" "$2")
  jq --arg st "$3" --arg ev "$4" --arg now "$(date -Is)" --arg tsk "$ts_key" \
    '.status=$st | .ts[$tsk]=$now | .last_event=$ev' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

attempt_tick() {  # attempt_tick <tag> <reason> — increments attempts; fails at 3
  local tag=$1 n; shift
  n=$(state_get "$RUNID" "$tag" '.attempts + 1')
  update_event "$RUNID" "$tag" "$* (attempt $n/3)"
  [ "$n" -ge 3 ] && { fail_target "$tag" "3 attempts: $*"; return 1; }
  log "RETRY   $tag — $* (attempt $n/3)"
  return 0
}

# --------------------------------------------------------------- main loop --
log "fleet start: runid=$RUNID targets=$(printf '%s\n' "$PARSED" | wc -l) slots=$SLOTS"
ACTIVE_GLUETUN=""

while :; do
  ALL_TERMINAL=1

  # ---- per-target state machine ------------------------------------------
  for f in "$RUN_DIR"/state/*.json; do
    [ -f "$f" ] || continue
    tag=$(jq -r .tag "$f"); st=$(jq -r .status "$f")
    c="eng-$tag"

    case "$st" in
      queued) ALL_TERMINAL=0 ;;
      failed|done|retired) continue ;;

      launched-osint)
        ALL_TERMINAL=0
        if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo false)" != true ]; then
          # container gone: entries stay in registry (auto-restart owns recovery);
          # if it was REMOVED (not just exited), re-register via pinned env.
          if ! docker ps -a --format '{{.Names}}' | grep -q "^$c$"; then
            log "ADOPT   $tag container missing — re-registering via pinned env"
            FLEET_GLUETUN="$ACTIVE_GLUETUN" bash /root/communitytools/scripts/kali-eng.sh "$tag" "$(state_get "$RUNID" "$tag" '.url') — continue the OSINT engagement" >/dev/null 2>&1 || attempt_tick "$tag" "re-register failed"
          fi
          continue
        fi
        # timeout ceiling
        if [ "$(ts_age_s "$(state_get "$RUNID" "$tag" '.ts.launched')")" -gt $((OSINT_TIMEOUT_H*3600)) ]; then
          if pane_idle "$c" && [ -z "$(osint_artifact "$tag")" ]; then
            attempt_tick "$tag" "osint timeout ${OSINT_TIMEOUT_H}h reached (idle, no artifact)" && { :; }
            state_set "$RUNID" "$tag" ".ts.launched=\"$(date -Is)\""  # window resets on retry
          fi
          continue
        fi
        # artifact landed? then wait for idle and inject stage 2
        art=$(osint_artifact "$tag")
        if [ -n "$art" ]; then
          if docker exec "$c" tmux has-session -t eng 2>/dev/null; then
            if pane_idle "$c"; then
              b1=$(transcript_bytes "$tag")
              sleep "$IDLE_SAMPLE"
              # still idle after the sample window and bytes static → truly idle
              b2=$(transcript_bytes "$tag")
              if pane_idle "$c" && [ "$b1" = "$b2" ]; then
                url=$(state_get "$RUNID" "$tag" '.url'); instr=$(state_get "$RUNID" "$tag" '.instructions')
                msg=$(stage2_message "$url" "$tag" "$instr")
                if inject_stage2 "$c" "$msg"; then
                  state_set "$RUNID" "$tag" ".status=\"active\" | .ts.injected=\"$(date -Is)\" | .injections+=1 | .last_event=\"stage2 injected\""
                  log "ACTIVE  $tag — stage-2 injected (osint: $art)"
                  fleet_notify "$tag: OSINT done, active phase started"
                else
                  log "INJECT-RETRY $tag — send-keys failed, retrying next poll"
                fi
              fi
            fi
          fi
        fi
        ;;

      osint-done)  # legacy/transient bookkeeping: normalize to launched-osint —
                   # the artifact branch re-detects idempotently (a state file in
                   # this dead state otherwise blocks fleet exit forever)
        state_set "$RUNID" "$tag" '.status="launched-osint"'
        ALL_TERMINAL=0 ;;

      active)
        ALL_TERMINAL=0
        if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo false)" != true ]; then
          if ! docker ps -a --format '{{.Names}}' | grep -q "^$c$"; then
            log "ADOPT   $tag container missing mid-active — re-registering (resumes pinned session)"
            FLEET_GLUETUN="$ACTIVE_GLUETUN" bash /root/communitytools/scripts/kali-eng.sh "$tag" "Continue the active pentest engagement for $(state_get "$RUNID" "$tag" '.url') from its files — keep driving to the impact rungs" >/dev/null 2>&1 || attempt_tick "$tag" "re-register failed mid-active"
          fi
          continue
        fi
        art=$(active_artifact "$tag")
        if [ -n "$art" ]; then
          state_set_status "$RUNID" "$tag" done "technical report: $art"
          log "DONE    $tag — $art"
          fleet_notify "$tag: engagement complete (technical report written)"
          continue
        fi
        # timeout ceiling on stage 2
        if [ "$(ts_age_s "$(state_get "$RUNID" "$tag" '.ts.injected')")" -gt $((ACTIVE_TIMEOUT_H*3600)) ]; then
          if pane_idle "$c"; then
            attempt_tick "$tag" "active timeout ${ACTIVE_TIMEOUT_H}h reached (idle, no report)" && { :; }
            # re-nudge on retry
            docker exec "$c" tmux send-keys -t eng -l -- "Continue the active engagement — finish and write the technical report in reports/ now." 2>/dev/null && sleep 1 && docker exec "$c" tmux send-keys -t eng Enter 2>/dev/null || true
            state_set "$RUNID" "$tag" ".ts.injected=\"$(date -Is)\""
          fi
        fi
        ;;
    esac
  done

  # ---- slot accounting + launch -------------------------------------------
  OWNED=$(owned_running)
  # next queued target — also the slot-pressure trigger below. || true: a
  # corrupt state file must never kill the runner via command substitution.
  next_tag=$(jq -r 'select(.status=="queued") | .tag' "$RUN_DIR"/state/*.json 2>/dev/null | head -1 || true)
  if [ "$OWNED" -lt "$SLOTS" ]; then
    if [ -n "$next_tag" ]; then
      if [ -z "$ACTIVE_GLUETUN" ]; then
        if ! ACTIVE_GLUETUN=$(pick_gluetun); then
          log "PARK    no healthy gluetun sidecar — queue parked (no attempt consumed)"
          sleep 300; continue
        fi
      fi
      if fleet_preflight "$ACTIVE_GLUETUN" "$WS/.env.deepinfra" "launch $next_tag" 2>>"$RUN_DIR/fleet.log"; then
        if memory_gate 2>>"$RUN_DIR/fleet.log"; then
          url=$(state_get "$RUNID" "$next_tag" '.url')
          kickoff=$(osint_kickoff "$url")
          if FLEET_GLUETUN="$ACTIVE_GLUETUN" bash /root/communitytools/scripts/kali-eng.sh "$next_tag" "$kickoff" >>"$RUN_DIR/fleet.log" 2>&1; then
            # stamp ownership marker into the registry env (render/up source it; unknown keys ignored)
            grep -q '^FLEET_RUN=' "$ENGAGE_REG/$next_tag.env" 2>/dev/null || echo "FLEET_RUN=$RUNID" >> "$ENGAGE_REG/$next_tag.env"
            state_set_status "$RUNID" "$next_tag" "launched-osint" "launched via kali-eng (gluetun=$ACTIVE_GLUETUN)"
            log "LAUNCH  $next_tag ($((OWNED+1))/$SLOTS) — gluetun=$ACTIVE_GLUETUN"
            sleep "$LAUNCH_INTERVAL"
          else
            attempt_tick "$next_tag" "kali-eng.sh launch failed"
          fi
        else
          log "PARK    memory gate refused launch — queue parked"
          sleep 300
        fi
      else
        log "PARK    preflight failed — queue parked (no attempt consumed)"
        ACTIVE_GLUETUN=""   # re-probe next time
        sleep 300
      fi
    fi
  fi

  # ---- retirement under slot pressure -------------------------------------
  # A parked done target holds its container until a QUEUED target needs the
  # slot. The old `OWNED > SLOTS` gate was unreachable (the launch gate caps
  # OWNED at SLOTS, so exactly-full never retired anything and the queue
  # starved). Empty queue = done targets park until `fleet-runner.sh cleanup`.
  OWNED=$(owned_running)
  if [ "$OWNED" -ge "$SLOTS" ] && [ -n "$next_tag" ]; then
    victim=$(for f in "$RUN_DIR"/state/*.json; do
      jq -r 'select(.status=="done") | "\(.ts.done // "9999") \(.tag)"' "$f" 2>/dev/null || true
    done | sort | head -1 | awk '{print $2}')
    if [ -n "${victim:-}" ]; then
      retire_target "$RUNID" "$victim"
    fi
  fi

  # ---- exit when everything is terminal ------------------------------------
  NONTERMINAL=$(jq -s '[.[] | select(.status=="queued" or .status=="launched-osint" or .status=="osint-done" or .status=="active")] | length' "$RUN_DIR"/state/*.json 2>/dev/null || echo 0)
  if [ "$NONTERMINAL" = 0 ]; then
    log "fleet complete — summary:"
    for f in "$RUN_DIR"/state/*.json; do
      jq -r '"  \(.tag): \(.status) (\(.last_event))"' "$f"
    done | tee -a "$RUN_DIR/fleet.log"
    fleet_notify "fleet run $RUNID complete"
    exit 0
  fi

  sleep 30
done
