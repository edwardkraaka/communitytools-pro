#!/usr/bin/env bash
# kali-resume-entrypoint.sh — crash/reboot-resilient launcher for a pentest engagement.
# Runs claude inside tmux so the initial kickoff (or a resume nudge) can be submitted
# programmatically, and so the session can be observed/driven with:
#     docker exec -it <container> tmux attach -t eng
#
# Required env (from the compose service):
#   ENGAGEMENT_SESSION_ID   pinned uuid for this engagement's claude session
#   ENGAGEMENT_KICKOFF      first input on a FRESH start, e.g. "/osint example.com"
# Optional:
#   ENGAGEMENT_CWD          working dir (default /workspace)
#   ENGAGEMENT_RESUME_NUDGE input sent on RESUME to re-arm the /loop (default: the
#                           lean-coordinator nudge — re-read state, run nothing inline,
#                           fan out 3-5 parallel background executors, collect via
#                           TaskOutput, sole ledger writer, artifacts by path)
#   ENGAGEMENT_STAGGER_S    seconds to sleep before launch (gateway burst
#                           protection; compose assigns 0/30/60 per slot)
#
# --- Stall watchdog (added Sep 17 2026) -------------------------------------------
# Claude parks ALIVE at API-error screens: the process never exits, so Docker's
# restart policy never fires — the 58h silent stall of Sep 13-16. The old watch
# loop only noticed process DEATH. It now also kills the tmux session (= non-zero
# exit = restart = --resume) on:
#   TRIP B error park    : transcript's newest API-error record (isApiErrorMessage:
#                          true, apiErrorStatus 4xx) has had NO byte growth after it
#                          for ENG_ERR_MIN(5m). 429s self-recover at limit reset, so
#                          they get ENG_RATELIMIT_MIN(120m) instead.
#   TRIP A context stall : zero transcript growth for ENG_STALL_MIN(60m) AND a
#                          confirming signature in the pane scrollback (error
#                          banner / Retrying). A CLEAN idle prompt is NEVER killed:
#                          the engagement /loop legitimately rests between batches.
#   TRIP T turn ceiling  : zero growth for ENG_TURN_MIN(90m) while the pane still
#                          shows an in-flight turn ("esc to interrupt") — bounds
#                          blackholed connections and retry stacks.
#   TRIP R ready ceiling : TUI never became ready (40x3s fast + ENG_READY_MIN slow
#                          polls). The old code warned here and hung forever with
#                          the first input never submitted.
# Liveness = the SUM OF BYTES of every ~/.claude/projects/**/*.jsonl. An idle
# claude still touches its transcript hourly with IDENTICAL size (observed Sep
# 17), so mtime alone would lie — only growth counts. Subagent transcripts and
# compact forks are covered by the sum.
# Circuit breaker: consecutive cycles that ended with zero growth are counted in
# $HOME/.claude/stall-cycles.json (bind-mounted, survives restarts). At 5, each
# cycle starts with an ENG_COOLDOWN_MIN(15m) sleep — stop burning provider quota
# against a hard-down gateway.
set -u

set -a; source /workspace/.env.deepinfra 2>/dev/null || true; set +a
export CLAUDE_CODE_TMPDIR=/tmp/cr; mkdir -p /tmp/cr

CWD="${ENGAGEMENT_CWD:-/workspace}"; cd "$CWD" 2>/dev/null || cd /workspace
SID="${ENGAGEMENT_SESSION_ID:?ENGAGEMENT_SESSION_ID is required}"
NUDGE="${ENGAGEMENT_RESUME_NUDGE:-Resume this engagement: re-read experiments.md and attack-chain.md (and session-memory.md if present), then re-enter the /loop and continue from where you left off. Stay a lean coordinator: run no experiment or scan tool calls inline — spawn 3-5 background executors on independent surfaces as ONE message of parallel Agent blocks with run_in_background, collect their reports with TaskOutput, write the ledgers yourself, and keep any command output or screenshots in engagement artifact files referenced by path. If an executor dies on a rate-limit error, halve the next batch width and wait rather than re-spawning at full width.}"
SESS=eng

# --- watchdog knobs (minutes unless _S = seconds); overridable via compose env ---
POLL_S="${ENG_POLL_S:-30}"
STALL_MIN="${ENG_STALL_MIN:-60}"      # Trip A: no-growth window (confirm w/ pane)
ERR_MIN="${ENG_ERR_MIN:-5}"           # Trip B: grace after a 4xx error record
RL_MIN="${ENG_RATELIMIT_MIN:-120}"    # Trip B tolerance for 429 (self-recovering)
TURN_MIN="${ENG_TURN_MIN:-90}"        # Trip T: in-flight turn hard ceiling
READY_MIN="${ENG_READY_MIN:-5}"       # Trip R: slow readiness window
COOLDOWN_MIN="${ENG_COOLDOWN_MIN:-15}"
BREAKER_N=5

ts() { date '+%F %T'; }

# --- total bytes across all session transcripts = the progress signal -----------
bytes_total() { find "$HOME/.claude/projects" -name '*.jsonl' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'; }

# newest API-error status in the registered transcript's tail window, else empty.
# Real serialization (Sep 17 fleet): "error":"...","isApiErrorMessage":true,
# "apiErrorStatus":429 — adjacent keys, and benign "No response requested."
# records carry isApiErrorMessage:false so they never match.
last_err_status() {
  tail -n 25 "$TR" 2>/dev/null \
    | grep -o '"isApiErrorMessage":true,"apiErrorStatus":[0-9][0-9]*' \
    | tail -1 | grep -o '[0-9][0-9]*$'
}

# --- circuit breaker state (on the bind mount) ------------------------------------
STALL_STATE="$HOME/.claude/stall-cycles.json"
cycles=0
[ -f "$STALL_STATE" ] && cycles=$(cat "$STALL_STATE" 2>/dev/null || echo 0)
case "$cycles" in ''|*[!0-9]*) cycles=0 ;; esac
if [ "$cycles" -ge "$BREAKER_N" ]; then
  echo "[$(ts)] [watchdog] breaker open: $cycles no-growth cycles — cooling ${COOLDOWN_MIN}m before launch"
  sleep $(( COOLDOWN_MIN * 60 ))
fi

# Stagger fleet-wide restarts: the gateway refuses bursts of new connections from
# one exit IP (observed Sep 16), so mass restart/watchdog-recreate must not thunder.
if [ "${ENGAGEMENT_STAGGER_S:-0}" -gt 0 ] 2>/dev/null; then
  echo "[$(ts)] [watchdog] staggering launch by ${ENGAGEMENT_STAGGER_S}s"
  sleep "${ENGAGEMENT_STAGGER_S:-0}"
fi

# Tools whose schemas omit "required" (CronList, EnterWorktree, TaskList, TaskStop,
# Workflow, ...): the gateway's Anthropic->OpenAI conversion turns the missing key into
# "required": null, and the GLM backend rejects the WHOLE request with
# 400 "All target providers failed" — claude then halts at the error screen with the
# process alive, so the restart policy never fires (silent infinite stall, Sep 13-16
# 2026). The interactive pane fleet passes this exact list and never hit the bug.
# Same list keeps eng-* and pane fleets behaviorally identical.
DISALLOWED="EnterPlanMode,EnterWorktree,ExitPlanMode,ExitWorktree,CronList,ListAgents,ScheduleWakeup,TaskList,TaskStop,Workflow"

# --- Seed onboarding-complete config so no first-run wizard ever blocks the TUI. ---
# settings.json lives inside the persisted ~/.claude volume; write it once.
mkdir -p "$HOME/.claude"
[ -f "$HOME/.claude/settings.json" ] || printf '%s\n' '{"theme":"dark","skipDangerousModePermissionPrompt":true}' > "$HOME/.claude/settings.json"
# ~/.claude.json lives OUTSIDE the mounted .claude dir (ephemeral per container), so
# seed it every start: mark global onboarding done + trust this project dir.
python3 - "$CWD" <<'PY' 2>/dev/null || true
import json,os,sys
p=os.path.expanduser("~/.claude.json"); cwd=sys.argv[1]
try: d=json.load(open(p))
except Exception: d={}
d["hasCompletedOnboarding"]=True; d.setdefault("lastOnboardingVersion","2.1.197")
e=d.setdefault("projects",{}).setdefault(cwd,{})
e.update({"hasTrustDialogAccepted":True,"hasCompletedProjectOnboarding":True,
          "projectOnboardingSeenCount":max(1,e.get("projectOnboardingSeenCount",0)),
          "hasClaudeMdExternalIncludesApproved":True})
json.dump(d,open(p,"w"))
PY

# --- Fresh vs resume: does this session id already have a transcript on the volume? ---
# Force the gateway-valid model on resume: old conversations carry the model name
# they were PINNED to (e.g. "glm-5.3", removed from the gateway ~Sep 13 2026). A resumed
# session re-sends it -> 400 "All target providers failed" -> claude halts at the
# error screen with the process alive, so the restart policy never fires: silent infinite stall.
# --model overrides the conversation's pin with the env default (tob-glm-5.3).
if ls "$HOME"/.claude/projects/*/"$SID".jsonl >/dev/null 2>&1; then
  MODE=resume; START="claude --resume $SID --model ${ANTHROPIC_DEFAULT_OPUS_MODEL:-tob-glm-5.3} --dangerously-skip-permissions --disallowedTools \"$DISALLOWED\""; FIRST_INPUT="$NUDGE"
else
  MODE=fresh;  START="claude --session-id $SID --model ${ANTHROPIC_DEFAULT_OPUS_MODEL:-tob-glm-5.3} --dangerously-skip-permissions --disallowedTools \"$DISALLOWED\""; FIRST_INPUT="${ENGAGEMENT_KICKOFF:-}"
fi
echo "[$(ts)] [entrypoint] mode=$MODE cwd=$CWD sid=$SID transcript-bytes=$(bytes_total)"

tmux new-session -d -s "$SESS" -x 220 -y 50 "$START; echo __CLAUDE_EXITED__; sleep 3"

# Wait for the main TUI to be ready (status line shows the permission-mode hint),
# then submit the first input (kickoff or resume nudge). Two-stage: fast 40x3s
# poll, then a slow ENG_READY_MIN window for huge-transcript loads (100% context).
# If still not ready, TRIP R: kill for restart+resume instead of hanging forever.
if [ -n "$FIRST_INPUT" ]; then
  ready=0
  for _ in $(seq 1 40); do
    pane=$(tmux capture-pane -pt "$SESS" 2>/dev/null || true)
    echo "$pane" | grep -qiE 'bypass permissions|for shortcuts|esc to interrupt' && { ready=1; break; }
    echo "$pane" | grep -q '__CLAUDE_EXITED__' && break
    sleep 3
  done
  if [ "$ready" != 1 ]; then
    rdeadline=$(( $(date +%s) + READY_MIN * 60 ))
    while [ "$(date +%s)" -lt "$rdeadline" ]; do
      pane=$(tmux capture-pane -pt "$SESS" 2>/dev/null || true)
      echo "$pane" | grep -qiE 'bypass permissions|for shortcuts|esc to interrupt' && { ready=1; break; }
      echo "$pane" | grep -q '__CLAUDE_EXITED__' && break
      sleep 10
    done
  fi
  if [ "$ready" = 1 ]; then
    sleep 2
    tmux send-keys -t "$SESS" -l "$FIRST_INPUT"   # -l = literal, safe for spaces/slashes
    sleep 1; tmux send-keys -t "$SESS" Enter
    echo "[$(ts)] [entrypoint] submitted first input ($MODE)"
  else
    echo "[$(ts)] [watchdog] TRIP R: TUI never became ready (${READY_MIN}m window) — killing for restart+resume"
    tmux kill-session -t "$SESS" 2>/dev/null
  fi
fi

# --- Watch loop: notice BOTH process death (original) and stalls (new) ------------
# Baselines: growth ratchet = transcript byte sum; TR = this session's transcript.
TR=$(ls "$HOME"/.claude/projects/*/"$SID".jsonl 2>/dev/null | head -1)
base_bytes=$(bytes_total)          # progress for THIS cycle is measured against this
last_bytes=$base_bytes
last_growth=$(date +%s)            # epoch of last byte growth
err_size=$base_bytes               # byte sum when the current tail error was first seen
err_since=$(date +%s)              # ...and when we first saw it
idle_logged=0

while tmux has-session -t "$SESS" 2>/dev/null; do
  [ "$(tmux list-panes -t "$SESS" -F '#{pane_dead}' 2>/dev/null | head -1)" = "1" ] && break
  tmux capture-pane -pt "$SESS" 2>/dev/null | grep -q '__CLAUDE_EXITED__' && break

  now=$(date +%s)
  bytes_now=$(bytes_total)

  # --- liveness: byte growth anywhere in the transcript tree ---------------------
  if [ "$bytes_now" -gt "$last_bytes" ]; then
    last_bytes=$bytes_now; last_growth=$now; idle_logged=0
  fi
  idle_s=$(( now - last_growth ))

  # --- TRIP B: parked on an API error ----------------------------------------
  # fresh sessions create the transcript AFTER first input; re-resolve until it appears
  [ -n "$TR" ] || TR=$(ls "$HOME"/.claude/projects/*/"$SID".jsonl 2>/dev/null | head -1)
  if [ -n "$TR" ]; then
    st=$(last_err_status)
    if [ -n "$st" ]; then
      if [ "$bytes_now" -gt "$err_size" ]; then
        # bytes grew after the error was first seen: the turn moved on (recovered)
        err_size=$bytes_now; err_since=$now
      else
        parked_s=$(( now - err_since ))
        if [ "$st" = 429 ]; then
          if [ "$parked_s" -ge $(( RL_MIN * 60 )) ]; then
            echo "[$(ts)] [watchdog] TRIP B: parked on 429 rate-limit for ${parked_s}s (>= ${RL_MIN}m) — killing for restart"
            tmux kill-session -t "$SESS" 2>/dev/null; break
          fi
        elif [ "$parked_s" -ge $(( ERR_MIN * 60 )) ]; then
          echo "[$(ts)] [watchdog] TRIP B: parked on API error HTTP $st for ${parked_s}s — killing for restart"
          tmux kill-session -t "$SESS" 2>/dev/null; break
        fi
      fi
    else
      # no error in the tail window: keep the error clock armed fresh
      err_size=$bytes_now; err_since=$now
    fi
  fi

  if [ "$idle_s" -ge $(( STALL_MIN * 60 )) ]; then
    sig=$(tmux capture-pane -pt "$SESS" -S -300 2>/dev/null || true)
    if echo "$sig" | grep -qiE 'API Error|Unable to connect|Connection refused|ConnectionRefused|No response from API|Retrying'; then
      echo "[$(ts)] [watchdog] TRIP A: no transcript growth for ${idle_s}s + pane error signature — killing for restart"
      tmux kill-session -t "$SESS" 2>/dev/null; break
    fi
    if echo "$sig" | grep -qi 'esc to interrupt' && [ "$idle_s" -ge $(( TURN_MIN * 60 )) ]; then
      echo "[$(ts)] [watchdog] TRIP T: in-flight turn silent for ${idle_s}s (>= ${TURN_MIN}m ceiling) — killing for restart"
      tmux kill-session -t "$SESS" 2>/dev/null; break
    fi
    if [ "$idle_logged" = 0 ]; then
      echo "[$(ts)] [watchdog] note: ${idle_s}s without transcript growth, clean idle prompt — standing down (engagement between batches is normal)"
      idle_logged=1
    fi
  fi

  sleep "$POLL_S"
done

# --- Exit: progress accounting + circuit breaker ----------------------------------
end_bytes=$(bytes_total)
if [ "$end_bytes" -gt "$base_bytes" ]; then
  if [ "$cycles" != 0 ]; then echo "[$(ts)] [watchdog] progress this cycle ($(( end_bytes - base_bytes )) bytes) — stall counter reset to 0"; fi
  cycles=0
else
  cycles=$(( cycles + 1 ))
  echo "[$(ts)] [watchdog] cycle ended with ZERO transcript growth — stall counter $cycles/$BREAKER_N"
fi
echo "$cycles" > "$STALL_STATE" 2>/dev/null || true
echo "[$(ts)] [entrypoint] claude ended — exiting for restart"
exit 1
