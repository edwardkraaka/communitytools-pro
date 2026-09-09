#!/usr/bin/env bash
# kali-resume-entrypoint.sh — crash/reboot-resilient launcher for a pentest engagement.
# Runs claude inside tmux so the initial kickoff (or a resume nudge) can be submitted
# programmatically, and so the session can be observed/driven with:
#     docker exec -it <container> tmux attach -t eng
#
# Required env (from the compose service):
#   ENGAGEMENT_SESSION_ID   pinned uuid for this engagement's claude session
#   ENGAGEMENT_KICKOFF      first input on a FRESH start, e.g. "/osint wild.io"
# Optional:
#   ENGAGEMENT_CWD          working dir (default /workspace)
#   ENGAGEMENT_RESUME_NUDGE input sent on RESUME to re-arm the /loop
set -u

set -a; source /workspace/.env.deepinfra 2>/dev/null || true; set +a
export CLAUDE_CODE_TMPDIR=/tmp/cr; mkdir -p /tmp/cr

CWD="${ENGAGEMENT_CWD:-/workspace}"; cd "$CWD" 2>/dev/null || cd /workspace
SID="${ENGAGEMENT_SESSION_ID:?ENGAGEMENT_SESSION_ID is required}"
NUDGE="${ENGAGEMENT_RESUME_NUDGE:-Resume this engagement: re-read experiments.md and attack-chain.md, then re-enter the /loop and continue from where you left off.}"
SESS=eng

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
if ls "$HOME"/.claude/projects/*/"$SID".jsonl >/dev/null 2>&1; then
  MODE=resume; START="claude --resume $SID --dangerously-skip-permissions"; FIRST_INPUT="$NUDGE"
else
  MODE=fresh;  START="claude --session-id $SID --dangerously-skip-permissions"; FIRST_INPUT="${ENGAGEMENT_KICKOFF:-}"
fi
echo "[entrypoint] mode=$MODE cwd=$CWD sid=$SID"

tmux new-session -d -s "$SESS" -x 220 -y 50 "$START; echo __CLAUDE_EXITED__; sleep 3"

# Wait for the main TUI to be ready (status line shows the permission-mode hint),
# then submit the first input (kickoff or resume nudge).
if [ -n "$FIRST_INPUT" ]; then
  ready=0
  for _ in $(seq 1 40); do
    pane=$(tmux capture-pane -pt "$SESS" 2>/dev/null || true)
    echo "$pane" | grep -qiE 'bypass permissions|for shortcuts|esc to interrupt' && { ready=1; break; }
    echo "$pane" | grep -q '__CLAUDE_EXITED__' && break
    sleep 3
  done
  if [ "$ready" = 1 ]; then
    sleep 2
    tmux send-keys -t "$SESS" -l "$FIRST_INPUT"   # -l = literal, safe for spaces/slashes
    sleep 1; tmux send-keys -t "$SESS" Enter
    echo "[entrypoint] submitted first input ($MODE)"
  else
    echo "[entrypoint] WARNING: TUI never became ready; first input NOT submitted"
  fi
fi

# Keep the container alive tied to claude's lifetime; exit non-zero when claude dies so
# the restart policy relaunches (which then takes the --resume branch).
while tmux has-session -t "$SESS" 2>/dev/null; do
  [ "$(tmux list-panes -t "$SESS" -F '#{pane_dead}' 2>/dev/null | head -1)" = "1" ] && break
  tmux capture-pane -pt "$SESS" 2>/dev/null | grep -q '__CLAUDE_EXITED__' && break
  sleep 5
done
echo "[entrypoint] claude ended — exiting for restart"
exit 1
