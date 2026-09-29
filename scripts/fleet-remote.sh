#!/usr/bin/env bash
# fleet-remote.sh — operator surface for fleet engagements across boxes.
# Resolves which box owns a tag (FLEET_BOXES), then runs the stock box-side
# primitives there: attach targets the container's own `eng` tmux session (the
# same pane `tmux attach -t pentest` shows, one hop further); relay is the
# runner's two-phase send-keys (-l then Enter) behind the overlay/busy guards.
# Automation rides ControlMaster ssh on its own ControlPath — an interactive
# pane never shares a master with the scripts (research: a stuck automation
# master must not take the operator's panes down with it).
#
#   fleet-remote.sh attach <tag>            open the harness pane (detach: Ctrl-b d)
#   fleet-remote.sh pane <tag> [-n LINES]   read-only capture-pane peek (default 40)
#   fleet-remote.sh relay <tag> "<text>" [--force]   guarded message injection
#   fleet-remote.sh which <tag>             print the exact attach command
#   fleet-remote.sh status [tag]            fleet-status.sh on the owning box
#   fleet-remote.sh logs [tag] [-n N]       tail the owning fleet's fleet.log
#   fleet-remote.sh mon [--box B]           attach the box's `pentest` monitor
#   fleet-remote.sh run <targets> [--box B] [-- runner-flags…]
#   fleet-remote.sh dry-run <targets> [--box B] [-- flags…]
#   fleet-remote.sh cleanup [--box B] [--all-done]
#
# Boxes come from FLEET_BOXES (default "local"): `local` or ssh-config aliases,
# space-separated; search order = resolution order. FLEET_STACK overrides the
# stack root (default /root/pentest-stack). FLEET_SSH_MODE=dispatch routes the
# pane/relay/has primitives through the box-side fleet-dispatch allowlist
# (hardened automation keys); the pass-through verbs (status/run/mon/cleanup)
# always use plain ssh aliases — pin those keys to the interactive profile.
set -euo pipefail
STACK=${FLEET_STACK:-/root/pentest-stack}
FLEET_BOXES=${FLEET_BOXES:-local}
SSH_MODE=${FLEET_SSH_MODE:-inline}
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
err()   { echo "fleet-remote: $*" >&2; }

valid_tag() { [[ "$1" =~ ^[a-z0-9][a-z0-9-]*$ ]]; }

# ---- transport ------------------------------------------------------------- --
# Snippets travel over stdin (`bash -s`): zero nested-shell quoting to get
# wrong, and the message body is base64 (safe charset at every layer).
box_ssh_opts=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=15
              -o ControlMaster=auto -o ControlPath="$HOME/.ssh/fleet-cm-%C"
              -o ControlPersist=10m)

run_snippet() {  # run_snippet <box> <snippet> — automation path, rc propagates
  local box=$1 snip=$2
  if [ "$box" = local ]; then bash -s <<< "$snip"; else
    printf '%s' "$snip" | ssh "${box_ssh_opts[@]}" "$box" bash -s
  fi
}

run_verb() {  # run_verb <box> <verb> [args…] — dispatch-mode primitive
  local box=$1; shift
  if [ "$box" = local ]; then bash "$SELF_DIR/fleet-dispatch.sh" "$@"; else
    ssh "${box_ssh_opts[@]}" "$box" fleet-dispatch "$@"
  fi
}

# ---- primitives (inline / dispatch are the two transports of the same ops) -- -
snip_has() {  # <tag> → rc 0 iff the box's fleet state claims the tag
  printf 'for f in "%s/fleet/active/state/%s.json" "%s/fleet/"*"/state/%s.json"; do [ -f "$f" ] && exit 0; done; exit 1' \
    "$STACK" "$1" "$STACK" "$1"
}

snip_pane() {  # <tag> → visible pane text
  printf 'docker exec eng-%s tmux capture-pane -pt eng 2>/dev/null' "$1"
}

snip_relay() {  # <tag> <b64-message> <force 0|1> — guarded two-phase injection.
  # Protocol (v1|relay, learned live 2026-09-29): NEVER send x or Escape.
  #   x      — races the overlay's own dismissal; lands in the input line
  #            ("xOperator…") and, in the current UI, x = "stop agent".
  #   Escape — interrupts a live turn whose busy signature is not rendered
  #            (subagent phases) — leaves "Interrupted· What should Claude do".
  #   The runner's x-clear works only because it RETRIES at poll cadence; an
  #   operator tool must be single-shot and honest instead:
  #     1. refuse while an agents overlay is up (they auto-dismiss — retry)
  #     2. refuse a pane that RENDERS busy (visible turn / API park) unless
  #        --force; an invisibly-running turn is still SAFE: type+Enter just
  #        stages in the input buffer until the turn completes
  #     3. type + Enter (the runner's two-phase submit)
  #     4. verify visibility of the probe text and report staged vs submitted
  printf '
c=eng-%s
m=$(printf %%s %s | base64 -d)
pane=$(docker exec "$c" tmux capture-pane -pt eng 2>/dev/null || true)
if printf "%%s" "$pane" | grep -q "Enter to view"; then
  echo "RELAY REFUSED: agents overlay is up (auto-dismisses) — retry in a moment"; exit 2
fi
if [ "%s" != 1 ] && printf "%%s" "$pane" | grep -qiE "esc to interrupt|API Error|Unable to connect|Retrying"; then
  echo "RELAY REFUSED: pane busy (mid-turn or API park) — retry after the turn or pass --force"; exit 3
fi
docker exec "$c" tmux send-keys -t eng -l -- "$m" || { echo "RELAY FAIL: send-keys -l failed"; exit 4; }
sleep 1
docker exec "$c" tmux send-keys -t eng Enter || { echo "RELAY FAIL: Enter failed"; exit 5; }
sleep 2
pane=$(docker exec "$c" tmux capture-pane -pt eng 2>/dev/null || true)
probe=$(printf "%%s" "$m" | head -c 15)
if printf "%%s" "$pane" | grep -qF "$probe"; then
  echo "RELAYED to $c (staged: a turn is still running — submits when it completes)"
else
  echo "RELAYED to $c (submitted)"
fi
' "$1" "$2" "$3"
}

has_tag() {  # <box> <tag> → rc 0 iff owned there
  if [ "$SSH_MODE" = dispatch ]; then run_verb "$1" has "$2"; else
    run_snippet "$1" "$(snip_has "$2")"
  fi
}

do_pane() {  # <box> <tag> <lines>
  local out=""
  if [ "$SSH_MODE" = dispatch ]; then out=$(run_verb "$1" pane "$2"); else
    out=$(run_snippet "$1" "$(snip_pane "$2")")
  fi
  printf '%s\n' "$out" | tail -n "$3"
}

do_relay() {  # <box> <tag> <text> <force>
  local b64; b64=$(printf '%s' "$3" | base64 -w0)
  if [ "$SSH_MODE" = dispatch ]; then
    printf '%s' "$b64" | run_verb "$1" relay "$2" $([ "$4" = 1 ] && echo --force)
  else
    run_snippet "$1" "$(snip_relay "$2" "$b64" "$4")"
  fi
}

# ---- resolution -------------------------------------------------------------
resolve_box() {  # <tag> → prints owning box; errors otherwise
  local b
  for b in $FLEET_BOXES; do
    if has_tag "$b" "$1"; then echo "$b"; return 0; fi
  done
  err "no fleet state for tag '$1' on: $FLEET_BOXES"
  return 1
}

default_box() {  # local if listed, else the first box
  local b
  for b in $FLEET_BOXES; do [ "$b" = local ] && { echo local; return 0; }; done
  echo "${FLEET_BOXES%% *}"
}

# ---- pass-through verbs (stock scripts on the box) -------------------------- --
pass_runner() {  # <box> <targets-file|-> <extra-flags…>
  local box=$1 file=$2; shift 2
  if [ "$box" = local ]; then
    bash "$STACK/fleet-runner.sh" "$file" "$@"
  else
    local remote="/tmp/fleet-remote-$(date +%s)-$(basename "$file")"
    scp -q "${box_ssh_opts[@]:0:1}" "$file" "$box:$remote" 2>/dev/null \
      || scp -q "$file" "$box:$remote"
    ssh "${box_ssh_opts[@]}" "$box" bash "$STACK/fleet-runner.sh" "$remote" "$@"
  fi
}

# ---- main ------------------------------------------------------------------------------------------------
main() {
  local cmd=${1:-} tag box n=40 lines=30
  local file="" extra=""
  [ $# -ge 1 ] || usage 1
  case "$cmd" in
    -h|--help|help) usage 0 ;;
  esac
  shift

  case "$cmd" in
    attach)
      [ $# -ge 1 ] || { err "usage: fleet-remote.sh attach <tag>"; exit 1; }
      tag=$1; valid_tag "$tag" || { err "invalid tag '$tag'"; exit 1; }
      box=$(resolve_box "$tag") || exit 1
      echo "# box: $box — detach with Ctrl-b d"
      if [ "$box" = local ]; then
        exec docker exec -it "eng-$tag" tmux attach -t eng
      else
        exec ssh -tt "$box" docker exec -it "eng-$tag" tmux attach -t eng
      fi
      ;;
    pane)
      [ $# -ge 1 ] || { err "usage: fleet-remote.sh pane <tag> [-n LINES]"; exit 1; }
      tag=$1; shift; while [ $# -gt 0 ]; do case "$1" in
        -n) n=$2; shift 2 ;; *) err "unknown flag: $1"; exit 1 ;; esac; done
      valid_tag "$tag" || { err "invalid tag '$tag'"; exit 1; }
      box=$(resolve_box "$tag") || exit 1
      do_pane "$box" "$tag" "$n"
      ;;
    relay)
      err 'relay is handled pre-main; unreachable'; exit 1 ;;
    which)
      [ $# -ge 1 ] || { err "usage: fleet-remote.sh which <tag>"; exit 1; }
      tag=$1; valid_tag "$tag" || { err "invalid tag '$tag'"; exit 1; }
      box=$(resolve_box "$tag") || exit 1
      if [ "$box" = local ]; then
        echo "docker exec -it eng-$tag tmux attach -t eng   # on this box"
      else
        echo "ssh -tt $box docker exec -it eng-$tag tmux attach -t eng"
      fi
      ;;
    status|logs)
      tag=""
      while [ $# -gt 0 ]; do case "$1" in
        -n) lines=$2; shift 2 ;;
        *) tag=$1; shift ;; esac; done
      if [ -n "$tag" ]; then valid_tag "$tag" || { err "invalid tag '$tag'"; exit 1; }
        box=$(resolve_box "$tag") || exit 1
      else
        box=$(default_box)
      fi
      if [ "$cmd" = status ]; then
        if [ "$box" = local ]; then bash "$STACK/fleet-status.sh"; else
          ssh "${box_ssh_opts[@]}" "$box" bash "$STACK/fleet-status.sh"
        fi
      else
        run_snippet "$box" "$(printf 'd=$(readlink -f "%s/fleet/active" 2>/dev/null || true); [ -n "$d" ] && [ -d "$d" ] && tail -n %s "$d/fleet.log"' "$STACK" "$lines")"
      fi
      ;;
    mon)
      while [ $# -gt 0 ]; do case "$1" in
        --box) shift; box=$1; shift ;; *) err "unknown flag: $1"; exit 1 ;; esac; done
      box=${box:-$(default_box)}
      if [ "$box" = local ]; then exec tmux attach -t pentest; else
        exec ssh -tt "$box" tmux attach -t pentest
      fi
      ;;
    run|dry-run)
      [ $# -ge 1 ] || { err "usage: fleet-remote.sh $cmd <targets-file> [--box B] [-- runner-flags…]"; exit 1; }
      file=$1; shift
      box=""
      while [ $# -gt 0 ]; do case "$1" in
        --box) box=$2; shift 2 ;;
        --) shift; break ;;
        *) err "unknown flag: $1 (runner flags go after --)"; exit 1 ;; esac; done
      [ -f "$file" ] || { err "no such targets file: $file"; exit 1; }
      box=${box:-$(default_box)}
      if [ "$cmd" = dry-run ]; then set -- "$@" --dry-run; fi
      pass_runner "$box" "$file" "$@"
      ;;
    cleanup)
      while [ $# -gt 0 ]; do case "$1" in
        --box) shift; box=$1; shift ;;
        --all-done) extra="--all-done"; shift ;;
        *) err "unknown flag: $1"; exit 1 ;; esac; done
      box=${box:-$(default_box)}
      if [ "$box" = local ]; then bash "$STACK/fleet-runner.sh" cleanup $extra; else
        ssh "${box_ssh_opts[@]}" "$box" bash "$STACK/fleet-runner.sh" cleanup $extra
      fi
      ;;
    *)
      err "unknown command: $cmd"; usage 1 ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  # relay message extraction: `relay <tag> <msg words…> [--force]` — pull the
  # message out BEFORE main's flag loop mangles positional args.
  if [ "${1:-}" = relay ] && [ $# -ge 2 ]; then
    _tag=$2; shift 2
    _force=0
    while [ $# -gt 0 ] && [ "$1" = "--force" ]; do _force=1; shift; done
    msg="$*"
    [ -n "$msg" ] || { err "relay: empty message"; exit 1; }
    valid_tag "$_tag" || { err "invalid tag '$_tag'"; exit 1; }
    box=$(resolve_box "$_tag") || exit 1
    do_relay "$box" "$_tag" "$msg" "$_force"
    exit $?
  fi
  main "$@"
fi
