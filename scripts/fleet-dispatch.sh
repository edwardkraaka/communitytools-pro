#!/usr/bin/env bash
# fleet-dispatch.sh — box-side allowlist wrapper for fleet automation over ssh.
# Install at /usr/local/bin/fleet-dispatch on every worker box and pin the
# automation-key authorized_keys line to it (research upgrade #3):
#   restrict,from="<hub-ip>",command="/usr/local/bin/fleet-dispatch" ssh-ed25519 AAAA… fleet-hub-automation
# The wrapper is the ONLY thing that key can run — docker-group access is
# root-equivalent, so the allowlist is the real boundary. Attack surface: two
# read-only verbs (has/pane), one guarded write verb (relay) whose message is
# a base64 blob already stripped of newlines by the caller.
#
#   fleet-dispatch has <tag>              rc 0 iff a fleet state file claims the tag
#   fleet-dispatch pane <tag>             visible pane text
#   fleet-dispatch relay <tag> <b64> [--force]   guarded two-phase injection
set -uo pipefail   # NOT -e: the wrapper answers every bad call with rc≠0 itself
STACK=${FLEET_STACK:-/root/pentest-stack}

err() { echo "fleet-dispatch: $*" >&2; }

valid_tag() { [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,23}$ ]]; }

cmd=${1:-}
[ -n "$cmd" ] || { err "no verb (has|pane|relay)"; exit 1; }
shift

case "$cmd" in
  has)
    [ $# -eq 1 ] || { err "usage: fleet-dispatch has <tag>"; exit 1; }
    valid_tag "$1" || { err "invalid tag"; exit 1; }
    for f in "$STACK"/fleet/active/state/"$1".json "$STACK"/fleet/*/state/"$1".json; do
      [ -f "$f" ] && exit 0
    done
    exit 1
    ;;
  pane)
    [ $# -eq 1 ] || { err "usage: fleet-dispatch pane <tag>"; exit 1; }
    valid_tag "$1" || { err "invalid tag"; exit 1; }
    c="eng-$1"
    docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
      || { err "container $c not running"; exit 2; }
    docker exec "$c" tmux capture-pane -pt eng 2>/dev/null
    ;;
  relay)
    [ $# -eq 2 ] || [ $# -eq 3 ] || { err "usage: fleet-dispatch relay <tag> <b64> [--force]"; exit 1; }
    tag=$1 b64=$2 force=${3:-}
    [ "$force" = "--force" ] || [ -z "$force" ] || { err "third arg must be --force"; exit 1; }
    valid_tag "$tag" || { err "invalid tag"; exit 1; }
    # decode strictly: base64 alphabet only (rejects any shell metachar) —
    # validated BEFORE any container interaction
    case "$b64" in
      *[!A-Za-z0-9+/=]*) err "not a base64 blob"; exit 1 ;;
    esac
    c="eng-$tag"
    docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
      || { err "container $c not running"; exit 2; }
    # decode strictly: base64 alphabet only (rejects any shell metachar)
    case "$b64" in
      *[!A-Za-z0-9+/=]*) err "not a base64 blob"; exit 1 ;;
    esac
    msg=$(printf '%s' "$b64" | base64 -d 2>/dev/null) || { err "bad base64"; exit 1; }
    [ -n "$msg" ] || { err "empty message"; exit 1; }
    pane=$(docker exec "$c" tmux capture-pane -pt eng 2>/dev/null || true)
    # NEVER send x or Escape here (live-learned 2026-09-29): x races the
    # overlay dismissal into the input line; Escape interrupts invisible live
    # turns. Refuse instead — overlays auto-dismiss, retry wins.
    if printf '%s' "$pane" | grep -q 'Enter to view'; then
      echo "RELAY REFUSED: agents overlay is up (auto-dismisses) — retry in a moment"; exit 3
    fi
    if [ -z "$force" ] && printf '%s' "$pane" | grep -qiE 'esc to interrupt|API Error|Unable to connect|Retrying'; then
      echo "RELAY REFUSED: pane busy (mid-turn or API park) — retry after the turn or pass --force"; exit 4
    fi
    docker exec "$c" tmux send-keys -t eng -l -- "$msg" || { echo "RELAY FAIL: send-keys -l failed"; exit 5; }
    sleep 1
    docker exec "$c" tmux send-keys -t eng Enter || { echo "RELAY FAIL: Enter failed"; exit 6; }
    sleep 2
    pane=$(docker exec "$c" tmux capture-pane -pt eng 2>/dev/null || true)
    probe=$(printf '%s' "$msg" | head -c 15)
    if printf '%s' "$pane" | grep -qF "$probe"; then
      echo "RELAYED to $c (staged: a turn is still running — submits when it completes)"
    else
      echo "RELAYED to $c (submitted)"
    fi
    ;;
  *)
    err "verb not on the allowlist: $cmd"; exit 1 ;;
esac
