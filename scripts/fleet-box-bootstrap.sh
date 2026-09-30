#!/usr/bin/env bash
# fleet-box-bootstrap.sh — one-shot bring-up of a fleet worker box. Runs ON the
# new box (as root), not the hub. Converges: repo, images, gluetun device,
# registry, systemd units, deploy-check. Idempotent — safe to re-run; finished
# steps are detected and skipped. Pattern-borrowed from tools/provision_vantage.sh
# (mode blocks, dry-run seam, labeled GC), deliberately NOT calling it: that
# tool is engagement-coupled (attack-vm ledger, 2h TTL) and wrong for a
# long-lived fleet box.
# Deployed at /root/pentest-stack/ with the docker-compose engagement stack;
# this is the tracked copy.
#
#   fleet-box-bootstrap.sh [--dry-run]
#
# Requires on the box before the first run: root ssh, git, docker, and network.
# Secrets stay box-local: the mullvad key/addr and API token are READ from
# /root/.config/ and the stack .env — never written by this script, never
# committed anywhere. The Mullvad device MUST be a fresh one (one tunnel per
# device — never copy box 1's key files).
#
# Env overrides: FLEET_REPO (default /root/communitytools), FLEET_STACK
# (default /root/pentest-stack), FLEET_IMAGE_FAST (default empty = fresh
# image build; "save-load" = expect kali-claude-eng.tar.gz in /root).
set -uo pipefail   # NOT -e: each step reports its own failure, then we exit
DRY_RUN=0
[ "${1:-}" = --dry-run ] && DRY_RUN=1
REPO=${FLEET_REPO:-/root/communitytools}
STACK=${FLEET_STACK:-/root/pentest-stack}
IMAGE_MODE=${FLEET_IMAGE_FAST:-build}

say()  { printf '[bootstrap] %s\n' "$*"; }
fail() { printf '[bootstrap] FAIL %s\n' "$*" >&2; FAILED=1; }
run()  { if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }
FAILED=0

[ "$(id -u)" = 0 ] || { echo "run as root (units install to /etc/systemd/system)" >&2; exit 1; }

needs() { command -v "$1" >/dev/null 2>&1; }

# ---- 1. repo ---------------------------------------------------------------
step_repo() {
  if [ -d "$REPO/.git" ]; then
    say "repo present at $REPO (branch: $(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null))"
    # Materialize the engagement-critical skill layers a fresh clone lacks:
    # layer-A symlink members dangle host-side and absent members (e.g.
    # attack-path-stitcher, the phase-3 stitch skill the runner mandates)
    # never materialize on their own — runner mandates name
    # /workspace/.claude/skills/<name>/ paths that must resolve in-container.
    if [ -x "$REPO/scripts/sync-pentest-mirror.sh" ] && [ -d "$REPO/skills/attack-path-stitcher" ]; then
      if run bash "$REPO/scripts/sync-pentest-mirror.sh"; then
        say "mirror layers synced (stitcher + intel skills materialized)"
      else
        fail "sync-pentest-mirror.sh failed — stitcher skill may be missing in-container"
      fi
    fi
  elif needs git; then
    say "cloning not possible here — clone manually, then re-run"
    fail "no repo at $REPO"
  else
    fail "no repo at $REPO and no git"
  fi
}

# ---- 2. images --------------------------------------------------------------
step_images() {
  local have_base have_eng
  have_base=$(docker image inspect kali-claude:latest --format ok 2>/dev/null || true)
  have_eng=$(docker image inspect kali-claude-eng:latest --format ok 2>/dev/null || true)
  if [ "$have_eng" = ok ] && [ "$have_base" = ok ]; then
    say "images present (kali-claude, kali-claude-eng)"
    return 0
  fi
  case "$IMAGE_MODE" in
    save-load)
      if [ -f /root/kali-claude-eng.tar.gz ]; then
        say "loading images from /root/kali-claude-eng.tar.gz (hub: docker save both | gzip)"
        run gzip -dc /root/kali-claude-eng.tar.gz | docker load
      else
        fail "IMAGE_MODE=save-load but /root/kali-claude-eng.tar.gz missing"
      fi ;;
    build)
      say "building base image (~1h public downloads) via kali-claude-setup.sh"
      run bash "$REPO/scripts/kali-claude-setup.sh"
      say "building eng image via build-eng.sh (selftest-gated)"
      run bash "$REPO/scripts/build-eng.sh" ;;
    *) fail "IMAGE_MODE must be build or save-load" ;;
  esac
}

# ---- 3. mullvad device ------------------------------------------------------
step_gluetun() {
  # One tunnel per device — a second box MUST carry its own key/addr files.
  # This script never creates or copies them; it verifies and hands off.
  if [ -f /root/.config/mullvad-gluetun.key ] && [ -f /root/.config/mullvad-gluetun.addr ]; then
    say "mullvad device files present (key+addr)"
  else
    fail "missing /root/.config/mullvad-gluetun.{key,addr} — generate a FRESH device"
    say "  (mullvad.net account → devices → new WireGuard key; one box per device)"
  fi
  if [ -x "$STACK/ensure-gluetun.sh" ]; then
    run bash "$STACK/ensure-gluetun.sh" gluetun "$(hostname -s | tr 'a-z' 'A-Z')" \
      || say "ensure-gluetun not converged yet (retry after stack .env is in place)"
  else
    say "ensure-gluetun.sh not at $STACK yet — run after stack setup"
  fi
}

# ---- 4. stack + units --------------------------------------------------------
step_stack() {
  if [ -d "$STACK" ]; then
    say "stack dir present at $STACK"
  elif [ -d "$REPO" ]; then
    say "stack dir missing — copying repo scripts/ twins is deploy-check's job;"
    say "  create $STACK, copy stack files from box 1 per docs/fleet-multi-box.md"
    fail "stack dir not initialized"
  fi
  for u in pentest-stack.service fleet-runner.service pentest-netns-watchdog.service; do
    if [ -f "$STACK/$u" ]; then
      [ "$DRY_RUN" = 1 ] && continue
      if ! cmp -s "$STACK/$u" "/etc/systemd/system/$u"; then
        say "installing $u"
        run cp "$STACK/$u" "/etc/systemd/system/$u"
        run systemctl daemon-reload
      else
        say "$u already installed"
      fi
    else
      say "$u not in stack (skipping unit install)"
    fi
  done
}

# ---- 5. gate ----------------------------------------------------------------
step_gate() {
  if [ -f "$STACK/fleet-deploy-check.sh" ]; then
    say "running fleet-deploy-check (ALL GREEN is the acceptance)"
    run bash "$STACK/fleet-deploy-check.sh"
  else
    fail "fleet-deploy-check.sh not at $STACK"
  fi
}

step_repo
step_images
step_gluetun
step_stack
step_gate

if [ "$FAILED" = 1 ]; then
  echo "[bootstrap] INCOMPLETE — fix the FAIL lines and re-run (idempotent)" >&2
  exit 1
fi
say "box converged — hub side: add this box to FLEET_BOXES and verify with fleet-hub.sh boxes"
[ "$DRY_RUN" = 1 ] && say "(dry-run: nothing was executed)"
