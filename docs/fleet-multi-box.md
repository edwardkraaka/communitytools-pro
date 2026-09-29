# Fleet Multi-Box — sharding engagements across identical boxes

The fleet runner is single-box by design. When more concurrent engagements are needed than one box can hold (13 × 6g caps on a 62 GiB box is the measured ceiling), the answer is **more identical boxes, statically sharded — not an orchestrator**. Every box runs the stock runner unchanged; a thin ssh control layer on top makes many boxes feel like one fleet.

- **No Kubernetes, no Swarm, no Nomad.** Orchestrators exist to replace failed containers *elsewhere*; this fleet pins each engagement session to its host (transcripts, tmux state, in-place resume). Swarm has no service-level `docker exec` at all — you would ssh to the node anyway — and `docker stack deploy` cannot read the modern Compose spec our stack uses. The orchestrator would be a control plane with no scheduling value.
- **Idempotent bring-up, per box.** `fleet-box-bootstrap.sh` converges a fresh VM to a working fleet box and ends at `fleet-deploy-check.sh` ALL GREEN.
- **Zero deployed code on workers.** The hub pulls state over plain ssh stdin snippets; a box joins the fleet by ssh alias alone.
- **Same operator verbs, one hop further.** Attach, relay, and monitor work exactly as on box 1 — `fleet-remote.sh` is the corridor.
- **Secrets stay box-local.** Mullvad device keys and API tokens live in each box's own config/state stores, mode 0600, never in this repo.

## Usage

```bash
# on the hub (any box listed first in FLEET_BOXES; default: this box)
FLEET_BOXES="local fleet2" fleet-hub.sh status --watch   # wall of screens
fleet-hub.sh split targets.txt 2                          # write targets.txt.1 / .2
FLEET_BOXES="local fleet2" fleet-hub.sh boxes             # per-box health card
FLEET_BOXES="local fleet2" fleet-remote.sh attach sometag # hop into any pane
FLEET_BOXES="local fleet2" fleet-remote.sh pane sometag   # read-only peek
FLEET_BOXES="local fleet2" fleet-remote.sh relay sometag "probe X, then continue"
```

`local` means this box (no ssh). Box aliases come from `~/.ssh/config`. Put the default list in the hub's environment (`.bashrc` or a wrapper) so every command does not need the prefix.

ControlMaster is pinned to `~/.ssh/fleet-cm-%C` with `ControlPersist 10m` for automation; interactive `attach` uses plain `ssh -tt` with **no** master, so a stuck automation master can never take the operator's panes down with it.

## Bring-up (per new box)

1. **Provision** an Azure VM in the same size class (8 vCPU / 62 GiB, ≥512 GiB disk), root ssh, docker + git installed.
2. **Repo**: clone this repo to `/root/communitytools`.
3. **Images**: default is a fresh build via `kali-claude-setup.sh` (~1h public downloads) then `build-eng.sh` (selftest-gated). Fast path: on the hub `docker save kali-claude:latest kali-claude-eng:latest | gzip > /tmp/images.tar.gz`, copy it over, `FLEET_IMAGE_FAST=save-load fleet-box-bootstrap.sh`. Either way, acceptance is the gate, not the path.
4. **Mullvad device — hard rule**: generate a **fresh** WireGuard key/addr pair in the Mullvad account for this box into `/root/.config/mullvad-gluetun.{key,addr}`. One tunnel per device; never copy box 1's files, or both boxes fight over one device and drop each other's egress.
5. **Run** `fleet-box-bootstrap.sh` (idempotent; re-run after fixing any FAIL line). It verifies repo/images/device, runs `ensure-gluetun.sh`, installs the systemd units from the stack dir, and finishes at `fleet-deploy-check.sh` — ALL GREEN is the acceptance.
6. **Hub side**: add the box's ssh alias to `FLEET_BOXES`, then `fleet-hub.sh boxes` shows it green and `fleet-hub.sh status` shows its targets.

The systemd units (`pentest-stack.service`, `fleet-runner.service`, `pentest-netns-watchdog.service`) are generated on the host, outside this repo, per the policy in the README — the bootstrap script installs them from the box's own stack dir.

## The control layer

**`fleet-remote.sh` — the operator surface.** `attach <tag>` resolves the owning box and opens `ssh -tt <box> docker exec -it eng-<tag> tmux attach -t eng` — the same pane `tmux attach -t pentest` shows on that box; detach stays Ctrl-b d. `pane <tag>` is a read-only capture. `relay <tag> "<text>"` types a message into the harness: it **refuses** while an agents overlay is up or the pane renders busy (mid-turn / API park; `--force` overrides), then does the runner's two-phase submit (`send-keys -l` + Enter). If a turn is invisibly running, the text simply stages in the input line and submits when the turn completes — the tool verifies and reports which happened. `status`, `logs`, `mon`, `run`, `cleanup` are thin pass-throughs of the stock box-side verbs. There is deliberately no kill/stop/systemctl verb — destructive operations stay a manual ssh away.

**`fleet-hub.sh` — the wall of screens.** One ssh round-trip per box per render pulls the active run's state JSONs plus a `fleet.log` tail; the hub prints a merged `BOX | TAG | STATUS | CTX% | CMP | PARK | LAST EVENT` table with the same canaries as `fleet-status.sh` (parked / wedge / ctx ≥ 90%), plus a `⚠ <box>: UNREACHABLE` row for a dead box — one box going down never kills the view. `split <targets> N` shards a targets file (`--round-robin` default or `--chunk`), deduping by host and preserving `|instructions` columns; launch each shard on its box with the stock runner. `which <tag>` prints the exact attach command; `reports` lists finished deliverables across boxes (`--pull DIR` rsyncs them on demand — never live-synced); `boxes` is the health card including an image-drift check.

**`fleet-dispatch.sh` — the box-side allowlist.** Install at `/usr/local/bin/fleet-dispatch` on each worker and pin the automation key to it:

```
restrict,from="<hub-ip>",command="/usr/local/bin/fleet-dispatch" ssh-ed25519 AAAA… fleet-hub-automation
```

Docker-group access is root-equivalent, so the allowlist is the real boundary: the automation key can run exactly `has <tag>`, `pane <tag>`, and `relay <tag> <base64>` — nothing else, ever. The interactive key (used by `attach`/`mon`) is a separate keypair with `restrict,pty`. `fleet-remote.sh` routes its automation through this allowlist when `FLEET_SSH_MODE=dispatch`, and through plain ssh snippets otherwise (single-operator, trusted-hub mode).

## Team interface (probing engagements)

The fleet is operated like a team: the hub view is the stand-up, `pane` is looking over a shoulder, `relay` is asking a direct question mid-run, `attach` is pulling up a chair. Reply behavior is governed by the coordination contracts: engagements never ask the operator questions (blockers become CIRs); a relayed probe is answered in-pane and folded into the ongoing work. Scripts stay read-mostly by design — the one write verb (`relay`) is guarded and verified, and everything destructive remains a deliberate manual ssh.

## What stays untouched

The stock runner, lib, and monitor on every box (registry `.env`s, run dirs, flock, active symlink — all per-box by design); transcript and pinned-session state stays box-local (no shared storage, no live migration); the hub itself is stateless — bring it up on any box, or rely on each box's own `fleet-status.sh` when the hub is down. Boxes run autonomously; the control layer is a convenience layered on top, never a dependency.
