# Fleet Runner — batch multi-engagement automation

The fleet runner automates the per-target manual loop: instead of typing the OSINT
kickoff into a pane, waiting, then typing the pentest-engagement kickoff, you drop a
targets file and the runner drives every target through the 2-stage chain across N
parallel **interactive** containers — each an attachable `claude` TUI you can jump
into mid-run.

Design constraints that shaped it:

- **Interactive, not headless.** Every engagement is the same crash-resilient
  stack as a manual one: Kali container, pinned session id (`--session-id` /
  `--resume`), transcript-growth stall watchdog, `kali-eng.sh` registry entry.
  The runner only *drives* the panes; it never replaces them.
- **Ownership boundary.** The runner touches only containers it registered
  (state file + `FLEET_RUN` marker in the registry `.env`). Manual engagements
  are never adopted, retired, or injected — a tag collision with the registry is
  a hard parse error by default.
- **It owns nothing destructive.** Everything reversible: parked containers,
  archived registry entries, plain-deletable state dirs. Retirement stops+removes
  the container (outputs and mirrored `~/.claude` transcripts persist).

## Usage

```
# targets file: one per line — bare host/URL, optional "| instructions"
#   acme-casino.example
#   example.com | payment endpoints; creds in TL_* env vars
fleet-runner.sh targets.txt                     # run (defaults: 8 slots)
fleet-runner.sh targets.txt --slots 6           # conservative memory profile
fleet-runner.sh -n targets.txt                  # dry-run: print the plan, execute nothing
fleet-runner.sh status [--watch]                # status table
fleet-runner.sh resume                          # re-adopt the active run after any restart
fleet-runner.sh resume --run 20260920_1530_targets   # adopt a specific run dir
```

Cluster state lives at `fleet/<YYYYMMDD_HHMMSS>_<targets-base>/` — `state/<tag>.json`
per target (queued → launched-osint → active → done/failed/retired), `targets.txt` +
`opts.env` snapshots (what `resume` re-adopts), `registry/` (archived `.env`s of
retired targets), `fleet.log`, and a `fleet/active` symlink (what `resume` adopts).

## The 2-stage chain per target

1. **Stage-1 (OSINT).** Launch via `kali-eng.sh` with a batch-pipeline-style
   kickoff: passive OSINT, every discovered credential validated single-shot
   (read-only identity call), handed off in `session-memory.md`, finish by
   writing `reports/osint_report.md`.
2. **Stage-2 (active).** Once the OSINT artifact exists AND the pane is idle
   (verified three ways: no `esc to interrupt`, no API-error park, transcript
   bytes static across a dual sample), the runner injects the active-pentest
   kickoff via `tmux send-keys` — the same two-phase submit the entrypoint's
   first-input path uses. The message carries the exploitation mandate and
   per-target instructions.

Completion = `*_<tag>_active/reports/*technical*report*.md`. Stage ceilings 6 h / 12 h
with idle+artifact gating; a timed-out rung parks without consuming an attempt,
a repeat failure fails the target after 3 attempts.

## Impact-rigor doctrine (what stage-2 injects)

The stage-2 message and the skills it invokes enforce the demonstrated-impact bar
and exploitation mandate (canonical homes: `skills/coordination/reference/principles.md`
"Exploitation depth" + "RoE authorization boundary", `severity-calibration.md` rule 6
+ `VALIDATION.md` Check 8):

- **Four impact rungs** — shell or box/machine access by any path (reverse shell,
  webshell, RCE session, or single-shot SSH login with a discovered key),
  admin/service-account access, a database exfiltration proof (auth proof +
  bounded enumeration ≤3 rows), or quantified financial harm / **fund PoC** on
  crypto targets (signing authority demonstrated by a signed message from the
  compromised key — broadcast nothing — plus funds-at-risk from Arkham
  `ARKHAM_API_KEY`).
- **High/Critical requires a demonstrated rung.** Reachable-but-untried (a
  discovered key/wallet left untried included) caps at Medium +
  `needs_live_confirmation`. Transient/reversible blockers score at root cause
  instead (Check 6 carve-out).
- **RoE default-authorization posture.** The rungs are the authorized default;
  "did not execute because of RoE" is banned for anything inside the mandate;
  genuine out-of-scope conflicts file a CIR and testing continues.
- **Crypto-native coverage** is a mandatory asset class for crypto-company
  targets (`blockchain-security` alongside web/API), with funds-at-risk
  quantified from on-chain data.

## Preflight and parking

Each launch is fenced by the batch-pipeline preflights (API token present,
gluetun sidecar alive + healthy, egress resolves through the VPN and not the box
IP, ≥5 GB disk) plus a memory gate (refuse when `eng-*` cap-sum + 6G would
exceed 90% of RAM+swap). Any failure parks the queue for 5 minutes without
consuming an attempt. `--slots 6` is the documented conservative profile when
running alongside manual engagements.

## Retirement

Finished containers park until a slot is needed; the oldest `done` target is
then stopped (30 s grace), the container removed, and its registry entry
archived into `fleet/<runid>/registry/` (re-attach: copy the `.env` back,
`up.sh` — the pinned session resumes where it left off). Workspace outputs and
`kali-state/<tag>/` are never touched.

## Boot persistence

`fleet-runner.service` (`After=`, `Restart=on-failure`) runs `fleet-runner.sh
resume` — it no-ops cleanly when there is no active run. **Not enabled by
default**; enable per-run: `systemctl enable --now fleet-runner.service`, and
disable when the run completes.
