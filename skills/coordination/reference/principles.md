# Engagement Principles

Standing principles for any engagement. Referenced from every skill instead of being restated.

## Source code first

Read every accessible source — application code, configs, scripts, share contents, dumped binaries — before any executor batch. Every answer is in the data already collected. Guessing without reading is the most common failure mode.

## Scope is the attack surface, not the asset list

The handoff — hosts, keys, ids — is a starting point, not the boundary. When an apex domain is in scope, the discovered surface is in scope: every subdomain, every origin behind a CDN/WAF, every host that appears in CT logs. Freezing on the handed-in hosts is the most common breadth failure. One passive CT-log sweep routinely surfaces admin and management consoles the handoff never named.

## Reversible active exploitation

A create-then-delete in your OWN org/tenant is not destructive. If a finding can only be proven by a write, do the minimal write and clean up — never veto the proof on a self-imposed "reads only" rule. Litmus: if you will POST a token-mint on your own org, you are authorized to POST a resource-create on your own org to prove an SSRF or mass-assignment. Destructive means irreversible loss to OTHERS (DROP, mass-delete, DoS) — not a scoped object you create and then delete. Log both the create and the cleanup in `experiments.md`.

## Exploitation depth — prove it to the ceiling

A confirmed primitive is **under-reported** if it stops at the detection rung when deeper rungs were reachable with the access in hand. Ladder: **detect → confirm → data access → code execution**. Climb it by default (`roe.post_exploitation`, house default true; only an explicit, dated client restriction disables it):

- **Injection → database access.** Escalate past boolean/error/time signals: authentication proof (`current_user()`/`user()`, `version()`, `database()`), then bounded enumeration (table COUNTs, ≤3 sample rows or one redacted column). The proof is *access*, never exfiltration — no mass dumps of client/PII data.
- **RCE-class (RCE/deser/upload/SSTI) → shell.** Prove execution with evidence commands (`id; hostname; uname -a`), then escalate to a shell when feasible — engagement-owned listener/collaborator or a session via the primitive. No persistence, no backdoors, no credential implants: capture evidence, log the session in `experiments.md`, tear it down.
- **File-read/LFI/SSRF → one named secret.** Read one specifically-named config/secret to prove read access; record it, redact verbatim values in the report.
- **Access in hand → use it.** Valid creds or an exposed DB/admin interface: attempt the authenticated surface single-shot (never spraying).

Record the highest rung reached in the finding. The prohibitions (non-destructive, in-scope, no DoS/brute force) bound the ladder's rungs — not whether you climb.

## Real tools before hand-rolled HTTP

For web/API recon, run the real tool before any bespoke `requests`/`urllib` script: CT-log enum (`crt.sh` / `certspotter` / `subfinder`) for surface, `sslscan` for TLS, `nuclei` for templated exposure, Burp/Playwright for proxying and rendering. Hand-rolled HTTP is for targeted hypothesis tests AFTER the tool-driven surface map. Zero hits when grepping your own scripts for `subfinder|nuclei|sslscan|crt.sh` on a web engagement is a coverage failure.

## Three hypotheses, one wildcard

At every P2 Think, write three hypotheses to `attack-chain.md`. At least one tagged `[wildcard]` — an angle no mounted skill explicitly prescribes. Pick 3-5 independent surfaces to spawn (1-2 when the hypotheses feed each other). Record the rejected ones — they form the search-tree backlog and can be revisited at P4b.

## Parallel breadth, coordinator depth

3-5 executors per batch on independent surfaces (1-2 when hypotheses feed each other), spawned as ONE message of parallel Agent blocks. Coordinator stays lean — it runs no experiments inline; it thinks between batches, integrates every report, and is the sole writer of the ledgers. Executors don't speculate. Mutual dependency is the only reason to go narrow.

## Conceptual-goal stuck detection

Count failures toward the same conceptual *goal*, not the same technique string. Five different cert tools chasing "use this cert to authenticate" = five strikes against one goal. See `bookkeeping.md` Goal column. At three strikes on a goal: P4b reset, fresh theory, no retry on cosmetic variants.

## Re-verify the primitive, not just the payload

A long-standing "BLOCKED" verdict is most often built on *inferred* walls — conclusions like "the gadget can't fire", "inbound is filtered", "the linked server is unreachable" — that were never independently re-proven. Before accepting a multi-session block, re-test the underlying primitive in isolation with an unambiguous out-of-band oracle (a callback that expands `%COMPUTERNAME%`, a timing delta, a marker write). In practice these walls are usually artifacts of your own earlier tooling/encoding mistakes, not the target. When you *inherit* a blocked state from a prior session, re-derive it from scratch — never build new work on prior negative conclusions. A public writeup / reference solution is a legitimate way to reset false premises; then re-prove every step live. (Real case: HTB Context sat at "deser RCE blocked / Pwnbox-required / portal-bot" for 6 sessions — all three were false; the deser fired the moment it was re-tested with a clean callback oracle.)

## Pivot menu, not cookbook

When stuck, consult symptom-indexed pivot tables (`when X fails, try Y`) rather than archetype cookbooks. Cookbooks tell you what success looks like — useless when you don't see success. Pivot menus tell you the next move.

## Blind validators

Validators receive evidence only — never the coordinator's reasoning, never the attack-chain. Independent verification is the anti-hallucination firewall. Both finding-validator and engagement-validator are blind. See `role-matrix.md`.

## Append-only audit

`experiments.md`, `tools/{NNN}_*.md`, `logs/activity/tool-invocations.jsonl`, and `logs/activity/source-ips.jsonl` are append-only. Never rewrite. Never prune. The trail proves thoroughness and lets the engagement-validator judge.

**Rule — register every egress vantage.** Every source/egress IP the engagement uses — the local runner, any attack VM, proxy, or VPN — must be registered via `tools/register_source_ip.py` (or `tools/provision_vantage.sh`, which registers automatically), so `source-ips.jsonl` is a complete record of where traffic originated.

**Rule — registered is not verified.** Registration records *intent* and writes `verified:false`; it proves nothing, because nothing sent a packet from that vantage. Only `tools/verify_source_ip.py` writes `verified:true`, and only against an **egress echo taken FROM that vantage** whose stored output contains the IP being claimed. `tools/coverage_gate.py` counts a region toward a `min_vantages` reachability negative only from a vantage-role row (`attack-vm`/`vpn`) that is verified with readable probe evidence, and dedupes by observed IP first — so one egress re-registered under two region names is one vantage, and a provider API reporting "your VM has address X" is not evidence (it proves allocation, not egress). The `region` you record must be the real **exit** geography.

## CLI tools first, library APIs second

For Active Directory / Kerberos / SMB / LDAP work, prefer CLI tools (impacket secretsdump, ticketer, getST, getTGT, smbclient; bloodyAD; certipy) over writing custom Python against library internals. Only drop to Python when CLI can't do what you need — and read the library source first. The same rule holds for web/API work (see "Real tools before hand-rolled HTTP").

## Source for library internals

Before writing Python against any library API (impacket, ldap3, pyasn1), read the relevant source file. Never guess function signatures.

## Background command discipline

State the specific result a tunnel / relay / listener will produce *before* spawning it. No speculative listeners.

## Diagnose before retrying

When a tool fails, read the error message. Check permissions, prerequisites, config. Don't retry with cosmetic variations.

## CVE risk lookup

Whenever a CVE ID (`CVE-YYYY-NNNNN`) is mentioned or discovered, run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS, severity, and CWE. Include in any finding's evidence.

## No `AskUserQuestion` from coordinator

Coordinator is autonomous. Missing creds → run env-reader, terminate with `status=BLOCKED` if not set. Asking is the parent orchestrator's job. See `role-matrix.md`.

## No partial-as-success

A multi-flag engagement is incomplete until every flag submits. `status=FAILED_partial` is a temporary marker, never a final outcome. On Easy targets, restart from recon if no progress in 5 batches after foothold. For non-flag engagements, completeness means surface/attack-class coverage, not chain depth — apply "Re-verify the primitive" to single-session BLOCKED-on-creds stops too, proving the wall is a real credential gap and not a self-imposed method restriction.

## Output discipline

All artifacts go under `OUTPUT_DIR`. Directory tree in `output-discipline.md`. Never write to repo root or working directory.
