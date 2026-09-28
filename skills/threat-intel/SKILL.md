---
name: threat-intel
description: Standing threat-intelligence base for engagements — live CVE/exploit intel sources, recent blockchain-hack incident anatomy with unconventional entry vectors, exploited-CVE detection signatures, zero-day hunter methodology, and the deterministic target-triage procedure that converts a fingerprinted stack into ranked hunt hypotheses. Consult at OSINT phase 5 and before the first active-phase batch; mandatory for crypto/web3 targets.
---

# Threat-Intel

Standing intelligence base (generic public research; zero engagement data). The active phase hunts intel-matched hypotheses FIRST — version-match exploits, incident-pattern replications — with OWASP breadth as the completion layer. [recent-incidents.md](reference/recent-incidents.md) carries the entry-vector patterns; [target-triage.md](reference/target-triage.md) converts a fingerprinted target into the ranked hypothesis list.

## When to consult

- **OSINT phase 5** (Code Intelligence) — after repos/stack are mapped, run the [target-triage.md](reference/target-triage.md) procedure over the fingerprint.
- **Before the first active-phase batch** — the kickoff/stage-2 mandate hands TI Hypotheses to the coordinator; consume them as the first exploit lanes (per spawning-recipes first-batch composition).
- **Every crypto/web3 target** — incident anatomy (wallet infra, custody, third-party integrations, off-chain services) is the leading edge.
- **Coordinator P4b reset** — creative-research Source 0.

## Digest contents

- [intel-sources.md](reference/intel-sources.md) — live CVE/exploit intel sources with exact clone/API URLs, cadences, and poll designs
- [recent-incidents.md](reference/recent-incidents.md) — blockchain-hack anatomy 2024–2026: entry vectors, precursors, what a tester could have caught
- [exploited-cve-classes.md](reference/exploited-cve-classes.md) — 2025–2026 exploited CVE classes with detection signatures and safe probes
- [zero-day-methodology.md](reference/zero-day-methodology.md) — hunter tradecraft: patch-diffing, JS/sourcemap reading, variant analysis
- [llm-research-sota.md](reference/llm-research-sota.md) — LLM-driven research state of the art and the practices an agent program copies
- [target-triage.md](reference/target-triage.md) — the deterministic per-target decision procedure

## The triage loop

Fingerprint the org's stack (vendors, frameworks, libraries, wallet/key infrastructure — techstack-identification outputs, JS bundles, sourcemaps, lockfile leaks, wallet-app/SDK versions) → match every component and version against [intel-sources.md](reference/intel-sources.md) entries and the incident anatomy in [recent-incidents.md](reference/recent-incidents.md) → each match becomes a numbered hunt hypothesis with an exploit sketch → record in `session-memory.md` (TI Hypotheses section). Full decision procedure: [target-triage.md](reference/target-triage.md).

## Refresh

Weekly, host-side, via the versioned [research-brief.md](reference/research-brief.md) — refreshes re-send exactly that prompt (generic by construction; no client data ever enters these files). History: [refresh-log.md](reference/refresh-log.md).

## Anti-Patterns

- Mounting whole digest files into executor prompts — pass the ONE most-relevant reference file path, ≤ 2 files per executor.
- Treating a digest match as a finding. A match is a hypothesis until it survives [VALIDATION.md](../coordination/reference/VALIDATION.md); version evidence must be pinned (`artifacts/nvd-cache/` via `tools/nvd-lookup.py --cache-dir`).
- Letting TI hypotheses starve coverage completion — they reorder the first batches and consume P2 budget; the coverage matrix still completes (spawning-recipes extension, [creative-research.md](../coordination/reference/creative-research.md) budget rules).
- Stale intel — the currency rule: if the refresh pipeline fails twice, treat affected vendor classes as unverified until re-verified.
- Case-sensitive prose with banned hard-negative phrasing outside this section.
