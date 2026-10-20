# Vertical overlay: crypto

Mounted when the target vertical is `crypto` — an explicit scope declaration (which always wins) or the OSINT-detected label from `tools/vertical_classify.py --org-fingerprint` (refreshed at mobile triage with `--app-dir`).

**Contract.** This overlay SELECTS CONTENT, NEVER AUTHORITY. The universal discipline — scope, RoE flags, prohibitions, the anti-stall/CIR machinery, the impact-rung bar ([`severity-calibration.md`](../severity-calibration.md) rule 6), the exploitation mandate ([`principles.md`](../principles.md) "Exploitation depth") — governs identically under every vertical. What this overlay changes: (a) HOW the financial-harm rung is quantified, and (b) which additional skill classes are mandatory. Nothing here adds authority; nothing here removes a prohibition.

## Financial-harm rung (the crypto quantification)

The universal rung — quantified financial harm, value-at-risk demonstrated by a NON-DESTRUCTIVE proof of authority — is quantified on crypto targets as a **fund PoC**: signing authority over at-risk funds demonstrated with a signed message from the compromised key (broadcast NOTHING, transfer NOTHING — the valid signature is the proof of control), plus the quantified funds-at-risk figure.

- **Funds-at-risk figure** = on-chain balances at the vulnerable addresses via labeled-entity data — Arkham, `ARKHAM_API_KEY` via [`env-reader.py`](../credential-loading.md) — plus treasury/TVL. Feed it to the risk-prioritiser.
- The PoC stops at demonstrating control. It never executes, moves, or broadcasts anything. `broadcast NOTHING` and `transfer NOTHING` are absolute; a signed message from the compromised key is the complete, sufficient proof.
- This sentence is mirrored byte-for-byte in the single-source JS constant `IMPACT_RUNGS.financial_overlay.crypto` (`.claude/workflows/lib/wf-helpers.mjs`; inline copies in the three workflow scripts are parity-governed).

## Mandatory skill mounts (crypto)

The blockchain surface is a **mandatory asset class** on crypto targets — it runs alongside the web/API/mobile classes, never as an optional extra:

- `skills/blockchain-security/` — contracts, wallets, treasury operations, web3 frontend↔chain interaction.
- `skills/threat-intel/` — blockchain-hack incident anatomy (wallet infra, custody, third-party integrations, off-chain services) is the leading edge for hypothesis generation; consult at OSINT phase 5 and before the first active-phase batch.

These mounts ride the normal per-asset dispatch: the expand phase appends `blockchain-security,threat-intel` to the asset's `skills_hint`, and coordinator-loop mounts them alongside the type-based set.
