# Vertical overlay: bank (and fintech)

Mounted when the target vertical is `bank` or `fintech` — an explicit scope declaration (which always wins) or the OSINT-detected label from `tools/vertical_classify.py --org-fingerprint` (refreshed at mobile triage with `--app-dir`). The `fintech` label dispatches HERE: funds-movement surfaces (payments, mandates, wallets-as-a-service, ledger rails) ride the bank definition, keeping the fintech label for reporting.

**Contract.** This overlay SELECTS CONTENT, NEVER AUTHORITY. The universal discipline — scope, RoE flags, prohibitions, the impact-rung bar ([`severity-calibration.md`](../severity-calibration.md) rule 6), the exploitation mandate ([`principles.md`](../principles.md) "Exploitation depth") — governs identically under every vertical. This overlay defines only HOW the financial-harm rung is quantified. Nothing here adds authority; nothing here removes a prohibition.

## Financial-harm rung (the bank/fintech quantification)

The universal rung — quantified financial harm, value-at-risk demonstrated by a NON-DESTRUCTIVE proof of authority — is quantified on bank/fintech targets as **demonstrated authority over funds movement on a reversible own-tenant path**:

- a **non-destructive create-then-delete proof on the client's own transfer/mandate flow** — the reversible-active-exploitation pattern ([`principles.md`](../principles.md) "Reversible active exploitation"): create a draft transfer/mandate under the compromised principal in the tester's OWN org/tenant, show it is reachable/actable, then delete it and log the create + cleanup. **NEVER a live transfer to any third party.** A transfer that moves real money out of the tenant is prohibited regardless of how it is labeled.
- or **quantified account exposure** — the number + aggregate balance of accounts the compromised position reaches (customer accounts, treasury accounts, internal ledgers), from enumerated access or the institution's own reporting surfaces.

Either form demonstrates control without moving funds. The proof stops at demonstrating authority; it never executes a payment.

- This sentence is mirrored byte-for-byte in the single-source JS constant `IMPACT_RUNGS.financial_overlay.bank` / `.fintech` (`.claude/workflows/lib/wf-helpers.mjs`; inline copies in the three workflow scripts are parity-governed).

## Skill mounts

No vertical-specific classes mount today — the standard (type, vertical) mapping already covers the funds-movement surface (API security, authentication, server-side, mobile MASVS). Vertical-conditional coverage classes (catalog `verticals` constraints) are the only gating mechanism; every universal class applies unchanged.
