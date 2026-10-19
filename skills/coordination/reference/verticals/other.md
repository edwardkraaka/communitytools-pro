# Vertical overlay: other (universal)

Mounted when the target vertical is `other` — no financial-sector evidence found by `tools/vertical_classify.py --org-fingerprint`, no scope declaration, or an explicit `other` declaration. Unknown/unset verticals also land here by design: the universal overlay, so a missing classification can never shrink the coverage obligation.

**Contract.** This overlay SELECTS CONTENT, NEVER AUTHORITY — and on this vertical it selects nothing beyond the universal defaults. The universal discipline — scope, RoE flags, prohibitions, the impact-rung bar ([`severity-calibration.md`](../severity-calibration.md) rule 6), the exploitation mandate ([`principles.md`](../principles.md) "Exploitation depth") — governs identically under every vertical. Nothing here adds authority; nothing here removes a prohibition.

## Financial-harm rung (the universal quantification)

The universal rung applies as-is: **quantified financial harm — value-at-risk demonstrated by a NON-DESTRUCTIVE proof of authority appropriate to the asset** (the proof demonstrates control; it never executes, moves, or broadcasts anything). On non-financial targets, quantify the value-at-risk **concretely** — affected records, services, SLA exposure, downstream business impact — and never claim financial harm without a number.

- This sentence is mirrored byte-for-byte in the single-source JS constant `IMPACT_RUNGS.financial_overlay.other` (`.claude/workflows/lib/wf-helpers.mjs`; inline copies in the three workflow scripts are parity-governed).

## Skill mounts

None. The standard (type, vertical) mapping applies; every universal coverage class applies unchanged. If mid-engagement evidence shows the target actually carries financial-sector surfaces (custody, funds movement, on-chain treasuries), re-run the classifier (`tools/vertical_classify.py --org-fingerprint` with the new evidence) — a detected switch to `crypto`/`bank` mounts that overlay from the next batch onward; a scope declaration still wins.
