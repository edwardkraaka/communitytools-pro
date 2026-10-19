#!/usr/bin/env python3
"""Vertical-overlay single-source agreement test (P1 + Seam B).

The engagement's second-stage instructions are adaptive to the target's
vertical (crypto|bank|fintech|other) instead of hardcoded for crypto:

  P1     - tools/vertical_classify.py + the scope-file `vertical` field
  Seam B - the impact rung / financial-harm quantification is single-sourced:
           one JS constant (IMPACT_RUNGS in wf-helpers.mjs, byte-identical
           inline copies in the three workflow scripts - identity itself is
           governed by parity.test.mjs) + one MD source
           (severity-calibration.md rule 6) + per-vertical overlay files
           (skills/coordination/reference/verticals/{crypto,bank,other}.md).

This test pins the CONTRACT, in the test_docs_lint.py PRESENT/ABSENT style:

  * every vertical's rung text independently carries the NON-DESTRUCTIVE
    proof requirement (safety never depends on the label);
  * crypto keeps the fund-PoC text verbatim, including "broadcast NOTHING";
  * bank/fintech = funds-movement quantification only; other = universal;
  * overlays SELECT CONTENT, NEVER AUTHORITY (advisory, overridable);
  * the vertical threads from scope -> setup -> expand -> spawn -> prompts;
  * the retired crypto-hardcoded conditionals are gone from the MD sources.

Stdlib only. Run: python3 tools/test_vertical_overlays.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- JS single-source (Seam B) ------------------------------------------------
JS_RUNG_FILES = [
    ".claude/workflows/lib/wf-helpers.mjs",
    ".claude/workflows/pentest-engagement.js",
    ".claude/workflows/coordinator-loop.js",
    ".claude/workflows/validate-findings.js",
]
# Canonical export lives in wf-helpers.mjs; the workflow scripts embed
# byte-identical copies without `export ` (identity: parity.test.mjs).
RUNG_DECLS = {
    ".claude/workflows/lib/wf-helpers.mjs": [
        "export function normalizeVertical(",
        "export const IMPACT_RUNGS = {",
        "export function financialHarmRung(",
        "export function impactRungs(",
    ],
}
for _wf in JS_RUNG_FILES[1:]:
    RUNG_DECLS[_wf] = [
        "function normalizeVertical(",
        "const IMPACT_RUNGS = {",
        "function financialHarmRung(",
        "function impactRungs(",
    ]

# Key invariant substrings that must exist in EVERY copy of the constant:
# the per-vertical quantification sentences + the safety clauses each carries.
RUNG_INVARIANTS = [
    "broadcast NOTHING, transfer NOTHING",          # crypto fund PoC, verbatim
    "NON-DESTRUCTIVE proof of authority",          # universal requirement
    "reversible own-tenant path",                  # bank/fintech
    "NEVER a live transfer to any third party",     # bank/fintech safety
    "never claim financial harm without a number",  # other
]

# --- Vertical threading (P1 -> workflows) -------------------------------------
THREADING = [
    # scope schema doc documents the field + the classifier + declared-wins.
    ("skills/pentest-engagement/reference/scope-file-format.md", '"vertical"'),
    ("skills/pentest-engagement/reference/scope-file-format.md", "--org-fingerprint"),
    ("skills/pentest-engagement/reference/scope-file-format.md", "vertical_source: declared"),
    # setup: schema field + normalization + per-asset parse instruction.
    (".claude/workflows/pentest-engagement.js",
     "enum: ['crypto', 'bank', 'fintech', 'other', null]"),
    (".claude/workflows/pentest-engagement.js",
     "const VERTICAL = normalizeVertical(setup.vertical)"),
    (".claude/workflows/pentest-engagement.js",
     "vertical (the per-asset override, else null)"),
    # Seam A: (type, vertical) -> hint mapping at expansion.
    (".claude/workflows/pentest-engagement.js",
     "APPENDS ,blockchain-security,threat-intel"),
    (".claude/workflows/pentest-engagement.js",
     "APPENDS ,authentication,server-side"),
    # Seam C: agent-side applicability rule mirrors the fails-safe gate.
    (".claude/workflows/pentest-engagement.js",
     "verticals[] constraint that EXCLUDES"),
    (".claude/workflows/pentest-engagement.js",
     "unknown/unset vertical NEVER excludes a class"),
    # spawn threading: web assets take the per-asset vertical.
    (".claude/workflows/pentest-engagement.js", "vertical: a.vertical || VERTICAL,"),
    # mobile triage refresh (detection point B) reuses the control-wiring inventory.
    (".claude/workflows/pentest-engagement.js", "VERTICAL REFRESH (detection point B"),
    (".claude/workflows/pentest-engagement.js", "tools/vertical_classify.py --app-dir"),
    (".claude/workflows/pentest-engagement.js", "--control-wiring ${appDir}/recon/control_wiring.json"),
    (".claude/workflows/pentest-engagement.js", "the triage-refreshed vertical label from tools/vertical_classify.py"),
    # OSINT phase 5 (target-triage step 1) runs detection point A.
    ("skills/threat-intel/reference/target-triage.md", "vertical_classify.py --org-fingerprint"),
    ("skills/threat-intel/reference/target-triage.md", "a scope-file `vertical` declaration wins"),
    # the three static-dispatch spawns carry the engagement vertical.
    (".claude/workflows/coordinator-loop.js", "const VERTICAL = normalizeVertical(a.vertical)"),
    (".claude/workflows/coordinator-loop.js", "REPAIR, VERTICAL,"),
    (".claude/workflows/coordinator-loop.js", "VERTICAL: ${VERTICAL}"),
    (".claude/workflows/coordinator-loop.js", "financialHarmRung(VERTICAL)"),
    (".claude/workflows/coordinator-loop.js", "impactRungs(VERTICAL)"),
    (".claude/workflows/coordinator-loop.js", "impactRungs(P.VERTICAL)"),
    (".claude/workflows/validate-findings.js", "const VERTICAL = normalizeVertical(a.vertical)"),
    (".claude/workflows/validate-findings.js", "impactRungs(P.VERTICAL)"),
    # parity governs the rung constants in all three workflow scripts.
    (".claude/workflows/lib/parity.test.mjs",
     "'normalizeVertical', 'IMPACT_RUNGS', 'financialHarmRung', 'impactRungs'"),
    # P carries the vertical next to BUSINESS_TIER (validator parity).
    (".claude/workflows/coordinator-loop.js",
     "const P = { OUTPUT_DIR, TARGET, BUSINESS_TIER, REPAIR, VERTICAL,"),
    (".claude/workflows/validate-findings.js",
     "const P = { OUTPUT_DIR, TARGET, BUSINESS_TIER, VERTICAL, REPAIR,"),
]

# --- MD single-source (rule 6 + overlays) --------------------------------------
MD = [
    # rule 6 is the single MD source: universal rungs + per-vertical definitions.
    ("skills/coordination/reference/severity-calibration.md",
     "NON-DESTRUCTIVE proof of authority appropriate to the asset"),
    ("skills/coordination/reference/severity-calibration.md",
     "broadcast NOTHING, transfer NOTHING"),
    ("skills/coordination/reference/severity-calibration.md", "verticals/crypto.md"),
    ("skills/coordination/reference/severity-calibration.md", "verticals/bank.md"),
    ("skills/coordination/reference/severity-calibration.md", "verticals/other.md"),
    ("skills/coordination/reference/severity-calibration.md",
     "overlays select content, never authority"),
    # crypto overlay: fund PoC verbatim + mandatory mounts.
    ("skills/coordination/reference/verticals/crypto.md", "SELECTS CONTENT, NEVER AUTHORITY"),
    ("skills/coordination/reference/verticals/crypto.md", "fund PoC"),
    ("skills/coordination/reference/verticals/crypto.md", "broadcast NOTHING"),
    ("skills/coordination/reference/verticals/crypto.md", "transfer NOTHING"),
    ("skills/coordination/reference/verticals/crypto.md", "blockchain-security"),
    ("skills/coordination/reference/verticals/crypto.md", "threat-intel"),
    ("skills/coordination/reference/verticals/crypto.md", "financial_overlay.crypto"),
    # bank overlay: quantification only, fintech dispatches here.
    ("skills/coordination/reference/verticals/bank.md", "SELECTS CONTENT, NEVER AUTHORITY"),
    ("skills/coordination/reference/verticals/bank.md", "reversible own-tenant path"),
    ("skills/coordination/reference/verticals/bank.md", "NEVER a live transfer to any third party"),
    ("skills/coordination/reference/verticals/bank.md", "quantified account exposure"),
    ("skills/coordination/reference/verticals/bank.md", "fintech"),
    ("skills/coordination/reference/verticals/bank.md", "financial_overlay.bank"),
    # other overlay: universal non-destructive requirement.
    ("skills/coordination/reference/verticals/other.md", "SELECTS CONTENT, NEVER AUTHORITY"),
    ("skills/coordination/reference/verticals/other.md",
     "NON-DESTRUCTIVE proof of authority"),
    ("skills/coordination/reference/verticals/other.md",
     "never claim financial harm without a number"),
    ("skills/coordination/reference/verticals/other.md", "financial_overlay.other"),
    # migrated conditionals: the MD rung copies point at the overlays.
    ("skills/coordination/reference/VALIDATION.md", "quantified per the target vertical's overlay"),
    ("skills/coordination/reference/validator-role.md", "quantified per the target vertical's overlay"),
    ("skills/coordination/reference/principles.md", "quantified per the target vertical's overlay"),
    ("skills/pentest-engagement/SKILL.md", "quantified per the target vertical's overlay"),
    ("skills/pentest-engagement/SKILL.md", "Vertical overlays dispatch per target vertical"),
    ("skills/threat-intel/SKILL.md", "verticals/crypto.md"),
]

# --- Retired crypto-hardcoded framing (must be gone) ---------------------------
RETIRED = {
    "skills/pentest-engagement/SKILL.md": [
        "Crypto-native coverage is mandatory for crypto-company targets",
        "on crypto targets the rung is a **fund PoC**",
    ],
    "skills/threat-intel/SKILL.md": [
        "mandatory for crypto/web3 targets.",
    ],
    "skills/coordination/reference/severity-calibration.md": [
        "on crypto targets the rung is a **fund PoC**",
    ],
    "skills/coordination/reference/VALIDATION.md": [
        "on crypto targets the rung is a **fund PoC**",
    ],
    "skills/coordination/reference/validator-role.md": [
        "on crypto targets the rung is a **fund PoC**",
    ],
    "skills/coordination/reference/principles.md": [
        "on crypto targets the rung is a **fund PoC**",
    ],
}


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def main():
    failures = []
    checked = 0

    # JS constant declarations + invariant substrings.
    for rel, decls in RUNG_DECLS.items():
        try:
            text = _read(rel)
        except FileNotFoundError:
            failures.append(f"rung file missing: {rel}")
            continue
        for decl in decls:
            checked += 1
            if decl not in text:
                failures.append(f"{rel}: missing rung declaration {decl!r}")
        for inv in RUNG_INVARIANTS:
            checked += 1
            if inv not in text:
                failures.append(f"{rel}: rung constant lost invariant {inv!r}")

    for rel, needle in THREADING + MD:
        checked += 1
        try:
            text = _read(rel)
        except FileNotFoundError:
            failures.append(f"PRESENT-check target missing: {rel}")
            continue
        if needle not in text:
            failures.append(f"{rel}: expected string {needle!r} not found")

    for rel, needles in RETIRED.items():
        try:
            text = _read(rel)
        except FileNotFoundError:
            failures.append(f"RETIRED-check target missing: {rel}")
            continue
        for needle in needles:
            checked += 1
            if needle in text:
                failures.append(f"{rel}: retired crypto-hardcoded string {needle!r} still present")

    print(f"vertical-overlays: {checked} checked, {len(failures)} failed")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
