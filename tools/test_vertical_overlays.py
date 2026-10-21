#!/usr/bin/env python3
"""Vertical-overlay behavior test (P1 + Seam B).

The engagement's second-stage instructions are adaptive to the target's
vertical (crypto|bank|fintech|other) instead of hardcoded for crypto. This
test EXECUTES the real single-source helper module
(.claude/workflows/lib/wf-helpers.mjs — normalizeVertical, impactRungs,
financialHarmRung, refuterPrompt) via node and asserts on its actual emitted
behavior, never on source prose. Identity of the byte-copies embedded in the
three workflow scripts is governed separately by parity.test.mjs; structural
wiring (which seam threads which value) is governed by
.claude/workflows/lib/wiring.test.mjs. Prose in severity-calibration.md /
VALIDATION.md / validator-role.md / principles.md / SKILL.md / the per-vertical
overlay files remains governed by human review, not CI substring matching.

Stdlib only (shells out to node, which CI already installs). Run:
  python3 tools/test_vertical_overlays.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPERS = os.path.join(REPO, ".claude", "workflows", "lib", "wf-helpers.mjs")

NODE_SCRIPT = r"""
import {{
  normalizeVertical, impactRungs, financialHarmRung, refuterPrompt,
}} from {helpers!r};

const normCases = [
  ['crypto', 'crypto'], ['bank', 'bank'], ['fintech', 'fintech'], ['other', 'other'],
  [' CRYPTO ', 'crypto'], ['Bank', 'bank'], ['  fintech  ', 'fintech'],
  ['nonsense', 'other'], ['', 'other'],
  [undefined, 'other'], [null, 'other'],
];
const normResults = normCases.map(([input, expected]) => ({{
  input: input === undefined ? '<undefined>' : input,
  expected,
  actual: normalizeVertical(input),
}}));

const verticals = ['crypto', 'bank', 'fintech', 'other'];
const rungs = {{}};
for (const v of verticals) {{
  rungs[v] = {{ impact: impactRungs(v), financial: financialHarmRung(v) }};
}}

const f = {{ id: 'finding-1', dir: 'FINDING_DIR' }};
const promptByVertical = {{}};
for (const v of verticals) {{
  promptByVertical[v] = refuterPrompt(f, 1, {{ VERTICAL: v, NVD_KEV: ['op0', 'op1'] }});
}}

console.log(JSON.stringify({{ normResults, rungs, promptByVertical }}));
"""


def run_node(script_text):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".mjs", delete=False, dir=tempfile.gettempdir(),
    ) as fh:
        fh.write(script_text)
        path = fh.name
    try:
        p = subprocess.run(
            ["node", path], capture_output=True, text=True, timeout=60,
        )
        return p.returncode, p.stdout, p.stderr
    finally:
        os.unlink(path)


def main():
    failures = []
    checked = 0

    def check(cond, msg):
        nonlocal checked
        checked += 1
        if not cond:
            failures.append(msg)

    rc, out, err = run_node(NODE_SCRIPT.format(helpers=HELPERS))
    if rc != 0:
        print(f"vertical-overlays: node execution failed: {err or out}")
        return 1
    data = json.loads(out.strip().splitlines()[-1])

    # (e) normalizeVertical: exact vocabulary passthrough, case/space
    # normalization, and unknown/undefined/null fail SAFE to 'other' (the
    # obligation never shrinks on an unrecognized or missing label).
    for case in data["normResults"]:
        check(
            case["actual"] == case["expected"],
            f"normalizeVertical({case['input']!r}) = {case['actual']!r}, expected {case['expected']!r}",
        )

    rungs = data["rungs"]
    universal = "the proof demonstrates control; it never executes, moves, or broadcasts anything"

    # (a) every vertical's rung independently carries the universal
    # NON-DESTRUCTIVE proof requirement — no vertical is left without it.
    for v in ("crypto", "bank", "fintech", "other"):
        check(
            universal in rungs[v]["financial"] and universal in rungs[v]["impact"],
            f"{v}: financial-harm rung missing the universal NON-DESTRUCTIVE proof requirement",
        )

    # (b) crypto carries the fund-PoC discipline verbatim.
    crypto_fin = rungs["crypto"]["financial"]
    for needle in ("broadcast NOTHING", "transfer NOTHING", "funds-at-risk", "signed message"):
        check(needle in crypto_fin, f"crypto rung missing fund-PoC discipline text {needle!r}")

    # (c)+(g) bank/fintech NEVER carry crypto-only phrases, and carry the
    # reversible own-tenant proof (fintech composing with the bank overlay).
    for v in ("bank", "fintech"):
        fin = rungs[v]["financial"]
        for crypto_only in ("broadcast NOTHING", "seed-phrase", "fund PoC", "signed message"):
            check(crypto_only not in fin, f"{v} rung leaked crypto-only phrase {crypto_only!r}")
        check("reversible own-tenant path" in fin, f"{v} rung missing the reversible own-tenant proof")
        check(
            "NEVER a live transfer to any third party" in fin or "quantified account" in fin,
            f"{v} rung missing the no-third-party-transfer / quantified-exposure safety clause",
        )
    check(
        "verticals/bank.md" in rungs["fintech"]["financial"],
        "fintech rung does not cite/compose with the bank overlay",
    )

    # (d) 'other' demands a concrete quantified value-at-risk, never claims
    # financial harm without a number.
    other_fin = rungs["other"]["financial"]
    check("value-at-risk" in other_fin, "other rung missing quantified value-at-risk requirement")
    check(
        "never claim financial harm without a number" in other_fin,
        "other rung missing the never-claim-without-a-number guard",
    )

    # (f) parity, not privilege: the SAME validator-side prompt builder
    # (refuterPrompt) composes the matching rung for whichever vertical it is
    # given — executors and validators receive the same universal rung plus
    # the same per-vertical overlay.
    prompts = data["promptByVertical"]
    for v in ("crypto", "bank", "fintech", "other"):
        check(
            rungs[v]["impact"] in prompts[v],
            f"refuterPrompt(VERTICAL={v!r}) did not compose the matching impactRungs({v!r}) output",
        )
    for v1 in ("crypto", "bank", "fintech", "other"):
        for v2 in ("crypto", "bank", "fintech", "other"):
            if v1 >= v2:
                continue
            check(
                prompts[v1] != prompts[v2],
                f"refuterPrompt is identical for VERTICAL={v1!r} and VERTICAL={v2!r} (vertical not threaded)",
            )

    # (j) md↔JS mirror agreement (bank): the bank overlay's quantification
    # sentence is the byte-for-byte mirror the single-source JS constant
    # composes into executor AND validator prompts.
    bank_mirror = "demonstrated authority over funds movement on a reversible own-tenant path"
    check(
        bank_mirror in rungs["bank"]["financial"] and bank_mirror in rungs["fintech"]["financial"],
        "wf-helpers.mjs bank/fintech rung drifted from the bank overlay mirror sentence",
    )

    # (k) verticals DSL consistency: every vertical in the canonical vocabulary
    # dispatches to an existing overlay file (fintech dispatches to bank.md),
    # and the vocabulary is single-sourced across classifier + catalog + this
    # test — vertical_na enumeration is unaffected (no class gains a
    # verticals[] constraint in this change; the vocabulary itself is closed).
    vocab = {"crypto", "bank", "fintech", "other"}
    overlay_files = {
        "crypto": "crypto.md", "bank": "bank.md",
        "fintech": "bank.md", "other": "other.md",
    }
    for v, fname in overlay_files.items():
        path = os.path.join(REPO, "skills", "coordination", "reference", "verticals", fname)
        check(os.path.isfile(path), f"vertical {v!r} has no overlay file at {fname!r}")
    with open(os.path.join(REPO, "tools", "vertical_classify.py"), encoding="utf-8") as fh:
        classify_src = fh.read()
    m = re.search(r"^VERTICALS\s*=\s*\(([^)]*)\)", classify_src, re.MULTILINE)
    check(
        m is not None and {t.strip().strip('"\'') for t in m.group(1).split(",") if t.strip()} == vocab,
        "tools/vertical_classify.py VERTICALS no longer equals the canonical vocabulary",
    )
    catalog = json.load(open(os.path.join(REPO, "skills", "coordination", "reference", "coverage-matrix.json"), encoding="utf-8"))
    check(
        set(catalog.get("meta", {}).get("verticals", [])) == vocab,
        "coverage-matrix.json meta.verticals no longer equals the canonical vocabulary",
    )

    print(f"vertical-overlays: {checked} checked, {len(failures)} failed")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
