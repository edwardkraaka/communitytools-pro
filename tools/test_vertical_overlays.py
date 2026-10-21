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
VALIDATION.md / validator-role.md / principles.md / SKILL.md remains governed by
human review, but the P3 bank overlay's safety-critical contract lines, taxonomy,
and md↔JS mirror are CI-asserted here (content preservation per the audit's §5.2
requirements: overlays select content, never authority — and the safety
constraints survive any future split verbatim).

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
BANK_MD = os.path.join(REPO, "skills", "coordination", "reference", "verticals", "bank.md")
ATT_SRC_MD = os.path.join(REPO, "skills", "mobile-security", "reference", "android-dynamic-analysis.md")

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

    # (h) P3 bank overlay CONTENT: the safety-critical contract lines and the
    # bank taxonomy survive in skills/coordination/reference/verticals/bank.md
    # verbatim (audit §5.2: safety-critical constraints survive the split
    # verbatim; overlays select content, never authority). CI substring
    # assertions pin exactly the lines a future split must not silently lose.
    with open(BANK_MD, encoding="utf-8") as fh:
        bank_md = fh.read()

    # (h1) the overlay contract itself.
    check(
        "SELECTS CONTENT, NEVER AUTHORITY" in bank_md,
        "bank overlay lost the select-content-never-authority contract",
    )

    # (h2) the four safety constraints the audit requires verbatim-in-intent:
    # vendor third-party boundary (via CIR), observation-build lane honesty,
    # mock/sandbox honesty, client-Boolean vs server enforcement.
    for needle in (
        "never testing the KYC vendor's production service",
        "third-party boundary goes through the CIR channel",
        "never reported as the release artifact",
        "test modifications, not security findings",
        "not server-enforcement defeat",
        "verify verdict + nonce + requestHash server-side",
    ):
        check(
            needle in bank_md,
            f"bank overlay lost safety-critical constraint {needle!r}",
        )

    # (h3) KYC/liveness tooling analysis: vendor identification, evaluation-layer
    # separation, capture-path integrity, session/trust-boundary verification,
    # deployed-configuration recording, mock-vs-production, data minimization.
    for needle in (
        "Onfido", "Jumio", "Veriff", "Persona", "iProov", "FaceTec",
        "presentation attack", "injection", "deepfake", "identity binding",
        "NEVER conflated",
        "virtual camera", "emulator", "rooted device", "sensor-consistency",
        "applicant → session → evidence → decision",
        "stale, mismatched, interrupted, and duplicated sessions",
        "SDK version, product tier", "reason codes",
        "canned verdicts proves nothing",
        "synthetic or explicitly consented fixtures", "retention", "deletion evidence",
    ):
        check(
            needle in bank_md,
            f"bank overlay missing KYC/liveness instruction {needle!r}",
        )

    # (h4) anti-tamper/anti-Frida taxonomy + two-lane discipline.
    for needle in (
        "27042", "D-Bus", "gum-js-loop", "/proc/self/maps", "LIBFRIDA",
        "unix sockets", "interceptor trampolines", "dyld",
        "Production-equivalent build", "Modified observation build", "lane",
    ):
        check(
            needle in bank_md,
            f"bank overlay missing anti-tamper/two-lane instruction {needle!r}",
        )

    # (h5) instrumentation discipline: upstream pinned first, stale forks
    # named with versions, repo/tag/hash recording, stack acceptance test.
    for needle in (
        "Upstream Frida first, version-pinned",
        "strongR-frida-android ends at **16.7.14**",
        "Florida at **16.7.0**",
        "1.12.5", "repo/tag/hash",
        "Acceptance-test the stack before attributing failure to the app",
    ):
        check(
            needle in bank_md,
            f"bank overlay missing instrumentation-discipline instruction {needle!r}",
        )

    # (h6) Play Integrity verdict separation + testing channels.
    for needle in (
        "MEETS_BASIC_INTEGRITY", "MEETS_STRONG_INTEGRITY",
        "PLAY_RECOGNIZED", "LICENSED",
        "MEETS_VIRTUAL_INTEGRITY", "Play Games",
        "isTestingResponse",
    ):
        check(
            needle in bank_md,
            f"bank overlay missing Play Integrity verdict-separation instruction {needle!r}",
        )

    # (h7) bank impact quantification: the funds-movement proof stays, and the
    # two further bank-specific impact claims are present as distinct claims.
    for needle in (
        "reversible own-tenant path",
        "NEVER a live transfer to any third party",
        "Server-verified attestation bypass",
        "KYC-flow trust-boundary compromise",
    ):
        check(
            needle in bank_md,
            f"bank overlay missing impact-quantification claim {needle!r}",
        )

    # (i) promoted-rule source consistency: the server-side attestation
    # verification rule promoted into the bank overlay carries the SAME core
    # sentence as its mobile-security source (the rule is single-voiced, not
    # paraphrased into drift).
    with open(ATT_SRC_MD, encoding="utf-8") as fh:
        att_src = fh.read()
    att_rule = "is only real if the SERVER verifies the Play Integrity verdict + nonce"
    check(
        att_rule in bank_md,
        "bank overlay dropped the source-verbatim server-side attestation rule",
    )
    check(
        att_rule in att_src,
        "android-dynamic-analysis.md no longer carries the attestation rule the bank overlay cites",
    )

    # (j) md↔JS mirror agreement (bank): the bank overlay's quantification
    # sentence is the byte-for-byte mirror the single-source JS constant
    # composes into executor AND validator prompts.
    bank_mirror = "demonstrated authority over funds movement on a reversible own-tenant path"
    check(
        bank_mirror in bank_md,
        "bank overlay no longer mirrors the JS financial-harm rung sentence",
    )
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

    # (l) executor/validator dispatch parity (static seams, no refactoring):
    # the executor prompt mounts the overlay by the SAME vertical label the
    # validator's refuter rung composes from — bank overlay content reaches
    # validators exactly as it reaches executors.
    with open(os.path.join(REPO, ".claude", "workflows", "coordinator-loop.js"), encoding="utf-8") as fh:
        loop_src = fh.read()
    with open(os.path.join(REPO, ".claude", "workflows", "validate-findings.js"), encoding="utf-8") as fh:
        val_src = fh.read()
    check(
        "skills/coordination/reference/verticals/${VERTICAL}.md" in loop_src,
        "coordinator-loop.js no longer mounts the per-vertical overlay in the executor prompt",
    )
    check(
        "impactRungs(P.VERTICAL)" in val_src,
        "validate-findings.js no longer composes the per-vertical rung in the validator prompt",
    )

    print(f"vertical-overlays: {checked} checked, {len(failures)} failed")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
