#!/usr/bin/env python3
"""Deterministic, evidence-cited vertical classifier — the P1 classification layer.

Labels the target's vertical (crypto | bank | fintech | other) plus capability
labels (kyc_sdk, root_detection, frida_detection, attestation, custody, wallet_sdk)
from OSINT org-fingerprint evidence and/or the decompiled app bundle. Executed at
the OSINT phase-5 org-fingerprint step (detection point A) and refreshed at mobile
triage from SDK signatures in the app bundle (detection point B).

ADVISORY, NEVER AUTHORITY (see skills/coordination/reference/verticals/): the label
selects content (which overlay/quantification/skills mount), never scope, RoE flags,
prohibitions, or the CIR channel. Every label carries citations; an explicit human
declaration in the scope file (`vertical` field) overrides detection, and a
misclassification changes investigative priority only — never RoE interpretation.

Inputs (either or both; app evidence refines the OSINT label):
  --org-fingerprint PATH   JSON evidence from the OSINT org-fingerprint step
                           (target-triage.md step 1). Any shape: every string
                           value in the tree is scanned; citations are JSON paths.
  --app-dir PATH           apktool/jadx-style decompiled app tree. Signature sweep
                           over relative paths, native-lib names (inventory REUSED
                           from apk_control_wiring.py — no parallel enumeration),
                           manifest text and assets filenames.
  --control-wiring PATH    recon/control_wiring.json from tools/apk_control_wiring.py
                           (optional; its native-lib + root-integrity inventory is
                           consumed rather than re-derived).
  --declared VERTICAL      explicit human declaration from the scope file — WINS
                           over detection; detection is still recorded as advisory.

Output: writes <out-dir>/vertical.json (default: alongside the evidence), prints the
same JSON on the last stdout line (house convention). Exit 0 classified / 2 usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Reuse the existing native-lib inventory helper (detection point B explicitly does
# NOT build a parallel enumeration — apk_control_wiring.py already owns it).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from apk_control_wiring import bundled_libs  # noqa: E402

VERSION = "1.0"
VERTICALS = ("crypto", "bank", "fintech", "other")

# --- capability signature tables (deterministic path/identifier substrings) ----
# Vendor tokens are chosen to be vendor-specific (no common-word false positives);
# matching is case-insensitive against decompiled paths, lib names and manifest.
KYC_SDKS = {
    "onfido": ("onfido",),
    "jumio": ("jumio",),
    "veriff": ("veriff",),
    "persona": ("withpersona", "com.persona"),
    "iproov": ("iproov",),
    "facetec": ("facetec", "zoomauth"),
    "sumsub": ("sumsub", "sumsubstance"),
    "idnow": ("idnow",),
    "socure": ("socure",),
    "smileid": ("smileid", "smile-identity"),
    "au10tix": ("au10tix",),
    "yoti": ("yoti",),
}
ROOT_DETECTION = {
    "rootbeer": ("rootbeer", "scottyab"),
    "dexguard": ("dexguard",),
    "promon": ("promon", "shieldfr"),
    "appdome": ("appdome",),
    "guardsquare": ("guardsquare",),
    "verimatrix": ("verimatrix",),
    "intertrust": ("intertrust", "whitecryption"),
}
FRIDA_MARKERS = ("libfrida", "re.frida.server", "frida-server", "fridaagent", "frida-gadget-detect")
ATTESTATION = {
    "play_integrity": ("play.core.integrity", "play/core/integrity", "integritymanager", "playintegrity"),
    "safetynet": ("safetynet", "attestation.google"),
    "app_attest": ("dcappattest", "appattest"),
}
CUSTODY = {
    "fireblocks": ("fireblocks",),
    "bitgo": ("bitgo",),
    "anchorage": ("anchoragedigital", "anchorage custody"),
    "fordefi": ("fordefi",),
    "qredo": ("qredo",),
    "gnosis_safe": ("gnosissafe", "safe.global", "com.safe.", "com/safe/"),
}
WALLET_SDK = {
    "web3j": ("web3j",),
    "walletconnect": ("walletconnect",),
    "metamask": ("metamask",),
    "trust_wallet_core": ("wallet-core", "trustwallet"),
    "bitcoinj": ("bitcoinj",),
    "bip39": ("bip39", "mnemonic"),
    "keccak": ("keccak",),
    "secp256k1": ("secp256k1",),
    "ledger": ("ledgerlive", "hwledger"),
}

# --- org-fingerprint keyword tables (scanned over every string value) -----------
# Distinct-keyword scoring: each table contributes once per DISTINCT keyword
# matched (an agent writing "wallet" ten times is one signal, not ten).
CRYPTO_KEYWORDS = (
    "crypto", "web3", "defi", "blockchain", "wallet", "custody", "on-chain",
    "smart contract", "stablecoin", "dapp", "seed phrase", "token treasury",
    "etherscan", "rpc endpoint", "dex", "hodl",
)
BANK_KEYWORDS = (
    "bank", "banking", "charter", "fdic", "deposit insurance", "basel",
    "banking license", "savings", "loan portfolio", "branch network", "iban",
    "know your customer", "kyc", "anti-money-laundering", "aml",
)
FINTECH_KEYWORDS = (
    "fintech", "neobank", "payment processor", "payments", "money transfer",
    "remittance", "stripe", "adyen", "plaid", "checkout.com", "open banking",
    "psp", "card issuing",
)
# Regulatory registrations are decisive bank/fintech evidence (weight 2 each).
BANK_REGISTRATION = ("bank charter", "banking license", "fdic", "occ", "basel", "national bank")
FINTECH_REGISTRATION = ("msb license", "money transmitter", "pci dss", "psd2", "emi license")


def _walk_strings(node, path="$", out=None):
    """Yield (json_path, string_value) for every string leaf in a JSON tree."""
    if out is None:
        out = []
    if isinstance(node, dict):
        for k, v in node.items():
            _walk_strings(v, f"{path}.{k}", out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_strings(v, f"{path}[{i}]", out)
    elif isinstance(node, str):
        out.append((path, node))
    return out


def _keyword_hits(text_l: str, table) -> list:
    return sorted({kw for kw in table if kw in text_l})


def scan_org_fingerprint(path: str) -> dict:
    """Detection point A: keyword/citation scan over the org-fingerprint JSON."""
    evidence = {"source": path, "strings": [], "vertical_keywords": {}, "registrations": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read org-fingerprint {path}: {e}")
    strings = _walk_strings(data)
    evidence["strings"] = strings
    for vert, table in (("crypto", CRYPTO_KEYWORDS), ("bank", BANK_KEYWORDS), ("fintech", FINTECH_KEYWORDS)):
        hits = {}
        for kw in table:
            for jpath, val in strings:
                if kw in val.lower():
                    hits.setdefault(kw, []).append(f"{jpath} = {val[:120]}")
                    break  # one citation per distinct keyword (deterministic: first in walk order)
        evidence["vertical_keywords"][vert] = hits
    for name, table in (("bank", BANK_REGISTRATION), ("fintech", FINTECH_REGISTRATION)):
        hits = {}
        for kw in table:
            for jpath, val in strings:
                if kw in val.lower():
                    hits.setdefault(kw, []).append(f"{jpath} = {val[:120]}")
                    break
        evidence["registrations"][name] = hits
    # Structured overrides the agent may supply (cited verbatim).
    if isinstance(data, dict):
        oc = data.get("onchain_footprint")
        if isinstance(oc, dict) and oc.get("present") is True:
            evidence["onchain_present"] = True
            evidence["onchain_citation"] = "$.onchain_footprint (declared present)"
        cust = data.get("custody_stack")
        if isinstance(cust, list) and cust:
            evidence["custody_declared"] = sorted({str(c) for c in cust})[:5]
            evidence["custody_citation"] = f"$.custody_stack = {json.dumps(evidence['custody_declared'])}"
    return evidence


def scan_app_dir(app_dir: str, control_wiring: dict | None) -> dict:
    """Detection point B: SDK-signature sweep over the decompiled bundle."""
    evidence = {"source": app_dir, "capabilities": [], "vertical_signals": {}}
    if not os.path.isdir(app_dir):
        raise ValueError(f"--app-dir not found: {app_dir}")
    corpus = []  # (kind, token) deterministic in walk order
    for root, dirs, files in os.walk(app_dir):
        dirs.sort()
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(root, name), app_dir)
            corpus.append(("path", rel.replace(os.sep, "/").lower()))
            if name == "AndroidManifest.xml" or name == "Info.plist":
                try:
                    with open(os.path.join(root, name), encoding="utf-8", errors="replace") as fh:
                        corpus.append(("manifest", fh.read().lower()[:200000]))
                except OSError:
                    pass
    # Native-lib inventory: REUSED from apk_control_wiring (never a parallel sweep).
    for so in bundled_libs(app_dir):
        corpus.append(("lib", so.lower()))
    if control_wiring:
        nw = control_wiring.get("native_library_wiring") or {}
        for so in (nw.get("bundled") or []) + (nw.get("loaded") or []):
            corpus.append(("lib", str(so).lower()))
        for key, row in (control_wiring.get("root_integrity") or {}).items():
            if isinstance(row, dict) and row.get("present"):
                corpus.append(("root_wiring", key.lower()))

    def find(tokens) -> list:
        return sorted({tok for tok in tokens for kind, text in corpus if tok in text})

    def cite(tokens) -> list:
        cites = []
        for kind, text in corpus:
            for tok in tokens:
                if tok in text:
                    cites.append(f"app-dir[{kind}]: {text[:140]}")
        return sorted(set(cites))[:3]

    for label, table in (("kyc_sdk", KYC_SDKS), ("root_detection", ROOT_DETECTION),
                         ("attestation", ATTESTATION), ("custody", CUSTODY)):
        for vendor, tokens in sorted(table.items()):
            hits = find(tokens)
            if hits:
                evidence["capabilities"].append(
                    {"label": f"{label}:{vendor}", "citations": cite(tokens)})
    frida = find(FRIDA_MARKERS)
    if frida:
        evidence["capabilities"].append({"label": "frida_detection", "citations": cite(FRIDA_MARKERS)})
    wallet = find(tuple(t for tokens in WALLET_SDK.values() for t in tokens))
    evidence["vertical_signals"]["wallet_sdk_hits"] = wallet
    evidence["vertical_signals"]["wallet_sdk_citations"] = cite(
        tuple(t for tokens in WALLET_SDK.values() for t in tokens))
    return evidence


def classify(org: dict | None, app: dict | None, declared: str | None) -> dict:
    """Deterministic scoring. Same inputs -> same output, every label cited."""
    scores = {"crypto": 0, "bank": 0, "fintech": 0}
    citations = {"crypto": [], "bank": [], "fintech": []}
    if org:
        for vert in ("crypto", "bank", "fintech"):
            kws = org["vertical_keywords"].get(vert) or {}
            scores[vert] += 2 * len(kws)
            citations[vert].extend(f"org-fingerprint keyword {kw!r} ({cites[0]})" for kw, cites in sorted(kws.items()))
            regs = org["registrations"].get(vert) or {}
            scores[vert] += 2 * len(regs)
            citations[vert].extend(f"{vert} registration signal {kw!r} ({cites[0]})" for kw, cites in sorted(regs.items()))
        if org.get("onchain_present"):
            scores["crypto"] += 2
            citations["crypto"].append(f"on-chain footprint ({org['onchain_citation']})")
        if org.get("custody_declared"):
            scores["crypto"] += 2
            citations["crypto"].append(f"custody stack ({org['custody_citation']})")
    if app:
        caps = {c["label"] for c in app["capabilities"]}
        wsigs = app["vertical_signals"]
        if wsigs.get("wallet_sdk_hits"):
            scores["crypto"] += 2
            citations["crypto"].append(
                f"wallet/web3 SDK signature(s) {wsigs['wallet_sdk_hits']} ({wsigs['wallet_sdk_citations'][0] if wsigs['wallet_sdk_citations'] else ''})")
        if any(c.startswith("custody:") for c in caps):
            scores["crypto"] += 2
            citations["crypto"].append("custody integration signature in bundle")
        if any(c.startswith("kyc_sdk:") for c in caps):
            # KYC/liveness is bank- AND fintech-leaning (crypto exchanges run KYC too,
            # so it never outweighs custody/on-chain evidence).
            scores["bank"] += 1
            scores["fintech"] += 1
            citations["bank"].append("KYC/liveness SDK in bundle (bank-leaning)")
            citations["fintech"].append("KYC/liveness SDK in bundle (fintech-leaning)")

    # Deterministic decision: highest score wins; ties resolved by fixed priority
    # (crypto > bank > fintech — a hybrid target leans to its strongest overlay);
    # zero evidence everywhere -> other (the universal overlay applies).
    detected = "other"
    best = max(scores.values())
    if best > 0:
        for vert in ("crypto", "bank", "fintech"):
            if scores[vert] == best:
                detected = vert
                break
    source = "declared" if declared else ("app_triage" if app else "osint")
    vertical = declared if declared else detected
    for vert in citations:
        citations[vert] = citations[vert][:8]

    capabilities = app["capabilities"] if app else []
    return {
        "tool": "vertical_classify",
        "version": VERSION,
        "vertical": vertical,
        "vertical_source": source,
        "detected_vertical": detected,
        "declared_vertical": declared,
        "scores": scores,
        "citations": citations,
        "capabilities": capabilities,
        "advisory": ("Advisory, evidence-cited, overridable: this label selects content "
                     "(overlay/skills/quantification), never authority — scope, RoE flags, "
                     "prohibitions and the CIR channel govern under every vertical. An "
                     "explicit scope-file declaration overrides detection."),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org-fingerprint", help="OSINT org-fingerprint evidence JSON (detection point A)")
    ap.add_argument("--app-dir", help="decompiled app tree (detection point B, mobile triage refresh)")
    ap.add_argument("--control-wiring", help="recon/control_wiring.json from tools/apk_control_wiring.py (reused inventory)")
    ap.add_argument("--declared", choices=VERTICALS, help="explicit human declaration from the scope file — wins over detection")
    ap.add_argument("--out-dir", help="where to write vertical.json (default: alongside the first evidence input; else cwd)")
    args = ap.parse_args(argv)

    if not (args.org_fingerprint or args.app_dir or args.declared):
        print("vertical_classify: nothing to classify — pass --org-fingerprint and/or --app-dir (and optionally --declared)", file=sys.stderr)
        return 2

    org = app = None
    control = None
    try:
        if args.org_fingerprint:
            org = scan_org_fingerprint(args.org_fingerprint)
        if args.control_wiring:
            with open(args.control_wiring, encoding="utf-8") as fh:
                control = json.load(fh)
        if args.app_dir:
            app = scan_app_dir(args.app_dir, control)
    except ValueError as e:
        print(f"vertical_classify: {e}", file=sys.stderr)
        return 2

    result = classify(org, app, args.declared)
    out_dir = args.out_dir or (os.path.dirname(os.path.abspath(args.org_fingerprint)) if args.org_fingerprint
                               else (os.path.join(args.app_dir, "recon") if args.app_dir else "."))
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "vertical.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    print(f"vertical_classify: vertical={result['vertical']} (source={result['vertical_source']}, "
          f"scores={result['scores']}, capabilities={len(result['capabilities'])}) -> {out}")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
