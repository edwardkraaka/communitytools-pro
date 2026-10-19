#!/usr/bin/env python3
"""Tests for tools/vertical_classify.py (deterministic vertical classifier).

Synthetic fixtures only (client-neutral org names like Example Corp / com/example;
the vendor SDK signatures exercised here are the tool's own public knowledge tables,
not real client artifacts). stdlib + subprocess, no pytest.
Run: python3 tools/test_vertical_classify.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "vertical_classify.py")


def run_tool(*argv):
    p = subprocess.run([sys.executable, TOOL, *argv],
                        capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


def last_json(stdout):
    lines = [l for l in stdout.splitlines() if l.strip()]
    return json.loads(lines[-1])


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


class TestOrgFingerprintClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def classify(self, evidence, *extra):
        p = write_json(os.path.join(self.tmp.name, "org-fingerprint.json"), evidence)
        rc, out, err = run_tool("--org-fingerprint", p, *extra)
        self.assertEqual(rc, 0, err or out)
        return last_json(out)

    def test_crypto_org_fingerprint(self):
        r = self.classify({
            "org_description": "Example Corp builds a self-custody crypto wallet and DEX aggregator.",
            "custody_stack": ["ExampleVault"],
            "onchain_footprint": {"present": True, "notes": "proxy admin + timelock"},
        })
        self.assertEqual(r["vertical"], "crypto")
        self.assertEqual(r["vertical_source"], "osint")
        self.assertTrue(any("custody stack" in c for c in r["citations"]["crypto"]))
        self.assertTrue(any("on-chain footprint" in c for c in r["citations"]["crypto"]))
        self.assertIn("advisory", r)

    def test_bank_org_fingerprint(self):
        r = self.classify({
            "org_description": "Example Bank — a licensed retail bank with a savings and loan portfolio.",
            "regulatory": ["national bank charter", "FDIC member"],
            "job_posts": ["AML analyst", "branch network operations"],
        })
        self.assertEqual(r["vertical"], "bank")
        self.assertTrue(any("bank" in c for c in r["citations"]["bank"]))

    def test_fintech_org_fingerprint(self):
        r = self.classify({
            "org_description": "Example Pay — payments and remittance rails with open banking APIs.",
            "regulatory": ["MSB license"],
        })
        self.assertEqual(r["vertical"], "fintech")
        self.assertTrue(any("payment" in c for c in r["citations"]["fintech"]))

    def test_no_evidence_is_other(self):
        r = self.classify({"org_description": "Example Corp makes developer tooling."})
        self.assertEqual(r["vertical"], "other")

    def test_declared_overrides_detection(self):
        r = self.classify({
            "org_description": "Example Bank — licensed retail bank.",
        }, "--declared", "crypto")
        self.assertEqual(r["vertical"], "crypto")
        self.assertEqual(r["vertical_source"], "declared")
        self.assertEqual(r["detected_vertical"], "bank")
        self.assertEqual(r["declared_vertical"], "crypto")

    def test_declared_only(self):
        rc, out, err = run_tool("--declared", "bank")
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertEqual(r["vertical"], "bank")
        self.assertEqual(r["vertical_source"], "declared")

    def test_deterministic_same_input_same_output(self):
        ev = {"org_description": "Example Chain — blockchain custody and web3 infrastructure."}
        a, b = self.classify(ev), self.classify(ev)
        self.assertEqual(a, b)

    def test_missing_input_fails(self):
        rc, out, err = run_tool()
        self.assertEqual(rc, 2)


class TestAppTriageClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = os.path.join(self.tmp.name, "app")

    def make_app(self, smali_pkgs=(), libs=(), manifest_text="", files=()):
        for pkg in smali_pkgs:
            d = os.path.join(self.app, "smali", *pkg.split("/"))
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "Example.clazz"), "w").close()
        for so in libs:
            d = os.path.join(self.app, "lib", "arm64-v8a")
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, so), "wb").close()
        if manifest_text:
            os.makedirs(self.app, exist_ok=True)
            with open(os.path.join(self.app, "AndroidManifest.xml"), "w") as fh:
                fh.write(manifest_text)
        for rel in files:
            p = os.path.join(self.app, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()
        return self.app

    def test_kyc_bank_app(self):
        self.make_app(smali_pkgs=["com/example/app", "com/onfido/sdk"],
                      libs=["libexample.so", "libonfido-impl.so"],
                      manifest_text="<manifest package='com.example.bankapp'></manifest>")
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertEqual(r["vertical"], "bank")
        caps = {c["label"] for c in r["capabilities"]}
        self.assertIn("kyc_sdk:onfido", caps)
        self.assertTrue(all(c["citations"] for c in r["capabilities"]))

    def test_crypto_wallet_app(self):
        self.make_app(smali_pkgs=["com/example/wallet", "com/walletconnect"],
                      libs=["libsecp256k1.so"])
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertEqual(r["vertical"], "crypto")
        self.assertEqual(r["vertical_source"], "app_triage")

    def test_crypto_exchange_kyc_still_crypto(self):
        # KYC alone is bank/fintech-leaning (+1 each) but custody/on-chain evidence
        # outweighs it: a crypto exchange with KYC stays crypto.
        self.make_app(smali_pkgs=["com/example/exchange", "com/veriff/sdk"],
                      libs=["libkeccak.so", "libfireblocks-core.so"])
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertEqual(r["vertical"], "crypto")
        caps = {c["label"] for c in r["capabilities"]}
        self.assertIn("kyc_sdk:veriff", caps)
        self.assertIn("custody:fireblocks", caps)

    def test_capabilities_via_manifest_and_paths(self):
        self.make_app(smali_pkgs=["com/example/app"],
                      manifest_text="<manifest package='com.example.app'>com.scottyab.rootbeer.RootBeer</manifest>",
                      files=["assets/frida-server-detect.txt"])
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        caps = {c["label"] for c in r["capabilities"]}
        self.assertIn("root_detection:rootbeer", caps)
        self.assertIn("frida_detection", caps)

    def test_attestation_capability(self):
        self.make_app(smali_pkgs=["com/google/android/play/core/integrity"])
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertIn("attestation:play_integrity", {c["label"] for c in r["capabilities"]})

    def test_control_wiring_inventory_reused(self):
        # The root-integrity inventory from apk_control_wiring is consumed via
        # --control-wiring rather than re-derived (no parallel enumeration).
        app = self.make_app(smali_pkgs=["com/example/app"])
        cw = write_json(os.path.join(self.tmp.name, "control_wiring.json"), {
            "native_library_wiring": {"bundled": ["librootbeer-native.so"], "loaded": [], "orphaned": []},
            "root_integrity": {"rootbeer": {"present": True, "references": 3, "wired": False, "shipped_but_unwired": True}},
        })
        rc, out, err = run_tool("--app-dir", app, "--control-wiring", cw)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertIn("root_detection:rootbeer", {c["label"] for c in r["capabilities"]})

    def test_no_signals_is_other_with_no_capabilities(self):
        self.make_app(smali_pkgs=["com/example/plain"])
        rc, out, err = run_tool("--app-dir", self.app)
        self.assertEqual(rc, 0, err or out)
        r = last_json(out)
        self.assertEqual(r["vertical"], "other")
        self.assertEqual(r["capabilities"], [])

    def test_vertical_json_written(self):
        self.make_app(smali_pkgs=["com/example/wallet", "com/metamask/sdk"])
        out_dir = os.path.join(self.tmp.name, "recon")
        rc, out, err = run_tool("--app-dir", self.app, "--out-dir", out_dir)
        self.assertEqual(rc, 0, err or out)
        with open(os.path.join(out_dir, "vertical.json")) as fh:
            persisted = json.load(fh)
        self.assertEqual(persisted["vertical"], last_json(out)["vertical"])


class TestOverlaySelectionContract(unittest.TestCase):
    """The vertical -> overlay mapping the dispatch seams rely on (documented in
    skills/coordination/reference/verticals/): crypto->crypto, bank->bank,
    fintech->bank (funds-movement quantification), other->other."""

    def test_enum_is_closed(self):
        rc, out, err = run_tool("--declared", "nonsense")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
