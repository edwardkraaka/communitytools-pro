# Handoff — from decompiled source to a MASVS pentest

The farm produces bytes and triage; the finding pass is owned by
[`../../mobile-security/SKILL.md`](../../mobile-security/SKILL.md). This file is the contract
between them. Acquisition is in [`acquisition.md`](acquisition.md); running is in
[`run-and-triage.md`](run-and-triage.md).

## Per-app handoff

For each `engagement/<pkg>/`, give the agent:

| Artifact | Use in the pentest |
|----------|--------------------|
| `jadx/sources/` | Primary source review — logic, auth, crypto contract, IPC callers |
| `apktool/AndroidManifest.xml` + `apktool/res/` | Exported components, permissions, deep links, network-security-config |
| `triage.md` | Starting worklist — permissions, endpoints, candidate secrets |
| `mobsf-report.json` | Automated MASVS baseline (severity is a hint, not the score) |

Then run the `mobile-security` static pass (SAST → manifest/IPC/storage/crypto/signing) and, where
a control is runtime-only (pinning, root detection, Keystore-backed keys), its dynamic confirmation.
Static analysis can prove a control **inert** (shipped but unwired) but never **effective** — use
[`../../../tools/apk_control_wiring.py`](../../../tools/apk_control_wiring.py) on the
`apktool`/`jadx` tree to separate a real applied control from an orphaned one.

## The backend API is a SEPARATE asset (do not skip)

A decompiled bundle hands you the **full server contract** — base URLs, paths, headers, request
shapes, and often the request-signing/crypto envelope. That surface is **not browser-reachable**, so
it is systematically under-tested. Treat it as its own **web asset**:

1. Harvest endpoints from `triage.md` (the `https?://…` list) and from `jadx/sources` (Retrofit/OkHttp
   interfaces, `@GET`/`@POST` paths, base-URL constants).
2. Reconstruct request signing / encrypted envelopes (KEY/IV/SALT/SIGNATURE headers) from the crypto
   classes, then replay against the live API.
3. Drive it through the ordinary OWASP **API/web classes** — BOLA/IDOR, auth, mass-assignment,
   injection — under `<apex>-api/`, with its own `recon/inventory/surface.json`.

Per the coordinator's coverage model
([`../../coordination/reference/coverage-matrix.md`](../../coordination/reference/coverage-matrix.md)),
the app bundle enumerates the **15 MASVS classes**; the backend enumerates the **24 web/API classes**.
A mobile engagement that only tests the bundle leaves the real risk untested — a bundle that yields
**zero endpoints is a failed acquisition**, not a clean bill.

## Coverage-mode (optional)

For a `pentest-engagement` mobile-mode run, build the machine-readable surface the coverage gate
consumes:

```bash
python3 tools/mobile_manifest_facts.py --platform android \
        --decoded engagement/<pkg>/apktool --app-dir engagement/<pkg> \
        --artifact engagement/<pkg>/base.apk \
        --artifact-sha256 "$(cut -d' ' -f1 engagement/<pkg>/apk.sha256)"
python3 tools/mobile_surface_build.py --app-dir engagement/<pkg> \
        --engagement-dir engagement/ --platform android --allow <in-scope apexes>
```

`tools/enumerate_cells.py` then reads `mobile-surface.json` to code-produce the applicable MASVS
work-list, and `tools/coverage_gate.py` enforces completion against on-disk evidence. Non-coverage
(ad-hoc) runs skip this and work straight from `jadx/sources` + `triage.md`.

## iOS

`ipa-pipeline.sh` yields plist/entitlements/URL surface only. Manifest-equivalent findings
(ATS exceptions, URL schemes, entitlements, associated domains) are reportable statically. Binary
(Mach-O) logic requires a **jailbroken-device decrypt** (`bagbak` / `frida-ios-dump`); once
decrypted, hand the `.ipa` to `mobile-security`'s iOS static/dynamic references like any other.
