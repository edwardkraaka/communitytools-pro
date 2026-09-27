# Mobile — 2026 Static Attack Surfaces: AAB/CT, SDK IPC, FCM, WASM (Android) Static Analysis

Beyond the classic manifest-and-dex SAST pass lies a set of 2026-documented surfaces that hide in the bundle format (`AAB` / Code Transparency), inside third-party SDK manifests, in push-handler code paths, and in concealed runtimes (WASM, ML models). Every one of them has a cheap static test — a grep, a re-verify, a diff against a sibling build — and each has produced real 2025-26 findings at scale. This scenario is the checklist pass to run once the core [android-static-analysis.md](../../android-static-analysis.md) flow is done.

## When to use

- The engagement scope includes an `.aab` artifact or the client distributes via AAB to Play (Code Transparency territory).
- The vendor ships white-label builds — sibling apps from the same codebase exist on any store.
- The app embeds a heavy SDK footprint (engagement/marketing/push SDKs are the usual suspects).
- A `FirebaseMessagingService` subclass appears in the decompiled tree (FCM handler abuse).
- The app is a **TWA** (Trusted Web Activity) with an `assetlinks.json` at the web origin.
- `\0asm` magic bytes appear in `lib/<abi>/` or `assets/` (WASM module — a concealed runtime).
- The bundle ships `.tflite` / `.onnx` models (local-ML abuse surface).
- An R8/ProGuard `mapping.txt` surfaced in a leak, a public repo, or a crash-report artifact.
- The RN version (recovered per [react-native-hermes.md](react-native-hermes.md)) falls in a known-CVE range.

## AAB / Code Transparency gaps

A Code Transparency file in an AAB normally means "the bundle I signed is the bundle that ships." The gap (TU Graz work, 2025-26): **CT covers only DEX and native libraries** — the merged manifest and assets remain modifiable while the signature still verifies. `bundletool` also never enforces that the CT signing key differs from the app signing key, so a single-key operator silently loses the separation the feature assumes.

```bash
# Test: strip the CT file, modify AndroidManifest.xml (add an exported activity),
# rebuild, and re-verify — a still-passing verify is the finding:
java -jar bundletool-all.jar build-apks --bundle=app.aab --output=out.apks --mode=universal
unzip -p out.apks universal.apk | grep -c "com.android.tools":  # locate merged manifest
java -jar bundletool-all.jar validate --bundle app.aab            # does it complain?
apksigner verify -v universal.apk                                 # still valid?
```

Acquisition of AAB artifacts and the bundletool version pin live in [methodology.md](../../methodology.md) (ACQUIRE phase) — this pass only applies once the artifact is on disk.

## Play Core persistent code execution

The Play Core library family supports post-install feature-module and asset delivery — which is persistent code execution by design. The Oversecured finding (in the Play Core in-app-update path): insufficiently validated update metadata lets an attacker-controlled component supply code that runs on every app start. Static indicator: `com.google.android.play.core` imports in the decompiled tree combined with an integrity-unchecked listener for update/install events. Score on reachability: who controls the metadata your listener trusts?

## White-label / fork differential

Sibling builds from the same vendor (white-label apps, regional forks, an "enterprise" and a "consumer" build) retain what the polished flagship removed: debug endpoints, staging API hosts, test keys, internal-namespace components. The technique (ApkDiff/DNADroid lineage, operationalized on this repo's farm):

```bash
# 1. Acquire BOTH sibling builds (see mobile-app-farm acquisition):
#    scripts/apk-pipeline.sh com.vendor.consumer engagement/com.vendor.consumer
#    scripts/apk-pipeline.sh com.vendor.enterprise engagement/com.vendor.enterprise
# 2. Diff the decompiled trees, ignoring the resource noise:
diff -r engagement/com.vendor.consumer/jadx/sources engagement/com.vendor.enterprise/jadx/sources \
  | grep -vE "^Only in.*res|^Binary" | head -100
# 3. Diff the exported components — the sibling frequently exports MORE:
diff <(rg -o 'android:exported="true"' -B2 engagement/com.vendor.consumer/apktool/AndroidManifest.xml) \
     <(rg -o 'android:exported="true"' -B2 engagement/com.vendor.enterprise/apktool/AndroidManifest.xml)
# 4. Hunt the debug leftovers the flagship cleaned:
rg -n "staging\.|\.internal\.|debug[^A-Za-z]" engagement/com.vendor.enterprise/jadx/sources | head -50
```

The finding is whatever the sibling exposes that the flagship does not — report against both builds, since the sibling's signing usually shares the vendor's update lineage.

## Exported SDK components

The 2025 EngageLab EngageSDK incident (50M installs / 30M crypto-wallet exposures via intent redirection, patched v5.2.1, Nov 2025) established the pattern: third-party SDK manifest entries — merged into your target's app — contribute their own exported components, and the app's own manifest audit never looks at them. Audit the merged manifest by namespace:

```bash
# Enumerate exported components grouped by their declaring SDK namespace:
rg -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*>' apktool/AndroidManifest.xml \
  | rg -oE 'android:name="[^"]+"' | sort | uniq -c | sort -rn
# Every namespace that is not the app's own package id is an SDK contribution —
# check each against the SDK vendor's advisory history.
```

Cross-link: the runtime reachability confirmation for any surfaced component is the `am start` / `content query` work in [android-static-analysis.md](../../android-static-analysis.md) §2-3.

## FCM handler abuse

Firebase Cloud Messaging delivers an app-controlled API surface that SAST rarely inspects: the push message itself. `FirebaseMessagingService.onMessageReceived` executes with the app's full privilege, and messages can be sent by anyone holding the server key ("Medium is the Message", arXiv 2407.10589 — content leakage in 4 studied apps; the 2024 $30k-bounty server-key extraction class). The FCM message protobuf has no integrity/authenticity field the client can check — trust is entirely in key custody.

```bash
# Find handlers and trace the message payload into sinks:
rg -ln "extends FirebaseMessagingService" jadx/sources
rg -n "onMessageReceived" jadx/sources -A 15 | rg -iE "get\s*\( |intent|url|http|exec|load|start" | head -40
# A message field flowing into an Intent, URI, WebView load, or dynamic-module load
# is command-execution-by-push — the server key is then the only gate. Check whether
# it leaks: AIza..., firebaseio.com, appspot.com in res/ and the google-services.json blob.
```

## PendingIntent provenance

Classic PendingIntent review (CWE-927 / MASWE-0117 — the static bullet in [android-static-analysis.md](../../android-static-analysis.md) §3) covers the *mutability* failure. The 2026 nuance (arXiv 2603.02539): `PendingIntent.getCreatorPackage()` returns the **creator** (who built it), not the **presenter** (who fired it) — receivers authenticating the sender by creator identity accept presentations from any app the intent was relayed to. Roughly 4k of 180k audited apps were spoofable this way. Static test: find `getCreatorPackage` calls and check whether the guarded action assumes "caller == creator."

## TWA / assetlinks gaps

Trusted Web Activities delegate the rendering to Chrome and the trust to a `/.well-known/assetlinks.json` at the web origin. The 2024-26 CVE set (CVE-2024-20837, 5.3 MEDIUM; CVE-2026-87486, 4.0 MEDIUM; CVE-2026-87552, 5.5 MEDIUM — scores via NVD): multi-origin configurations where the statement list omits an origin the app still trusts, letting a second app bind the same web relationship. For an engagement: fetch the origin's assetlinks.json, diff the declared origins against every origin the app actually navigates (grep the decompiled tree for the TWA launch URLs), and report every trusted-but-undeclared or declared-but-stale origin.

## WASM concealment

A WASM module inside an APK is a runtime neither dalvik SAST nor most scanners inspect (AndroWasm, arXiv 2602.18082 — MobSF and VirusTotal are blind to the pattern; used to conceal license checks, DRM, and payload logic). The module runs host-side via a WASM runtime the app bundles.

```bash
# Find concealed WASM — the \0asm magic at a page-boundary-aligned offset:
rg -aobu '\x00asm' --no-messages lib/ assets/ | head
# Extract and decompile to WAT (WebAssembly text) for review:
wasm2wat extracted.wasm -o module.wat        # WABT; then grep the .wat for URLs/keys/dispatch logic
rg -n "http|key|secret|license" module.wat | head -20
```

## ML-model abuse

Apps increasingly run local ML for sensitive classification (fraud scoring, content moderation, OCR of documents). Smart App Attack (arXiv 2204.11075): adversarial inputs coerced 38 of 53 studied apps' local models into wrong outputs — 71.7% attack success — which becomes an authorization bypass when the model gates a flow. Static inventory plus sink-mapping:

```bash
# Inventory the models the app ships or downloads:
find apktool -name "*.tflite" -o -name "*.onnx" -o -name "*.pb" | head
# Map the inputs: where does untrusted data (intent extras, form text) reach the model?
rg -ln "TensorBuffer|tflite|OnnxTensor" jadx/sources | head
```

Test dynamically per [android-dynamic-analysis.md](../../android-dynamic-analysis.md): mutate the input field's content and observe whether the gated decision changes.

## R8 / ProGuard mapping hunt

A leaked `mapping.txt` is full deobfuscation: every `a.b.c` back to its real name. Before accepting "the logic is obfuscated, analysis stops," hunt for the mapping: public vendor repos, crash-report exports, support-forum attachments, the app's own backup volume. With no mapping, LLM-assisted renaming seeded from anchors (resource strings, endpoint paths, log tags — the react-native-hermes BuildConfig fast-path is the same idea) recovers a surprising fraction of semantics.

## React Native CVEs

Two 2025 RN-side CVEs reachable from an app that embeds a vulnerable RN version: **CVE-2025-11953** (9.8 CRITICAL, NVD) and **React2Shell CVE-2025-55182** (10.0 CRITICAL, NVD). Confirm the RN version before citing either — the version-recovery procedure is [react-native-hermes.md](react-native-hermes.md). Presence is not exploitability: check the vulnerable component is on a reachable path before scoring (the [SBOM pass](../../android-static-analysis.md) §9 discipline).

## Toolchain

| Tool | Command | When | Notes |
|------|---------|------|-------|
| **bundletool** (Google) | `java -jar bundletool-all.jar build-apks …` | AAB / CT pass | version-pinned jar per [methodology.md](../../methodology.md); `validate` + `apksigner verify` are the CT gap probes |
| **apksigner** (Android build-tools) | `apksigner verify -v universal.apk` | CT / signing checks | scheme set + signer identity output |
| **jadx** | `jadx -d jadx/ base.apk` | differential + sink greps | same base decompile the farm pipeline produces |
| **rg** (ripgrep) | `rg -aobu '\x00asm' lib/ assets/` | WASM magic scan, sink traces | binary-mode `-a` for the magic-number sweep |
| **wasm2wat** (WABT) | `wasm2wat module.wasm -o module.wat` | WASM decompile | pin the version `wasm2wat --version` reports on your rig |
| **nvd-lookup** (this repo) | `python3 tools/nvd-lookup.py CVE-…` | every CVE cited | repository rule: authoritative CVSS/CWE before any severity prose |

## MASVS map

Copy ids only from the sources below; per-class anchors live in [masvs-class-map.md](../../masvs-class-map.md) and [methodology.md](../../methodology.md).

- **MAS-PLATFORM-IPC** (MASTG-TEST-0250s · MASWE-0060) — exported SDK components, PendingIntent provenance, FCM-driven intent dispatch, TWA relationships.
- **MAS-PLATFORM-WEBVIEW** (MASVS-PLATFORM-2 / MASWE-0069) — TWA as a trust-boundary surface rather than "just a WebView."
- **MAS-CODE-DEPENDENCY** (MASTG-TEST-0270s · MASWE-0071) — the EngageSDK case is the canonical SDK-as-dependency finding; RN CVEs and Play Core are the same class.
- **MAS-RESILIENCE-INTEGRITY** (MASTG-TEST-0280s · MASWE-0100) — AAB/CT gaps: manifest modified, signature still valid.
- **MAS-CODE-SECRETS** (MASTG-TEST-0270s · MASWE-0071) — leaked mapping.txt, white-label debug keys, FCM server keys.
- **MAS-PLATFORM-SCREEN** / **MAS-PRIVACY-DATA** (MASTG-TEST-0300s · MASWE-0110) — FCM content leakage into notification surfaces.
- **MAS-AUTH-LOCAL** (MASTG-TEST-0017 · MASWE-0040) — local-ML decisions gating authorization flows.

## Anti-Patterns

- Auditing only the app's own manifest namespace and skipping merged SDK manifest entries — the EngageSDK lesson (50M installs) is entirely an SDK-manifest miss.
- Calling a CT-signed bundle tamper-proof without running the manifest-modification test — the CT file covers DEX and `.so`, little else.
- Writing a CVSS from memory — every CVE id in a report goes through `python3 tools/nvd-lookup.py <id>` first (repo rule).
- Concluding there is no hidden logic after grepping only `classes*.dex` — a `\0asm` module in `assets/` is invisible to that grep and to MobSF.
- Treating a TWA as just a WebView — the `assetlinks.json` multi-origin gap makes it a trust-boundary question between two codebases.
- Scoring an RN CVE on version presence alone — the vulnerable component needs a reachable path (SBOM §9 discipline).
- Discarding a sibling build because "it is the same codebase" — the differential IS the finding source; the sibling retains what the flagship cleaned.

## Cross-references

- [advanced-ebpf-dynamic-2026.md](advanced-ebpf-dynamic-2026.md) — the dynamic counterpart: capture, fuzzing, and relay lanes that consume these static targets.
- [android-static-analysis.md](../../android-static-analysis.md) — the base SAST flow this pass extends (manifest §2-3, PendingIntent §3, SBOM §9).
- [methodology.md](../../methodology.md) — AAB acquisition + bundletool pinning, MASVS/MASTG anchors, client→API pivot.
- [react-native-hermes.md](react-native-hermes.md) — RN version recovery (CVE applicability) and the BuildConfig secret fast-path.
- [masvs-class-map.md](../../masvs-class-map.md) — class-level completion contracts.
- [acquisition.md](../../../../mobile-app-farm/reference/acquisition.md) — acquiring sibling builds for the white-label differential.
