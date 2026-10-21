# Vertical overlay: bank (and fintech)

Mounted when the target vertical is `bank` or `fintech` — an explicit scope declaration (which always wins) or the OSINT-detected label from `tools/vertical_classify.py --org-fingerprint` (refreshed at mobile triage with `--app-dir`). The `fintech` label dispatches HERE: funds-movement surfaces (payments, mandates, wallets-as-a-service, ledger rails) ride the bank definition, keeping the fintech label for reporting.

**Contract.** This overlay SELECTS CONTENT, NEVER AUTHORITY. The universal discipline — scope, RoE flags, prohibitions, the impact-rung bar ([`severity-calibration.md`](../severity-calibration.md) rule 6), the exploitation mandate ([`principles.md`](../principles.md) "Exploitation depth") — governs identically under every vertical. This overlay defines only HOW the financial-harm rung is quantified, which bank-specific impact claims count toward it, and which bank-specific second-stage guidance (KYC/liveness, anti-tamper, instrumentation, root/integrity) mounts on mobile surfaces. Nothing here adds authority; nothing here removes a prohibition.

## Financial-harm rung (the bank/fintech quantification)

The universal rung — quantified financial harm, value-at-risk demonstrated by a NON-DESTRUCTIVE proof of authority — is quantified on bank/fintech targets as **demonstrated authority over funds movement on a reversible own-tenant path**:

- a **non-destructive create-then-delete proof on the client's own transfer/mandate flow** — the reversible-active-exploitation pattern ([`principles.md`](../principles.md) "Reversible active exploitation"): create a draft transfer/mandate under the compromised principal in the tester's OWN org/tenant, show it is reachable/actable, then delete it and log the create + cleanup. **NEVER a live transfer to any third party.** A transfer that moves real money out of the tenant is prohibited regardless of how it is labeled.
- or **quantified account exposure** — the number + aggregate balance of accounts the compromised position reaches (customer accounts, treasury accounts, internal ledgers), from enumerated access or the institution's own reporting surfaces.

Either form demonstrates control without moving funds. The proof stops at demonstrating authority; it never executes a payment.

Two further bank-specific impact claims count toward the rung only when DEMONSTRATED, never inferred:

- **Server-verified attestation bypass** - a distinct impact claim: the backend ACCEPTED an action it should have rejected (or rejected one it should have accepted) carrying a forged, stale, or mismatched integrity verdict, with the full chain (verdict + nonce + requestHash) verified server-side before the claim is credited. A client-side Boolean flip alone is never this claim (see "Root / integrity" below).
- **KYC-flow trust-boundary compromise** - the backend credited a KYC/liveness decision to an applicant/session/evidence tuple it should have rejected: stale, mismatched, or duplicated session correlation, or a decision issued without its evidence. Quantify what the compromised flow gates: account openings, onboarding states, transaction limits, funds reachable through accounts opened via the compromised path.

- This sentence is mirrored byte-for-byte in the single-source JS constant `IMPACT_RUNGS.financial_overlay.bank` / `.fintech` (`.claude/workflows/lib/wf-helpers.mjs`; inline copies in the three workflow scripts are parity-governed).

## KYC selfie / liveness tooling analysis

These instructions authorize analysis of the CLIENT'S KYC FLOW within the engagement scope - **never testing the KYC vendor's production service**. Client authorization does not automatically grant permission to test an independent SDK provider's production service: that third-party boundary goes through the CIR channel ([`principles.md`](../principles.md) "RoE authorization boundary"), and any vendor sandbox/test tenant is used only under the client's own vendor agreement.

- **Vendor SDK identification first** - identify WHICH liveness engine is deployed before designing any test: Onfido/Entrust, Jumio, Veriff, Persona, iProov, FaceTec (the classifier's `kyc_sdk:<vendor>` capability label detects the full signature set: Sumsub, IDnow, Socure, SmileID, AU10TIX, Yoti included) - from the app bundle: SDK strings, class/package names, network hosts, manifest artifacts (static pass: [`android-static-analysis.md`](../../../mobile-security/reference/android-static-analysis.md) / [`ios-static-analysis.md`](../../../mobile-security/reference/ios-static-analysis.md)). A visible selfie prompt or SDK brand does not establish which backend checks are active.
- **Evaluation layers - distinct tests, NEVER conflated**: (1) **presentation attack** - a physical artifact shown to the real camera (photo, screen replay, mask); (2) **injection** - media substituted into the capture/processing path rather than shown to a camera (virtual camera, modified device, emulator, API manipulation); (3) **deepfake / manipulated media** - synthetic or manipulated content, deliverable through EITHER of the first two paths; (4) **identity binding** - a live person and the claimed identity are different checks (liveness vs face comparison vs government-ID linkage). Design one case per layer; report each layer's result per layer - one layer passing says nothing about the others.
- **Capture-path integrity** - virtual cameras, emulators, rooted devices, and sensor-consistency signals (motion/orientation corroborating the claimed capture) are each evaluated and each reported as its own observation, never as one merged "environment" result.
- **Session / trust-boundary verification** - the backend must independently correlate applicant → session → evidence → decision. Within the approved harness, evaluate stale, mismatched, interrupted, and duplicated sessions; a decision credited to a mismatched or replayed session IS the trust-boundary finding.
- **Deployed-configuration recording** - record the deployed SDK version, product tier, enabled policy, backend correlation ID, and server-side reason codes - not only the on-screen result. Vendors ship materially different engines per tier (an older integration does not inherit a newer injection-aware product); an evaluated control is meaningless without its recorded configuration.
- **Mock-vs-production distinction** - a sandbox returning canned verdicts proves nothing about production detection; KYC mock/sandbox outcomes are test modifications, not security findings. Only the production configuration (or the client's production-identical tenant, with the vendor's role recorded) counts as evidence about the control.
- **Biometric-data minimization** - use synthetic or explicitly consented fixtures, encrypted storage, limited access, fixed retention, and deletion evidence ([`privacy-testing.md`](../../../mobile-security/reference/privacy-testing.md)); biometric fixtures are engagement evidence governed by the same minimization rules as any other sensitive data.

## Anti-tamper / anti-Frida mapping

Bank apps commonly carry commercial anti-tamper/anti-Frida stacks on top of the universal MAS-RESILIENCE classes. Map the full detection-layer taxonomy before claiming a bypass - technique detail lives in [`android-dynamic-analysis.md`](../../../mobile-security/reference/android-dynamic-analysis.md) and [`ios-dynamic-analysis.md`](../../../mobile-security/reference/ios-dynamic-analysis.md):

| Detection layer | What the app examines |
|---|---|
| Port / protocol probes | localhost port **27042**, other known ports, recognizable protocol responses (iOS: D-Bus AUTH probing) |
| Thread enumeration | `/proc/self/task/<tid>/status`, historical names (`gum-js-loop`, `gdbus`) |
| Maps + memory markers | `/proc/self/maps` / `smaps`, agent/Gadget paths, suspicious executable mappings, in-memory `LIBFRIDA` strings |
| IPC / file artifacts | unix sockets, named pipes, file descriptors, installation paths, version-dependent `frida-` strings |
| Hook / code-integrity evidence | interceptor trampolines, code changes, executable-memory behavior - remains after names are stripped |
| iOS loader difference | dyld-image scan (`_dyld_image_count`) vs frida-server's custom Mach-O loader keeping the agent OUTSIDE dyld's image list - a clean dyld list is not proof of no instrumentation |

**Two-lane discipline** - every finding is labeled with the lane that produced it:

- **Production-equivalent build** (resilience evaluation, MAS-RESILIENCE-ROOT / -INTEGRITY): a detection survived or defeated is claimed ONLY from this lane - the unmodified release artifact, unmodified instrumentation.
- **Modified observation build** (logic inspection): a client-provided debug/re-signed build with local gates disabled, for business-logic, storage, and network inspection. A modified observation build is **never reported as the release artifact**, and "we disabled a local gate to inspect the app" is never conflated with "the backend accepted an unauthorized operation".

## Instrumentation discipline

- **Upstream Frida first, version-pinned** (host package + frida-server/Gadget + bridge dependencies + agent). 17.x removed the Java/ObjC/Swift bridges from core GumJS and the legacy `Memory.read*`/`write*` APIs - old CodeShare snippets and harnesses fail on 17.x for stack reasons, not app reasons.
- **Stealth forks are stale vs upstream 17.x**: strongR-frida-android ends at **16.7.14**, Florida at **16.7.0** - lagging 16.x branches, usable only when a documented detection test requires them, on an explicitly compatible lab image. Pin and record repo/tag/hash (plus patch set and architecture) for every fork or patched build - a fork name ("Hluda" is a lineage, not a version) is not a pin.
- **Objection (1.12.5, Frida-17-compatible) for exploration** - pinning bypass, filesystem/keychain work, runtime inspection; do not design automation around its retired webserver.
- **Acceptance-test the stack before attributing failure to the app**: launch/attach, enumerate modules, exercise the required language bridge, install one harmless observation hook, detach, repeat. Only after that passes may a detection failure be attributed to the target rather than the instrumentation stack.

## Root / integrity: Play Integrity verdict separation

SafetyNet is retired (fully turned down January 2025); Play Integrity is the successor, and its verdicts are SEPARATE signals, never merged:

- **Basic vs strong**: `MEETS_BASIC_INTEGRITY` can hold on an unlocked/unverified-boot device; `MEETS_STRONG_INTEGRITY` (Android 13+) additionally requires recent OS/vendor security updates and genuine hardware - a rooted/re-signed test device is a separately documented trust boundary, never assumed to pass strong.
- **App recognition / licensing**: `PLAY_RECOGNIZED` and `LICENSED` are separate concerns from hiding `su` or instrumentation - repackaging or sideloading changes them even when local detection is disabled; access-risk signals (capture/overlay-capable apps) ride their own optional verdicts.
- **`MEETS_VIRTUAL_INTEGRITY` is Play-Games-only** - documented for apps distributed through Google Play Games on PC; it is NOT a general approval of an arbitrary Android emulator.
- **Test responses via provider-supported testing channels** - Play Integrity test responses for selected accounts (`testingDetails.isTestingResponse`) or a narrowly scoped staging policy - kept distinct from real-device attestation evidence.
- **Server-side verification (the rule)**: attestation is only real if the SERVER verifies the Play Integrity verdict + nonce (+ `requestHash`) - a client-only `integrity.token` call that never round-trips to a server that checks it is bypassable; confirm server-side verification before crediting the control (MASVS-RESILIENCE-1, [`android-dynamic-analysis.md`](../../../mobile-security/reference/android-dynamic-analysis.md)). A client-side Boolean bypass is **not server-enforcement defeat**: flip the client verdict, then verify verdict + nonce + requestHash server-side - and test the backend's rejection of malformed, stale, and mismatched evidence directly - before crediting anything. A clean-device success likewise proves nothing about backend enforcement; they are separate tests.

## Skill mounts

No vertical-specific classes mount today — the standard (type, vertical) mapping already covers the funds-movement surface (API security, authentication, server-side, mobile MASVS). The KYC/liveness, anti-tamper, instrumentation, and root/integrity guidance above rides the mobile-security lane's universal MAS-RESILIENCE-ROOT / -INTEGRITY classes; no new vertical-conditional class is introduced. Vertical-conditional coverage classes (catalog `verticals` constraints) remain the only gating mechanism; every universal class applies unchanged.
