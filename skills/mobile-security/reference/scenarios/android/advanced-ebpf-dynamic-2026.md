# Mobile — eBPF & the 2026 Dynamic Toolkit (Android) Dynamic Analysis

Current-gen dynamic analysis moves traffic interception into the kernel: eBPF uprobes on the TLS/SSL functions see plaintext immediately before encryption and after decryption, with no proxy position, no installed CA, and no per-target patching. Certificate pinning becomes moot by construction — the capture point is inside the app's own process, after the TLS library has done its work. That collapses the per-app Frida-script maintenance burden that classic mobile MITM carries, and one rooted rig then covers a whole portfolio. Around that core, the 2026 toolkit refreshes the other dynamic lanes: intent/deeplink fuzzing, LLM-driven GUI agents, in-memory DEX recovery, and integrity-relay testing for Play-Integrity-gated flows.

## When to use

- A proxy + custom CA is repeatedly defeated by pinning (JS layer, native layer, or both — see [android-dynamic-analysis.md](../../android-dynamic-analysis.md) for the cross-stack ladder) or by a pinned non-HTTP protocol.
- One rooted rig must cover many apps — eBPF capture needs no per-target script, so it scales where Frida hook scripts do not.
- Anti-ptrace / anti-Frida detection blocks classic instrumentation (kernel-side uprobes are not the ptrace vector).
- Coverage must exceed the ~30% screen ceiling that scripted crawlers hit; fuzzing at the intent/deeplink layer or LLM GUI agents explore paths no script enumerates.
- A packer or encrypted DEX hides the real logic from static analysis — dump it from memory at runtime.
- The target gates a flow on Play Integrity and you need to test the server's verdict handling, not just the client.

## eBPF traffic capture vs proxy vs Frida

`ecapture` attaches uprobes to `SSL_read`/`SSL_write` (and per-stack variants — BoringSSL, GnuTLS, Java SSL via libssl hooks): the probe fires at the function boundary where the buffer is already plaintext. There is no MITM position, so pinning is irrelevant to the capture; there is no ptrace attach, so classic anti-debug does not see it. The same rig serves every app — an app update changes function offsets at worst, and ecapture resolves symbols per target.

Honest caveat: an aggressive RASP can still notice tracing-related kernel state or the absence of expected Attestation — frame eBPF capture as "invisible to the common detection classes," an improvement over proxy and Frida, not a universal cloak.

## Toolchain

| Tool | Command | When | Notes |
|------|---------|------|-------|
| **ecapture** (gojue) | `ecapture tls -i wlan0` | primary traffic capture | last commit **2026-09-26**; eBPF uprobes on SSL functions — plaintext pre-encryption, no proxy/CA/patch; beats pinning entirely; one rig covers every app |
| **frida-dexdump** | `frida-dexdump -U -f com.pkg` | packers / encrypted DEX | definitive dump of decrypted DEX from memory (pairs with the packer workflow in [packed-binaries.md](../../../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md)) |
| **objection** (sensepost) | `objection patchapk -s app.apk` | no-root gadget injection | last commit **2026-09-17**; `patchapk` embeds a Frida gadget — gets the app onto a non-rooted device |
| **Maestro** (by-mobiledevops) | `maestro test flow.yaml` | GUI-agent driver | updated **2026-09-25**; the practical scripted-flow lane, usable as the harness for LLM agents |
| **Detect-Maestro** | — | anti-detection pre-check | caveat row: GUI-agent harnesses are detectable (env markers, input timing); probe your rig before trusting coverage |
| **MALintent** (sslab-gatech) | `malintent --apks <dir>` | intent fuzzing | updated **2026-06-05**; fuzzer for intent/extras surfaces |
| **AHA-Fuzz** (S2-Lab) | per repo README | intent fuzzing | **2025-12-02**; coverage-guided Android fuzzing lineage |
| **deeplinkfuzz** (cognis-digital) | `deeplinkfuzz manifest.xml` | deeplink surface | **2026-06-30**; enumerates and fuzzes exported deeplink schemes from the manifest |

```bash
# 1. Traffic capture on a rooted rig (no CA, no proxy, pinning irrelevant):
adb push ecapture /data/local/tmp/ && adb shell "su -c 'chmod +x /data/local/tmp/ecapture'"
adb shell "su -c '/data/local/tmp/ecapture tls -i wlan0'"   # plaintext of every TLS session

# 2. Dump the real DEX from a packed app after first launch:
frida-dexdump -U -f com.example.app                        # decrypted classes*.dex land in ./

# 3. Gadget injection when the device is NOT rooted:
objection patchapk -s base.apk                             # → base.objection.apk, install & attach

# 4. GUI flow at scale (LLM agent harness or plain flows):
maestro test flows/login.yaml                              # deterministic replays / agent actions
```

Treat the captured output the way you treat any proxy log: it contains live session plaintext — scope it, store it under the engagement tree, and keep it out of anything public.

## Research lanes (paper-grade, not tooling)

These are 2025-26 academic results worth knowing for methodology, with no maintained tool to install today:

- **WOOTdroid** (arXiv 2604.27830) — semantic reconstruction of Binder/WOOT syscalls (WDSys + WDBind): recovers IPC structure from kernel trace, by design resistant to anti-ptrace. Paper-grade; no public tooling.
- **Snapshot fuzzing** (TimeMachine / VMIGEN lineage) — snapshot the device/app state after login, then fuzz from restores: each run starts authenticated without re-doing the login flow, which multiplies effective iterations for gated surfaces.
- **LLM GUI agents** (GraphDroid, CovAgent, DroidAgent, ScenGen) — agent-driven exploration beats the ~30% coverage ceiling of scripted crawlers by goal-directed exploration. Maestro is the practical harness; the academics are the ceiling.

## Encrypted-envelope replay

Apps that wrap their API in a custom crypto envelope (see [flutter-aot-reversing.md](../../flutter-aot-reversing.md) for the canonical pattern) normally force a key-recovery detour. With plaintext already captured at the SSL boundary you can skip the keys: mutate at the plaintext layer (the pre-encryption JSON the app itself serialized), then re-inject at the app's serialization hook (a Frida `Interceptor` on the serializer entry point). The app re-encrypts and re-signs your mutation with its own key material — the server sees a well-formed envelope. This is a delivery mechanism for tamper tests, not a findings generator by itself: the finding is still what the mutated payload convinces the server to do.

## Play-Integrity relay (Quarkslab, Aug 2026)

For apps gating flows on Play Integrity, the red-team question is whether the backend actually binds verdict to nonce and session. The published relay pattern: a clean, unrooted device obtains genuine verdicts; the relay forwards them to the test rig, where a Frida chain-splice injects the verdict into the gated request. A server that accepts the relayed verdict without checking nonce freshness or session binding fails the control — and that server-side failure is the finding. Client-side verdict inspection alone proves nothing (see [android-dynamic-analysis.md](../../android-dynamic-analysis.md) — client-only integrity is always bypassable; verify server-side).

## MASVS map

Copy ids only from the sources below; per-test anchors live in [masvs-class-map.md](../../masvs-class-map.md) and [methodology.md](../../methodology.md).

- **MAS-NETWORK-PINNING** (MASTG-TEST-0230s · MASWE-0050) — eBPF capture proves pinning does not defend against an on-device observer: an interception that "failed" over proxy still yields full plaintext.
- **MAS-RESILIENCE-ROOT** (MASTG-TEST-0280s · MASWE-0100) — anti-debug/anti-ptrace defeated by kernel-side capture; `objection patchapk` for the non-root case.
- **MAS-RESILIENCE-INTEGRITY** (MASTG-TEST-0280s · MASWE-0100) — the attestation relay validates (or breaks) the server's verdict+nonce binding.
- **MAS-PLATFORM-IPC** (MASTG-TEST-0250s · MASWE-0060) — intent/deeplink fuzzing drives the reachability evidence for exported components.
- **MAS-CODE-SECRETS / MAS-STORAGE-LOCAL** (MASTG-TEST-0270s · MASWE-0071) — decrypted-in-memory content from frida-dexdump and captured session data.
- **MAS-AUTH-LOCAL** (MASTG-TEST-0017 · MASWE-0040) — post-login snapshot states as fuzzing entry points.

## Anti-Patterns

- Intercepting each target with its own Frida unpinning script when one ecapture rig covers the portfolio — the per-script maintenance cost is the failure mode, the capture quality is identical.
- Assuming eBPF capture is undetectable — a sophisticated RASP watches kernel tracing state too; test the rig against the target's detection before claiming coverage.
- Presenting WOOTdroid, VMIGEN, or the academic GUI agents as installable tooling — they are research lanes, and a methodology section, citing them as tools misleads the engagement.
- Pointing GUI agents or intent fuzzers at anything outside the authorized scope — they act at scale, and one misconfigured flow file reaches far past the target app.
- Reporting the attestation relay itself as the finding — the relay is test scaffolding; the finding is the server that fails to bind verdict to nonce.
- Treating captured session plaintext as inert evidence — it is live session data and belongs under engagement-data handling, not in shared scratch dirs.

## Cross-references

- [advanced-static-surfaces-2026.md](advanced-static-surfaces-2026.md) — the static counterpart: where these dynamic lanes get their targets.
- [android-dynamic-analysis.md](../../android-dynamic-analysis.md) — the device bring-up, objection recipes, and cross-stack pinning ladder this scenario builds on.
- [react-native-hermes.md](react-native-hermes.md) — JS-layer pinning that kernel capture sidesteps.
- [flutter-aot-reversing.md](../../flutter-aot-reversing.md) — the crypto-envelope pattern the replay section attacks.
- [frida-hooking.md](../../../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) — the Frida primitives behind dexdump, the replay splice, and the relay chain.
- [ltrace-strace.md](../../../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md) — the general eBPF/bpftrace tracing background.
- [masvs-class-map.md](../../masvs-class-map.md) — class-level completion contracts.
