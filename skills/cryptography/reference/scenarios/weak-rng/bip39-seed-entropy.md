# BIP-39 Seed-Entropy Failure (On-Device Wallet Keygen)

## When this applies

- The target generates BIP-39 mnemonics (12/24 words) **on-device** and claims the seed is safe: hardware wallet firmware, embedded keygen modules, HSMs, browser/mobile wallets with "seed generated on device" marketing.
- Firmware has an RNG **fallback path** — hardware TRNG with a software PRNG behind a compile-time or runtime guard.
- Build configuration guards keyed on macro **existence** (`#ifndef HAVE_TRNG`) rather than value (`#if !HAVE_TRNG`).
- Entropy reads wrapped in silent exception handlers (`try/except: pass`), truncated reseeds, or seed material mixed **at boot** rather than at generation time.
- RNG state seeded from device-identifiable or time-based material: chip UID, SysTick, RTC registers, build constants, public seeds.
- Trigger keywords: `BIP-39`, mnemonic, seed words, TRNG, `rng_get`, dice-roll entropy, `entropy_pool`.

The core fact driving this whole scenario: **SHA-256, PBKDF2, and BIP-32 derivation add no entropy.** The 128/256 bits advertised by a 12/24-word mnemonic are bounded above by the entropy of the generator's initial state. If that state is 40 bits, the wallet is a 40-bit wallet regardless of how many words the user writes down.

## Technique

Three root-cause patterns, all demonstrated by the Coldcard incident of July 2026 (see case study below). They generalize to any embedded keygen:

1. **Link-time substitution.** A board config defines `MICROPY_HW_ENABLE_RNG (0)` intending to disable a hardware RNG wrapper. But in MicroPython's `ports/stm32/rng.c`, a value of `0` compiles `rng_get()` to the software Yasmarang PRNG — it does not compile the call out. Downstream guards check `#ifndef MICROPY_HW_ENABLE_RNG` → `#error "get a HW TRNG plz"` — macro **existence**, not value — so the build never fails. Both implementations share the same C signature, so the linker silently binds keygen to the software PRNG on every build. The hardware TRNG remains in the binary, active and healthy, for other callers.

2. **Thin seeding.** The software fallback's state starts as `pad = UID_low32 ^ SysTick->VAL` — one 32-bit word. RTC registers that should have diversified this were always 0 because `MICROPY_HW_ENABLE_RTC (0)` never started the clock. A second generator instance seeding the XOR mixer starts from public source constants (`pad=0x0a8ce26f, n=69, d=233`). Result: ≤2^32 starting states per device class. The final `sha256s()` over the PRNG output disguises the deficit statistically but adds nothing.

3. **Truncated reseed with swallowed failure.** Newer models read 40 bytes from two secure elements at boot, double-hash them, keep **4 bytes**, and overwrite one word of the mixer state. If the reads fail, `try/except: pass` continues silently. Effective entropy reaches ~72 bits instead of the nominal 128/256.

## Steps

### 1. Map the binary's actual entropy binding

Before trusting any RNG claim, verify which generator the shipped binary really calls for keygen — source review alone missed the Coldcard bug because it lived at a submodule boundary.

- Obtain the exact firmware image the target devices run (vendor release, not just source repo — build flags diverge).
- Walk the keygen call chain: seed request → bytes source → PRNG → entropy file.
- `nm -C firmware.elf | grep -i rng` and inspect the link map: **which `rng_get` symbol did the linker bind?** Multiple definitions with identical signatures across submodules is the smoking gun.
- Grep sources for `#if defined(X)` vs `#if X` semantics — the first checks existence, the second value. The Coldcard bug survives a grep for "RNG" in every crypto file because the flag looked correct.
- Flag: silent `except: pass` entropy paths, reseeds truncated to a few bytes, entropy mixed at boot rather than at seed generation, assertions like `assert len(set(seed)) > 4` (a PRNG passes this trivially).

### 2. Bound the candidate space

Enumerate everything the PRNG state could depend on:

- Device-unique material: chip UID (32/64/96 bits), serial, efuses. Known-UID devices shrink the space dramatically (Coldcard Mk3: ~2^16.3 with UID known vs 2^32 blind).
- Time-of-boot material: SysTick at seeding (~80k values on STM32-class chips), RTC subseconds — but verify the RTC was actually running (`MICROPY_HW_ENABLE_RTC (0)` class bugs leave registers at 0).
- Constants from public source: package-initialization values, public seeds.
- **Skip counts**: how many PRNG calls happened before the seed was drawn. First-session skips are often near-deterministic (Coldcard first-session: `chip_skip=3103`, `mixer_skip≈3161±8`); later sessions vary by 0–30.
- Multiply the possibilities: total space ≈ product of unknowns. Anything ≤2^80 is sweepable today; ≤2^40 is cheap (<$1k GPU rental).

### 3. Enumerate → derive → compare (offline sweep)

Purely offline — no physical access to the target device is needed, only the public chain and a funded-address set:

```python
# pip install mnemonic bip_utils pybloom-live
import hashlib
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from pybloom_live import BloomFilter

# Bloom filter of every funded address on-chain (built from UTXO/electrum server export)
funded = BloomFilter(capacity=80_000_000, error_rate=0.001)
# funded.add(addr) for each funded address

mnem = Mnemonic("english")

def candidate_to_addresses(pad, chip_skip, mixer_skip):
    state = yasmarang_state(pad, n=0, d=0)          # model of the fallback PRNG
    advance(state, chip_skip)                        # replay boot-time calls
    mixer = yasmarang_state(0x0a8ce26f, 69, 233)     # public constants
    advance(mixer, mixer_skip)
    raw = b"".join(next_word(state) ^ next_word(mixer) for _ in range(8))  # 32 bytes
    entropy = hashlib.sha256(raw).digest()           # deterministic — adds nothing
    words = mnem.to_mnemonic(entropy)
    seed = Bip39SeedGenerator(words).Generate("")
    root = Bip44.FromSeed(seed) \
        .Purpose()   .Coin()   .Account(0) \
        .Change(Bip44Changes.CHAIN_EXT) .AddressIndex(0)
    return [root.PublicKey().ToAddress()]            # extend: BIP84/49/44, index 0..N
```

For every candidate `(pad, chip_skip, mixer_skip)`:

1. Drive the modeled PRNG forward by the skip counts.
2. Produce 16/32 bytes, SHA-256 → BIP-39 entropy → mnemonic.
3. PBKDF2-HMAC-SHA512, 2048 rounds, empty or known passphrase → BIP-32 master key.
4. Derive the first N receive addresses on BIP-84/44/49 paths.
5. Bloom-filter membership test against funded addresses. A hit = the private key.

One pass finds **all** vulnerable wallets simultaneously. Throughput is ~0.9 ms/candidate (dominated by PBKDF2); the full blind 2^32 Mk3 space is 1–2 days on two rented GPUs. Speed up with PBKDF2 on GPU or multiprocessing before spending cycles on address derivation — hash first, derive only on entropy-candidate hits when a faster pre-filter exists.

### 4. Cold-boot duplicate test (cheap black-box proof)

Needs only **one** test device and no sweep infrastructure — ideal for an engagement where you can re-generate seeds on borrowed hardware:

- Power-cycle the device repeatedly; generate a fresh seed after each cold boot.
- With a ~2^16-state space per device, the birthday bound says duplicates appear after ~2^8 generations (256 cold boots → ~50% chance of at least one collision).
- A single repeated mnemonic across cold boots proves the state space is tiny; the PoC repo below observed near-immediate duplicates on affected Mk3 units.

### 5. Model reproduction

The definitive lab proof:

- Reimplement the suspected PRNG offline (Yasmarang is ~50 lines; most fallback PRNGs are).
- Generate seeds on a test device through a controlled sequence of reboots.
- Match each generated mnemonic against your model's predictions across the candidate space. Exact hits confirm the root cause and quantify the effective entropy.

## Verifying success

- A derived address from an enumerated candidate matches a known funded address — definitive.
- Duplicate mnemonics appear across cold boots on the same device.
- The offline model predicts test-device seeds exactly, given the right `(seed material, skip count)`.

## Common pitfalls

- **SP 800-90B / AIS-31 health tests miss this class.** Those validate the entropy **source**; Coldcard's TRNG was healthy and certified. The break was in the **path** — which generator keygen actually reached.
- **Statistical tests on the mnemonics.** SHA-256 over the PRNG output whitewashes distribution defects. Chi-square/NIST-style tests on generated words will pass on a 40-bit wallet.
- **Trusting word count.** 24 words says nothing about entropy — the space actually sampled can be 2^40.
- **Seed-length checks.** `len(set(seed)) > 4` or byte-length assertions pass for any PRNG; they measure shape, not uncertainty.
- **Re-running keygen on a patched firmware fixes nothing.** The weak seed stays weak until funds move to a fresh seed on patched firmware.
- **Assuming physical access is required.** This class is exploitable fully offline from public chain data; a device in a bank vault is not safe.
- **Foregoing the dice-roll check.** 50 dice rolls (≥128 bits) added to the seed, or a strong unique BIP-39 passphrase, would have made even the broken generator safe — check whether the target exposes user-supplied entropy and whether it's actually mixed in.

## Build-audit checklist (prevention)

For clients shipping embedded keygen, the audit deliverables that catch this class:

- **CI link-map verification**: after every build, `nm`/link-map assert that keygen call chains bind the intended TRNG symbol; CI fails on fallback-RNG symbols present in the linked keygen objects.
- **Fail closed on macro values**, not existence: `#if !defined(HAVE_TRNG) || !HAVE_TRNG` → `#error`.
- **CI symbol poisoning**: compile keygen objects with `-Wl,--defsym=rng_get=...` tricks or ship a poisoned fallback that panics, so a silent swap cannot link.
- **Reproducible builds** so the reviewed source is the shipped binary.
- **Lint rules for silent excepts** around entropy reads, truncated reseeds, and boot-time-only mixing.
- **Hardware RNG read counters**: count physical TRNG reads per seed request (fixed Coldcard Mk4 5.6.0 emits 8 STM32 TRNG reads for a 32-byte seed, observable on-tester).
- Deployed mitigations: user dice-roll entropy ≥128 bits; strong unique BIP-39 passphrase.

## Case study: Coldcard, July 2026

- **What happened**: seed generation on Mk2/Mk3 (fw 4.0.1–4.1.9) and Mk4/Mk5/Q (pre-5.6.0/1.5.0Q) linked MicroPython's Yasmarang software PRNG instead of the STM32 hardware TRNG, via the `MICROPY_HW_ENABLE_RNG (0)` / `#ifndef`-guard chain described in Technique. Regression shipped 2021-03-17 (v4.0.0); the trading suffix -Edge builds fixed at 6.6.0X/QX.
- **Effective entropy**: Mk2/Mk3 ≈ 40 bits (2^32 blind; ~2^16.3 with known device UID); Mk4/Mk5/Q ≈ 72 bits. No CVE assigned.
- **Exploitation**: fully offline; first wave swept 594 BTC (~$38M) from 501 wallets in 46 minutes on 2026-07-30; total tracked losses ~$116–130M across 15+ copycat attackers. One drained device had sat offline in a bank safe-deposit box since before the regression.
- **Users saved by**: ≥50 fair dice rolls added to the seed, or a strong unique BIP-39 passphrase.
- **What Coinkite's post-mortems emphasize**: models and humans both missed it — reviews confirmed the TRNG was present and of good quality rather than that keygen used it; the guard boundary lived between two submodules outside the crypto logic reviews focused on.

Sources: https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/ · https://blog.coinkite.com/adding-to-public-record/ · https://github.com/DK27ss/ColdCard-38M-PoC · https://santala-research.com/en/research/coldcard-entropy-flaw.html · https://www.steven-geller.com/2026-08-02-coldcard-had-two-hardware-rngs-its-seeds-used-neither.html · https://www.galaxy.com/insights/research/your-keys-not-your-coins-coldcard-wallets-hacked-for-130m-and-counting · https://www.trmlabs.com/resources/blog/the-largest-hardware-wallet-exploit-of-2026-inside-the-usd-116-million-coldcard-hack · https://cc-vuln.org/how-it-broke/entropy/ · https://coldcard.com/security/status

## Tools

- `mnemonic` (Bitcoin python-mnemonic) — BIP-39 entropy ↔ words.
- `bip_utils` — BIP-32/39/44/49/84 derivation chains.
- `pybloom_live` — bloom filter for funded-address membership.
- `nm`, `objdump`, link maps (`-Wl,-Map=`) — verify which RNG symbol the binary binds.
- `unicorn` / QEMU — emulate firmware PRNG code paths without hardware.
- Siblings: `lcg-state-recovery.md` (LCG output prediction), `mt19937-state-recovery.md` (MT19937 output prediction) — this scenario covers the adjacent failure class: thin initial **state entropy at keygen** rather than observable output prediction. [wallet-generator-prng-vintage.md](wallet-generator-prng-vintage.md) covers the software-generator side of the same class.
