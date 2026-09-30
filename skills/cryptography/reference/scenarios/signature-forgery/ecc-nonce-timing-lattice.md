# ECC Nonce-Timing Lattice Attack (Minerva Class)

## When this applies

- You can collect many ECDSA/SM2 signatures from a target signer **and** measure the signing time — HSM signing APIs, mTLS client-certificate handshakes, JWT ES256 endpoints, TPM attestation, any signing oracle with a clock on the response.
- Or a version inventory hits the known-vulnerable family: Minerva (CRoCS 2019, smartcards), LadderLeak (2020, Montgomery-ladder implementations leaking <1 bit of the nonce MSB, OpenSSL/RELIC lineage), GnuTLS CVE-2024-28834 (reproducible-flag nonce-size step, CVSS 5.3), python-ecdsa CVE-2024-23342 (≤0.18.0, CVSS 7.4), OpenSSL CVE-2025-27587 (PowerPC, `EVP_DigestSign`, CVSS 5.3 — disputed: OpenSSL's documented threat model excludes same-host side channels), OpenSSL CVE-2025-9231 (SM2, 64-bit ARM, CVSS 6.5).
- This is the statistical member of the nonce-leak family: exact nonce reuse is `scenarios/signature-forgery/ecdsa-nonce-reuse.md` (2 signatures, algebra), trace-based operand leakage is `scenarios/signature-forgery/gcd-transcript-operand-recovery.md` — this one needs hundreds-to-tens-of-thousands of (signature, timing) pairs.

## Technique

Elliptic-curve scalar multiplication runs a ladder whose iteration count (and sometimes per-iteration work) depends on the scalar's bit length. The ECDSA nonce `k` is the scalar: a `k` with a shorter bit length produces a measurably faster signature. Each timing observation therefore bounds `k` from above — "this `k` is < 2^(t-bits-ε)" for a per-signature threshold. Those per-signature upper bounds on `k`, combined with the public relation `s·k ≡ z + r·d (mod n)`, form a Hidden Number Problem instance. LLL/BKZ on the HNP lattice recovers the private key `d` once enough bounded nonces accumulate. `<1 bit` of leakage per signature (LadderLeak class) still suffices with enough samples; the plaintext-timing correlation does the rest.

## Steps

### 1. Inventory the signer

Identify library + version. Run CVE lookups against each family member found (`python3 tools/nvd-lookup.py CVE-2024-28834` etc. per CLAUDE.md discipline). If the stack is not in the CVE list, the class may still be present — Minerva-style leakage was found in implementations with no CVE; timing characterization (step 3) decides.

### 2. Collect signatures and timings

- High-resolution timestamps: server-side instrumentation if authorized (best), else co-located client with RTT baseline subtracted.
- Batch and interleave; steady-state warm-up first; record ambient load.
- Repeated signing of the *same* message is ideal when legal (isolates timing from message variation) — many oracles allow it (attestation, session tokens).

### 3. Characterize and bucket

Plot signature-time distributions; look for structure correlated with `r`-derived expectations — for HNP you need, per signature, a probabilistic bound on `bitlen(k)`. Buckets like "top-decile-fast ⇒ `k` < 2^252 with high confidence" (for a 256-bit curve) each contribute one HNP constraint. One clean bit of separation per signature is a strong attack; sub-bit separations need more samples (the LadderLeak regime).

### 4. Solve HNP with LLL

```python
# sketch: HNP with per-signature nonce-length bounds (Minerva/LadderLeak form)
# sigs: [(r_i, s_i, bound_i)] where bound_i is the hypothesized upper bound on k_i
# z_i = leftmost bitlen(n) bits of H(m_i) per ECDSA (see gotchas)
n = curve_order
M = 2 ** (bitlen(n) - 1)  # scale factor for the bounds (tune per leak size)
rows = []
for r, s, z, bound in sigs:
    a_i = (-r * pow(s, -1, n)) % n      # s^-1 combines k and d terms
    b_i = (z * pow(s, -1, n)) % n
    # d = a_i*k_i + b_i with k_i < bound  -> bound each nonce's MSBs
# build the standard HNP lattice (Boneh-Venkatesan) with per-row k-bounds,
# run LLL/BKZ (fpylll), take a short vector -> candidate d
```

Verify the candidate `d` immediately: it must reproduce every collected `r`, `s` pair exactly.

### 5. Verify and report

A recovered `d` that generates a matching test signature (on an authorized test message) closes the finding. Report: the leakage source (ladder step count vs per-bit work), samples needed, the classification statistics, affected surfaces, and remediation (constant-time/scalar-blinded ladder, upgrade to fixed releases, disable reproducible-nonce flags).

## Verifying success

- Candidate `d` regenerates all collected `(r, s)` pairs.
- The timing model reproduces the observed distribution on held-out signatures.
- Deployed versions match the CVE matrix from step 1.

## Common pitfalls

- **Sample count.** Dozens of signatures rarely suffice; hundreds for clean leakage, tens of thousands for sub-bit. Design collection windows accordingly.
- **Clock resolution vs network.** Timing the network path instead of the crypto: on remote targets the crypto's ~microsecond signal sits under ~millisecond RTT variance — needs server-side timing, enormous batching, or co-location.
- **Hash truncation.** `z` is the leftmost `bitlen(n)` bits of the hash, and with the curve's `n ≈ p` but not equal, using `int(h)` directly corrupts the lattice (see `cryptography-principles.md` gotcha).
- **Low-S normalization and signature malleability.** If the stack normalizes `s`, account for it when forming the HNP equations (the relation holds with either sign, but consistency matters).
- **Disputed threat models.** CVE-2025-27587-class entries where the maintainer's documented threat model excludes local attackers — report as "requires same-host measurement" rather than remotely exploitable.
- **`k` MSB vs LSB bounds.** Some leaks bound the top bits (this lattice), others the bottom bits (different HNP orientation) — verify which before building rows.

## Tools

- `fpylll` (LLL/BKZ) or SageMath for the HNP lattice; `gmpy2` for the modular arithmetic.
- Vulnerable `python-ecdsa` (≤0.18.0) as a lab reference signer to validate the harness end-to-end before touching the target.
- `tools/nvd-lookup.py` for the version-matrix discipline.
- JWT-side nonce issues: `../../../../authentication/reference/scenarios/jwt/ecdsa-nonce-reuse.md`.
- Lattice background: `scenarios/lattice/lll-basis-reduction.md`.
