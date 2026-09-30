# Marvin Timing Oracle (RSA-PKCS#1 v1.5)

## When this applies

- An RSA-PKCS#1 v1.5 decryption surface where responses look uniform (no error-text distinction) but processing time is measurable — the Bleichenbacher/ROBOT attack class with timing as the signal channel instead of the response body.
- Surfaces in scope that commonly expose it: TLS endpoints negotiating RSA key exchange; SAML `EncryptedAssertion` decryptors; JWE tokens with `alg=RSA1_5`; KMS/decrypt-style APIs; PHP applications calling `openssl_private_decrypt` with the default `OPENSSL_PKCS1_PADDING` — the CVE-2024-2408 lineage (CVSS 5.9; Marvin, disclosed by H. Kario 2023, extending ROBOT 2017).
- Trigger: "the server returns the same error for bad padding, so BB98 is impossible" — measure before believing it.
- Prerequisite context: read `scenarios/padding-oracle/pkcs1-v1.5-bleichenbacher.md` first; this file only swaps the oracle signal.

## Technique

BB98 is a multiplicative-plaintext oracle: re-encrypt a modified ciphertext `c' = c·s^e mod n` and learn whether the decrypted value falls inside the PKCS#1-conforming interval. ROBOT showed many stacks still expose the conforming/non-conforming distinction through error text or connection behavior. Marvin showed that even with byte-identical responses, conforming plaintexts take a measurably different amount of processing (the padding check itself, and follow-on parsing that only happens on success), so timing distributions separate enough to classify individual queries. The attacker sends millions of crafted ciphertexts and statistically classifies each; the big-interval BB98 narrowing then runs exactly as in the classic attack.

Whether a given stack leaks is testable in minutes with `tlsfuzzer`; whether it is exploitable depends on how far the distributions separate.

## Steps

### 1. Map the v1.5 surfaces

Enumerate where RSA PKCS#1 v1.5 *decryption* (not signing) happens: TLS cipher suites (`TLS_RSA_*`), SAML `EncryptedAssertion` handling, JWE `RSA1_5` (see `../../../../authentication/reference/scenarios/jwt/jwe-nested-token.md`), payment/HSM decrypt endpoints. TLS 1.3 has no RSA key exchange — check the legacy-suites fallback path.

### 2. Probe with tlsfuzzer

Run the `tlsfuzzer` ROBOT/Marvin test cases (`tests/tests_tls_rsa.py` Marvin variants) against the endpoint. They automate the conforming/non-conforming classification and report whether each behaved distinctly. For non-TLS surfaces, build the same two-class probe manually: known-conforming ciphertext vs known-garbage, many repetitions.

### 3. Establish timing discipline

- Thousands of samples per class before trusting a separation; warm-up runs first (JIT/connection setup pollutes early samples).
- Interleave classes rather than batching, so load drift hits both equally.
- Record per-query send/receive timestamps server-side if you can (authorized instrumentation beats network RTT noise); otherwise co-locate the client and subtract baseline RTT.
- Classify with a difference-of-means (or Mann-Whitney) test on per-query medians, not raw means.

### 4. Run BB98 with the timing oracle wired in

Take the flow from `scenarios/padding-oracle/pkcs1-v1.5-bleichenbacher.md` and replace its "did the server error?" predicate with the timing classifier from step 3. Expect the query volume to be in the millions (Marvin-class attacks) — keep it within pre-agreed rate limits and RoE windows (see pitfalls).

### 5. Report

Deliverable: which surfaces leaked, the measured separation (samples, medians, p-value), the recovered plaintext for an authorized test token or session, and the fix list — migrate to OAEP (encryption) / PSS (signatures); where v1.5 must remain, verify the mitigation story: the OpenSSL 3.2+ lineage introduced `rsa_pkcs1_implicit_rejection` (a constant-time decoy path, present in backports; PHP fixed releases 8.1.29/8.2.20/8.3.8+ carry it). Version-check the deployed stack against those releases.

## Verifying success

- `tlsfuzzer` reports a consistent timing distinction (or clean negative — also a finding).
- Recovered plaintext re-encrypts/round-trips against the target's public key (the re-encryption check from `cryptography-principles.md`).
- The mitigation matrix matches the deployed library versions.

## Common pitfalls

- **Volume vs RoE.** Millions of queries over hours is loud; it can trip rate limiters, WAFs, or availability budgets. Pre-agree rates and monitoring with the client; batch across windows if needed.
- **Jitter swallowing the signal.** Container cold starts, GC pauses, and load balancer rotation all inject one-off outliers — use per-query medians across retries, not single samples.
- **Implicit rejection ≠ constant time.** `rsa_pkcs1_implicit_rejection` adds a decoy computation so the timing flattens for non-conforming inputs; a truly constant-time implementation and an implicit-rejection one are different fixes with different residual risks. Classify which one the target has.
- **Testing only TLS.** The SAML/JWE decryptor in the app tier is frequently the real exposure while the TLS front is modern.
- **Confusing decrypt with sign.** v1.5 *signing* issues are the `scenarios/signature-forgery/rsa-pkcs1.5-bleichenbacher.md` family (e=3 cube-root forgeries) — different attack, different fix.

## Tools

- `tlsfuzzer` (ROBOT/Marvin test cases) — the reference harness; run it before hand-rolling probes.
- `tls-attacker` as a second implementation for cross-checking classifications.
- `openssl s_client` for manual cipher-suite negotiation checks.
- Python ``statistics``/``scipy.stats`` for the classification test.
