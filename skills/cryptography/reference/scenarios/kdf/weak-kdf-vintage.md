# Weak-KDF Vintage Artifacts

## When this applies

- An authorized offline artifact is in scope and the question is how much protection its key derivation actually provides: password-manager vaults (LastPass-class), Bitcoin Core `wallet.dat` files, exported key stores, encrypted backups with legacy derivation.
- The generator-side sibling question — passwords *created* by a weak PRNG (RoboForm pre-2015 time-seeded class) — is `scenarios/weak-rng/wallet-generator-prng-vintage.md`; this file covers the derivation side: strong key material behind a KDF whose work factor is decades out of date.
- Trigger artifacts: vault metadata showing four- or five-digit PBKDF2 iteration counts; `wallet.dat` from any Bitcoin Core era; any `EVP_BytesToKey`-derived container.

## Technique

A KDF translates a low-entropy secret (password) into a key with a cost function: iterations × hash. Vintage failures make that cost near-zero:

1. **Iteration-count vintage.** Password-manager vaults from the PBKDF2 defaults of their era commonly used tens of thousands of rounds or fewer; current guidance (OWASP-class) puts PBKDF2-HMAC-SHA256 at hundreds of thousands of rounds, with Argon2id preferred. A vault cracked at a GPU rate of 10^5–10^6+ candidate passwords/second class turns "strong password" into "eventually brute-forceable" — the audit read is the ratio between the client's actual password entropy and the achievable guess rate.
2. **Single-iteration derivation.** Bitcoin Core's `wallet.dat` encrypts with AES-256-CBC keyed via OpenSSL `EVP_BytesToKey(MD5, 1 iteration)` — the master key is derived from the wallet passphrase in one MD5 pass. Extract with `bitcoin2john.py`, attack with hashcat mode 11300.
3. **Lifecycle gap.** Upgrading the KDF does not re-encrypt history: Vaultwarden's CVE-2024-39925 (organization-key rotation leaving server-side encrypted data decryptable, CVSS 6.5) class shows old ciphertext staying weak after the fix. An audit states when each blob was encrypted and under which parameters.

The audit deliverable: derivation parameters, cost model, and a demonstrated crack of a known-password lab fixture.

## Steps

### 1. Read the derivation parameters off the artifact

Vault metadata exposes the KDF (type, hash, iterations, salt). `wallet.dat` version bytes + the OpenSSL `EVP_BytesToKey` structure. Document parameters per artifact — clients run mixed eras of vaults from merges and migrations.

### 2. Build the cost model

`time_to_crack ≈ keyspace_password / rate(capabilities × iterations⁻¹)`. Benchmark the actual hash mode on your hardware (or a cited public benchmark) rather than quoting numbers — GPU-era rates make five-digit iteration counts a rounding error. State the model's hardware assumption in the report.

### 3. Reproduce on a lab fixture

Create a test artifact with the same parameters and a known password; extract and crack it. For `wallet.dat`: `bitcoin2john.py wallet.dat > hash.txt` then `hashcat -m 11300 hash.txt` (see `../../../../authentication/reference/scenarios/password-attacks/hash-cracking.md` for mode-specific mechanics; `btcrecover` narrows the password space with per-client patterns — partial known strings, keyboard walks). The fixture reproduces before touching client artifacts.

### 4. Audit the client artifact (within scope)

Run the same extraction against the authorized artifact; report the parameters and cost model without necessarily completing a full crack — a demonstrated fixture crack plus the client artifact's parameters is the finding. If a crack is in scope, pre-agree the password source (client-provided seed list, their policy on real passwords).

### 5. Report with remediation

- Parameter table: artifact → KDF → iterations → modeled crack time.
- Migration: ≥600k PBKDF2-HMAC-SHA256 rounds or Argon2id (memory-hard, GPU-resistant) for new material.
- Lifecycle: re-encrypt or retire legacy blobs (a KDF bump alone leaves old ciphertext at old strength); key-rotation hygiene gaps of the CVE-2024-39925 class.
- Principle: the KDF cannot rescue weak generation — tie back to `scenarios/weak-rng/bip39-seed-entropy.md` and `scenarios/weak-rng/wallet-generator-prng-vintage.md` if the client's exposure spans both layers.

## Verifying success

- The fixture crack succeeds with its known password — end-to-end toolchain works.
- Benchmarked rate matches the model's assumption (same hardware/mode).
- Artifact parameters match the eras claimed by the client (e.g., an iteration count consistent with the vault's creation year — mismatches indicate undocumented migrations).

## Common pitfalls

- **Era-mixing.** Assuming one iteration count (or one KDF) across all vaults; audit reads parameters per artifact.
- **Salt handling.** A missing or reused salt enables precomputation (rainbow-table class); its presence/absence changes the cost model class entirely.
- **Asserting crackability without a model.** "MD5 is weak" is not a finding; "1 iteration ⇒ rate X ⇒ keyspace Y ⇒ time Z" is.
- **Live-system drift.** This scenario is offline-artifact analysis: pulling a live vault requires change-control, and cracking against production authentication endpoints is the authentication skill's password-attacks lane (stay here for captured artifacts).
- **Believing upgrades are retroactive.** Post-upgrade audits must still check what was encrypted when; the lifecycle gap is the recurring miss.

## Tools

- `hashcat` (mode 11300 for `wallet.dat`, plus the vault-specific modes), `john` (updated jumbo modes for PBKDF2 vaults).
- `btcrecover` for password-space narrowing on Bitcoin Core wallets.
- `bitcoin2john.py` for `wallet.dat` extraction.
- Container-attack workflow context: `../../../../authentication/reference/scenarios/password-attacks/encrypted-container-cracking.md`.
