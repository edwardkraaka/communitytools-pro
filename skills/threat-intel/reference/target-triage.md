## Synthesis: threat-intel-first decision procedure

**Standing ingestion (automation hooks per Section 1):**
- Daily 02:00 UTC job: pull KEV mirror diff, PoC-in-GitHub year-JSON diff, nuclei-templates `git pull`, SlowMist Hacked + rekt leaderboard check, vendor PSIRT RSS.
- Hourly: `api.github.com/advisories?updated_since=` filtered to npm/PyPI + wallet/seed/web3 keywords; NVD `lastModStartDate` enrichment for new KEV entries.
- Event-triggered deep dives: any new RCA in 0days-in-the-wild; any crypto incident ≥$3M; any new exploit campaign name from Sonatype/Cyfirma.

**Per-target decision procedure (before any generic scanning):**
1. **ORG FINGERPRINT** — domains, subdomains, ASN/cloud ranges, JS bundle inventory (hash and store every bundle — front-end compromise detection), exchange/custody stack identification (Safe? MPC vendor? which custody integration), on-chain footprint (proxy admins, verifier sets, role holders, timelock presence).
2. **STACK VERSION MATCH** — map every fingerprinted component against: current KEV, PoC-in-GitHub hits, nuclei-templates coverage, GitHub/osv advisories for its dependencies. Output: ranked candidate list of known-exploit exposure.
2. **KNOWN-EXPLOIT PATTERN MATCH** — for each candidate, check the public-surface detection signature (endpoint path, version banner, Host-header behavior, admin-port exposure); run ONLY the safe verification probe within written scope; record version-pinned evidence.
4. **LEAKED-CREDENTIAL / PRECURSOR SURFACE** — grep target JS + source maps for secrets/endpoints; check npm/PyPI for typosquats of the target's published packages and its dependencies; check exchange org's job posts/BPO footprint for support-role data access; on-chain: single-verifier bridges, retained admin roles, absent timelocks (top-10 precursor list).
5. **HYPOTHESIS LIST** — convert all of the above into ranked, falsifiable hypotheses (auth-flow bypass > access control > logic > deserialization > memory), each with expected evidence and a safe probe. Only now begin active testing, hypothesis-first; generic scanning last, purely for coverage gaps.
6. **REPORT** — every finding: version-pinned artifact, reproducible PoC, precursor class mapped to a real 2024–2026 incident analog, remediation tied to the observed control failure.

**Deep-dive triggers:** target uses Safe/multisig custody → signer-workflow and simulation review; target is an SDK publisher → publish-integrity review (Injective analog); target runs Langflow/Next.js/k8s ingress → probe set; target has any Exchange/SharePoint/SAP edge → KEV same-day check; new ≥$25M crypto incident with shared vendor/stack → variant sweep of all clients using that component within 72h.

**Currency rule:** the intel base is only as current as its polling; if any daily job fails twice, block testing of the affected vendor class until the feed is restored — testing from a stale knowledge base produces false "not vulnerable" conclusions.
