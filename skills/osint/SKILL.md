---
name: osint
description: Open-source intelligence gathering - company repository enumeration, secret scanning with live-credential validation (read-only identity probes, in-scope access proofs), git history analysis, employee footprint, and code exposure discovery. Verified-live credentials are handed off to the engagement's active phases.
---

# OSINT

Intelligence gathering (passive-first, active-capable) focused on code repositories, developer footprints, and exposed secrets across public platforms. Output feeds the engagement's active phases — OSINT is never a passive-only cap; engagement RoE defaults to active testing.

**A discovered secret is under-reported if it stops at "found"** (`principles.md` "Exploitation depth" — the same ladder, OSINT rung): **detect → verify live → prove access → hand off**. A key that might work is a Medium; a key confirmed live with an identity proof is a Critical, and a validated credential handed to the executors converts OSINT into authenticated attack surface. `roe.post_exploitation` (default true) authorizes the verification rungs.

## Phases

### 1. Organization Discovery
- Enumerate GitHub/GitLab/Bitbucket orgs for target company name variants
- Find employee personal accounts linked to the target org
- Identify archived, forked, and deleted repositories

### 2. Repository Analysis
- Map all repos: tech stack, languages, CI/CD, dependencies
- Identify internal hostnames, IPs, endpoints, environment names
- Check for `.env`, config files, secrets in current code

### 3. Secret & Credential Scanning
- Scan current code with `gitleaks` / `trufflehog`
- Scan full git history (secrets removed in commits are still accessible)
- Search with targeted dorks (see `reference/repository-recon.md`)

### 4. Credential Validation (the actionable rung)
- Re-run trufflehog with `--only-verified` to separate live secrets from regex noise
- Verify each candidate against the **issuing provider's identity endpoint**, read-only, single-shot (`reference/repository-recon.md` Phase 5) — an unverified secret is a lead, a verified one is a finding
- Where a verified credential maps to an **in-scope** asset (DB connection string, API key on the client's own service): attempt the authenticated access proof — identity call first (`/me`, `current_user`), bounded enumeration per engagement RoE, never a mass dump
- Record validity state + validation evidence per finding; redact secret values in the report
- **Hand off**: every validated credential goes into the engagement credential pool (`session-memory.md` Access & Credentials) so executors drive the authenticated attack classes — the point of the phase

### 5. Code Intelligence
- Extract API endpoints, auth patterns, internal service names
- Review Dockerfiles, CI configs, IaC for infra details
- Check dependency files for version-specific CVE candidates

## Output

```
data/reconnaissance/repositories.json   # Repo inventory + findings (each secret carries verified_live + validation evidence)
reports/reconnaissance_report.md        # OSINT section appended
raw/osint/                              # Raw tool outputs
session-memory.md (Access & Credentials)  # Validated creds handed to the engagement
```

## Tools

`trufflehog`, `gitleaks`, `gitrob`, GitHub/GitLab search, `gh` CLI, `git log`

## Rules

1. Passive discovery first (search APIs, public pages) before any cloning — *ordering*, not a cap; active follow-up (cloning, git-history scanning, authorized probing) proceeds under engagement RoE, which defaults to active testing
2. Scan git history — deleted secrets are still in commit objects
3. Check employee personal accounts, not just org accounts
4. Document AND VALIDATE every discovered credential — found ≠ finding; verify it live (Phase 4) before scoring it Critical. Validation calls: identity/whoami endpoints only, read-only, single-shot — never spraying, never data access beyond a bounded proof
5. Verification is scoped: read-only identity checks against the issuing provider are always fine; *using* a credential to access data is only for in-scope assets under engagement RoE. A third party's key found in the client's repo gets reported, not used
6. Redact secret values in every report/artifact; store raw values only in the engagement dir
7. Report a confirmed live credential to the client immediately (house rule: report unexpected access/data exposure immediately) — a live key is an incident, not just a pentest finding
8. All output saved to `{OUTPUT_DIR}/` per CLAUDE.md directory structure

## Reference

- `reference/repository-recon.md` - Dorks, tool commands, secret patterns, credential-validation probes, workflow
