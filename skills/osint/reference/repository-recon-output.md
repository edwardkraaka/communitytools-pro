# Repository Recon — Output & Severity

Companion to [repository-recon.md](repository-recon.md): the findings output JSON schema, the severity guide, and reference links. Recon phases, dorks, secret patterns, and credential-validation probes live there.

## Output Format

`{OUTPUT_DIR}/recon/repositories.json`:

```json
{
  "asset_type": "repositories",
  "target_org": "example",
  "platforms": ["github", "gitlab"],
  "repositories": [
    {
      "name": "example/backend-api",
      "url": "https://github.com/example/backend-api",
      "platform": "github",
      "language": "Python",
      "last_updated": "2024-11-01",
      "risk_level": "critical",
      "findings": [
        {"type": "secret", "description": "AWS Access Key ID in commit a1b2c3d",
         "file": "config/settings.py", "commit": "a1b2c3d",
         "detector": "trufflehog", "verified": true,
         "verified_live": true, "validation": "sts get-caller-identity -> arn:aws:iam::1234:root (read-only, single-shot)",
         "handed_off": true}
      ]
    }
  ],
  "employee_accounts": [
    {"platform": "github", "username": "jsmith-example",
     "repos_scanned": 12, "findings": []}
  ],
  "stats": {"total_repos": 34, "repos_with_findings": 5,
            "total_secrets_found": 8, "verified_secrets": 3}
}
```

---

## Severity Guide

| Finding | Severity |
|---------|----------|
| Cloud key (AWS/GCP/Azure) **verified live** (identity proof captured) | CRITICAL |
| DB connection string **verified live** (connect + `current_user()` proof) | CRITICAL |
| Private SSH/TLS key **verified live** (auth-mode login on in-scope host) | CRITICAL |
| API key for payment/auth **verified live** (`/me` proof) | HIGH–CRITICAL |
| Verified credential granting admin/service-role identity | CRITICAL |
| Unverified cloud key / DB string / private key (found, validation failed or not yet run) | MEDIUM — a lead, not a confirmed finding |
| API key for payment/auth (Stripe, Twilio, …), unverified | HIGH |
| Internal hostname/IP + service version | MEDIUM |
| Hardcoded staging/dev credentials | MEDIUM |
| Tech stack / dependency versions | LOW |
| Internal endpoint paths | LOW / INFO |

Severity on the **root cause** (`principles.md`): an unverified secret is scored as exposure-of-a-possible-credential; the verified-live rung is what proves access. Never score Critical on an unverified candidate.

---

## References

- MITRE ATT&CK: T1593.003, T1552.001, T1213.003
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- Gitleaks: https://github.com/gitleaks/gitleaks
- Gitrob: https://github.com/michenriksen/gitrob
- Search: grep.app, sourcegraph.com, github.com/search
