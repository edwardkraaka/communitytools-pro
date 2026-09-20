# Repository Reconnaissance Reference

Public repos regularly expose API keys, credentials, internal infrastructure, and architecture. Git history amplifies leaks — secrets "deleted" in a commit remain accessible until the repo is force-pushed/rewritten.

**MITRE ATT&CK**: T1593.003 (Code Repositories), T1552.001 (Credentials in Files)

---

## Phase 1: Org & Repo Discovery

```bash
# All public repos in an org
gh repo list <org-name> --limit 200 --json name,description,updatedAt,primaryLanguage
gh search repos --owner <org-name>

# API code search by org (auth)
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/search/code?q=org:TARGET+filename:.env"
```

**Org name variants**: `company-name`, `companyname`, `company_name`, `company-eng`, `company-dev`, `company-security`, brand/product/codenames.

**Employees**:
```bash
gh search users --type users "company.com in:email"
gh api orgs/<org>/members --paginate | jq '.[].login'
```

**Other platforms**: `gitlab.com/<org>`, `bitbucket.org/<org>`, `sourcegraph.com/search?q=org:<org>`, `grep.app`.

---

## Phase 2: GitHub Search Dorks

Run at `github.com/search?type=code` or via API.

**High-value secrets**:
```
org:TARGET "api_key"
org:TARGET "api_secret"
org:TARGET "AWS_ACCESS_KEY_ID"
org:TARGET "AWS_SECRET_ACCESS_KEY"
org:TARGET "password" filename:.env
org:TARGET "private_key" extension:pem
org:TARGET "BEGIN RSA PRIVATE KEY"
org:TARGET "BEGIN OPENSSH PRIVATE KEY"
org:TARGET "token" filename:config
org:TARGET "jdbc:mysql"
org:TARGET "mongodb+srv"
org:TARGET "redis://"
org:TARGET "Authorization: Bearer"
org:TARGET "internal" filename:docker-compose.yml
org:TARGET extension:sql "INSERT INTO users"
```

**Infrastructure**:
```
org:TARGET "10.0." OR "192.168." OR "172.16."
org:TARGET ".internal" OR ".corp" OR ".local"
org:TARGET "staging" OR "dev" OR "preprod" filename:.env
org:TARGET "DATABASE_URL"
org:TARGET "SLACK_WEBHOOK"
org:TARGET "STRIPE_SECRET"
org:TARGET "SENDGRID_API_KEY"
```

---

## Phase 3: Secret Scanning

**TruffleHog** (best for git history):
```bash
trufflehog git https://github.com/ORG/REPO --json > raw/osint/trufflehog-REPO.json
trufflehog github --org=TARGET --json > raw/osint/trufflehog-org.json
trufflehog git https://github.com/ORG/REPO --only-verified
trufflehog git REPO_URL --since-commit=HEAD~500
```

**Gitleaks**:
```bash
gitleaks detect --source /path/to/repo --report-format json --report-path raw/osint/gitleaks-REPO.json
gitleaks detect --source /path/to/repo --log-opts="HEAD~1000..HEAD" --report-format json --report-path raw/osint/gitleaks-history.json
```

**Gitrob** (org-wide): `gitrob -github-access-token TOKEN TARGET_ORG`.

---

## Phase 4: Credential Validation (detect → verify live → prove access → hand off)

A secret is a lead until verified. Every candidate gets a read-only, single-shot identity check against its **issuing provider** — this separates Critical (live credential) from noise (rotated/redacted/regex false-positive) without touching data.

**Re-scan with verification on** (trufflehog performs provider-side validation itself):
```bash
trufflehog git https://github.com/ORG/REPO --only-verified --json > raw/osint/trufflehog-REPO-verified.json
```

**Provider identity probes** (read-only, single-shot each — never iterate/spray):
```bash
# AWS keys: STS identity call answers live? + whose account? (no data API touched)
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… aws sts get-caller-identity

# Generic API keys/tokens: hit the whoami-style endpoint, nothing else
curl -s -H "Authorization: Bearer <token>" https://api.<service>/me | jq .
curl -s -H "X-API-KEY: <key>" https://api.<service>/v1/whoami

# Google OAuth refresh token: token endpoint introspection only
curl -s https://oauth2.googleapis.com/token -d client_id=… -d refresh_token=… -d grant_type=refresh_token

# Slack: auth.test verifies the token and names the workspace
curl -s -X POST https://slack.com/api/auth.test -d token=<token>

# Twilio/Stripe/SendGrid style: fetch own account object
curl -s -u <sid>:<token> https://api.twilio.com/2010-04-01/Accounts/<sid>.json
```

**Verified credential + in-scope asset → access proof** (engagement RoE, `roe.post_exploitation` default true):
```bash
# Leaked DB connection string on an in-scope database: connect + identity proof, bounded enumeration (<=3 rows)
mysql -h <host> -u <user> -p<pass> -e "SELECT current_user(), version();"
psql "postgres://user:pass@host/db" -c "SELECT current_user, version();"
redis-cli -h <host> -a <pass> INFO server

# Leaked SSH key + in-scope host: auth-mode probe only, capture the welcome banner
ssh -i <key> -o BatchMode=yes -o StrictHostKeyChecking=accept-new <user>@<host> 'id; hostname'

# Private key/cert for an in-scope service (e.g. mTLS client cert): handshake proof
openssl s_client -connect <host>:443 -cert client.pem -key client.key </dev/null | head
```
No mass dumps, no config changes, no persistence — identity proof + bounded enumeration, teardown logged in `experiments.md`. Out-of-scope/third-party credentials: record and report, never use.

**Hand-off**: write each validated credential to `session-memory.md` → Access & Credentials (value in the engagement dir only, env-var name in prompts) and flag the authenticated attack classes it unlocks for the executors.

### Exposed `.git/` recursive walker

When `https://<vhost>/.git/HEAD` returns 200 but `git-dumper` can't reach it (vhost not in DNS, SNI-only certs), monkey-patch DNS in Python and walk loose objects directly. Each object lives at `.git/objects/<sha[:2]>/<sha[2:]>`, zlib-decompressed to `<kind> <size>\x00<content>`. Parse `commit` for `tree` and `parent` SHAs; parse `tree` (binary `<mode> <name>\x00<20-byte-sha>` repeating). BFS until empty, then `git checkout master` reconstructs the working tree.

```python
import socket, ssl, zlib, urllib.request
orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *a, **k: orig(TARGET_IP, p, *a, **k) if VHOST in (h or '') else orig(h, p, *a, **k)
ctx = ssl._create_unverified_context()
# fetch HEAD → refs/heads/master → walk objects/<sha[:2]>/<sha[2:]>
```

After dump, ALWAYS `git log -p <auth-related-file>` — devs frequently regress redacted secrets (`var key = "****"`) in earlier commits, leaking JWT keys / DB passwords / API tokens.

### Internal Git portals — anonymous clone is the default

GitBucket (`:8080`), Gitea (`:3000`), Gogs (`:3100`) and similar self-hosted portals frequently leave anonymous clone enabled even on internal deployments. Discover via REST (`/api/v3/repositories` GitBucket, `/api/v1/repos/search` Gitea), clone every repo, then mine removed-but-not-rotated credentials with `git log --all --full-history -p -- '*.cfg' '*.env' '.htpasswd' 'docker-compose*' 'haproxy.cfg' 'nginx.conf' | grep -iE 'pass|secret|key|token'`. Removed credentials are STILL VALID until rotated; `haproxy.cfg`, `docker-compose.yml`, `.env`, and ansible vault files are the highest-yield targets.

---

## Phase 5: Code Intelligence

**Extract endpoints and config from cloned repos**:
```bash
git clone https://github.com/ORG/REPO /tmp/repo-scan

# Internal hostnames
grep -rE '(https?://[a-z0-9.-]+\.(internal|corp|local|dev|staging))' /tmp/repo-scan/

# Hardcoded RFC1918 IPs
grep -rE '\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' /tmp/repo-scan/

# Auth literals
grep -rE '(Authorization|Bearer|apikey|api_key|secret|password)\s*[=:]\s*["\x27][^"\x27]{8,}' /tmp/repo-scan/

# Dependency manifests (CVE lookup material)
cat /tmp/repo-scan/{package.json,requirements.txt,Gemfile,pom.xml} 2>/dev/null
```

**CI/CD config files to review**:
```
.github/workflows/*.yml      GitHub Actions: secrets, deploy keys, env vars
.gitlab-ci.yml               GitLab CI: tokens, registry creds
Jenkinsfile                  Jenkins: credentials, internal URLs
.circleci/config.yml         CircleCI: env vars, contexts
.travis.yml                  Travis: encrypted vars
Dockerfile, docker-compose.yml  ARG secrets, internal services
terraform/, *.tf             Cloud infra, IAM, resource names
```

---

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
