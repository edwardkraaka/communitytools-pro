# php2shell — PHP session.upload_progress + Zend OOM pre-auth RCE (CVE-2026-109618 / CVE-2026-109619)

Provenance: adapted from the upstream php2shell-poc toolkit (github.com/ikow/php2shell-poc, MIT) pinned at commit 31519e6d8a84dee1df1262961ed1bebb65accadd; disclosed 2026-10-21; GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp; CVSS 9.2 (NVD v4.0 primary; v3.1 9.8 / 8.1). Always run `python3 tools/nvd-lookup.py CVE-2026-109618 CVE-2026-109619` for the authoritative scores before writing a finding. **No exploit code is vendored here** — this is verification methodology; weaponized chains A-C live upstream and D/E are paywalled upstream. The suite's positioning is authorized-engagement methodology and verification.

## What it is

Two coupled root causes in PHP 5.4.0 - 8.5.x (14 years of vulnerable code):

1. **rfc1867 `session.upload_progress` handler** (`ext/session/session.c`): accepts `PHPSESSID` from the multipart POST body (ignoring `session.use_only_cookies` — session fixation, fixed by PR#22113) and stores the raw upload **filename** into the session file with no validation (PHP code / serialized-object injection primitive). `session.upload_progress.enabled` is On by default.
2. **Zend OOM `longjmp()` bailout**: out-of-memory during request handling skips stack cleanup; shutdown then reads stale `EG()`/`BG()` globals (`BG(unserialize)` survives across FPM worker requests because it is not reset before `rfc1867` runs). Patch adds `php_basic_early_rinit()`; fix versions 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ — EOL branches (5.x, 7.x, 8.0, 8.1) never get a fix.

Impacts near-universal PHP fleets: WordPress (via plugins, WooCommerce), Joomla, Drupal, Laravel (`PendingBroadcast` destruct gadget), Magento (even in maintenance mode).

## The five chains — preconditions

| Chain | Vector | Pre-auth | Preconditions | SAPI |
|---|---|---|---|---|
| **A** | session injection + LFI | yes | `upload_progress.enabled=On` (default) **+ app has any LFI sink** (`include($_GET[...])`, wrapped path, plugin template loader). Version-independent — still fires on patched PHP when the app-level LFI exists | any |
| **B** | var_destroy UAF → handler overwrite | no (needs `unserialize()`) | app calls `unserialize()` on controlled data (cookie/body); payload >VAR_ENTRIES_MAX (1018) entries; heap-dependent (~60%) | any |
| **C** | serialize_handler mismatch → `__destruct` | yes | FPM worker reuse **+ two directories with different `session.serialize_handler`** (`.user.ini` per-dir); a reachable `__destruct` gadget class (Laravel et al.) | FPM |
| **D** | OOM corruption → stale `EG()` | yes | **none** — any endpoint; oversized multipart (can bypass `post_max_size` via chunked encoding) | mod_php |
| **E** | session OOM → stale `BG(unserialize)` | yes | producer: any `session_start()` endpoint (near-universal); consumer: **any** endpoint — `rfc1867` runs during SAPI startup before app code; deterministic with `pm.max_children=1` | FPM |

Read the `serialize_handler` mismatch signal from source/config when available: `find /var/www -name ".user.ini" -exec grep -l serialize_handler {} +` (or the same keys in vhost/.htaccess context). Chain D is the worst case: zero-dependency pre-auth RCE on stock Apache mod_php.

## Verification ladder (default-on, non-destructive)

Drive this with `tools/php2shell_check.py` (stdlib-only; tiers 1-3 default-on). Run it when techstack identification fingers PHP — `X-Powered-By: PHP/x.y.z`, `PHPSESSID` cookie, `.php` paths, Laravel/WordPress/Joomla/Drupal/Magento fingerprints:

```bash
# single asset (tiers 1-3: version + upload_progress reachability + session write)
python3 tools/php2shell_check.py https://www.example.com/ --json

# batch from the engagement surface list
python3 tools/php2shell_check.py --targets OUTPUT_DIR/recon/inventory/php-assets.txt --json
```

| Tier | What it proves | Risk | Traffic |
|---|---|---|---|
| 1 | PHP version + SAPI guess vs patch matrix (EOL branch = vulnerable, no fix) | none | 1 GET |
| 2 | rfc1867 handler processed our multipart: `Set-Cookie: PHPSESSID` on cookie-less POST = attack primitive reachable; second probe tests POST-body session fixation | low | 2 small POSTs (~2KB) |
| 3 | marker filename stored raw in session (injection primitive) when any endpoint reflects session content | low | 1 POST + 1 GET |
| 4 | OOM differential (crash vs graceful OOM) | **DESTRUCTIVE** | refused — see below |

Verdicts: `VULNERABLE` (version-vulnerable + reachable, or OOM-confirmed), `LIKELY_VULNERABLE` (primitive reachable, version hidden), `PATCHED`, `UNKNOWN`, `ERROR`. Exit 0 = at least one vulnerable/likely target. Record the JSON as the finding evidence; a `PATCHED` verdict with tier-2 reachability still evidences the residual app-level chains (A via LFI).

**Tier 4 (OOM differential) is refused by default and stays refused on client targets.** It sends a ~2MB multipart engineered to exceed `memory_limit` during SAPI parsing; on unpatched PHP it **kills the worker** (empty 500 / connection reset / 502). That is a worker-killing availability event — squarely the destructive-action class the standing prohibition `no DoS / availability disruption` refuses (see [`principles.md`](../../../../coordination/reference/principles.md) — destructive means irreversible impact to others). `--oom-differential` exists ONLY for the engagement-owned lab (`benchmarks/php2shell`), and the tool additionally verifies the target resolves to loopback / RFC 1918 / RFC 5737 space before sending. For a client target, chain D/E confidence comes from tier 1-2 + SAPI inference; note the residual uncertainty in the finding instead of crashing a worker.

## RoE / coverage discipline

- **Coverage mapping**: a fingerprinted PHP listener opens `WEB-A06-COMPONENTS` (host-scope cell); a deserialization/unserialize surface opens `WEB-A08-INTEGRITY`. The tier 1-3 JSON is the corroborator evidence for `tools/NNN_php2shell-check.md` (cite the raw JSON; header `Experiment: E-NNN`) — covered-negative cells need it.
- **Reversible writes**: tier-3 writes a session file entry under a random marker SID on the target's session store — a scoped, self-expiring write (`upload_progress.cleanup=On` reclaims it; the marker SID is never reused). Log it in `experiments.md` like any create-then-delete.
- **Exploitation depth**: tiers 1-3 prove the primitive (detect/confirm rungs). Climbing to code execution means weaponized chains A-C (upstream) — run those only from the linked upstream repo against the engagement-owned lab, never vendored into this suite; on a client engagement, chain-applicability + primitive proof + version matrix is the deliverable, with the chain named per SAPI from the table above.
- **CVE risk lookup** is mandatory before any finding cites these CVEs (`tools/nvd-lookup.py`), and the NVD JSON goes in evidence.

## Lab

`benchmarks/php2shell/` stands up the vulnerable/patched matrix (PHP 8.2.34 FPM vulnerable, 8.2.35 FPM patched, 8.2.34 Apache mod_php) bound to 127.0.0.1 only — the sanctioned place to run tier 4 and the upstream chain exploits.

## Detection/defense deliverable

When the engagement includes detection engineering or the client runs PHP, the blue-team counterpart is [`php2shell-detection.md`](../../../../dfir/reference/scenarios/log-analysis/php2shell-detection.md) (Suricata/Sigma/ModSecurity/OpenResty rules + mitigation ladder).

## Upstream

Scanner, POCs, Docker lab, detection rules, full technical analysis: https://github.com/ikow/php2shell-poc (pinned 31519e6d8a84dee1df1262961ed1bebb65accadd). Writeup: https://qideng.substack.com/p/php2shell-dissecting-phps-critical. Chain D/E exploit detail is paywalled upstream; the root-cause and detection material cited here is public.
