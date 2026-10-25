# php2shell detection and mitigation — CVE-2026-109618 / CVE-2026-109619

Provenance: detection rules below are adapted from the upstream php2shell-poc toolkit (github.com/ikow/php2shell-poc, MIT) pinned at commit 31519e6d8a84dee1df1262961ed1bebb65accadd (`detection/` directory); disclosed 2026-10-21; GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp; CVSS 9.2. Fetch authoritative scores with `python3 tools/nvd-lookup.py CVE-2026-109618 CVE-2026-109619`. Offensive counterpart (verification methodology): [`server-side php2shell scenario`](../../../../server-side/reference/scenarios/php2shell/php2shell-session-upload-progress-rce.md).

## What to detect

Pre-auth RCE chains against PHP 5.4.0-8.5.x built on (1) the rfc1867 `session.upload_progress` handler accepting `PHPSESSID` from the multipart POST body and storing the raw upload filename into the session file, and (2) Zend OOM `longjmp()` bailout leaving stale `EG()`/`BG()` globals that the next request/cleanup dereferences. Attack traffic is recognizable because `PHP_SESSION_UPLOAD_PROGRESS` has near-zero legitimate use in modern applications.

## Detection rules (upstream, deployable as-is)

| File upstream | Format | Coverage |
|---|---|---|
| `detection/php2shell.rules` | Suricata / Snort | 13 rules — request-side (SID 2026100-2026106), response-side (2026110-2026112), recon (2026115-2026116) |
| `detection/php2shell.yaml` | Sigma | 5 rules — webserver logs, process creation, file events |
| `detection/modsecurity.conf` | ModSecurity v2/v3 | 7 rules — IDs 9900100-9900106 |
| `detection/php2shell.lua` | OpenResty/Nginx Lua | reverse-proxy block/log module |

Pull the current rule text from the pinned upstream commit (rule bodies are updated upstream; this page carries the coverage map and usage guidance so an IR team can act without re-deriving it).

### The one rule that matters most

**SID 2026100** — `PHP_SESSION_UPLOAD_PROGRESS` in a multipart POST body — covers the primary attack vector for both CVEs with near-zero false positives. ModSecurity equivalent is rule 9900100 (`phase:2, deny, status:403` on `REQUEST_BODY @contains PHP_SESSION_UPLOAD_PROGRESS` chained on `Content-Type: multipart/form-data`). OpenResty equivalent: the Lua module's first check (`body:find("PHP_SESSION_UPLOAD_PROGRESS")` → `ngx.exit(403)`).

### Full SID map

| SID / Rule | Detects | Sev |
|---|---|---|
| 2026100 | `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST (primary trigger, both CVEs) | HIGH |
| 2026101 | `PHPSESSID` as a multipart form field (session fixation via POST body) | HIGH |
| 2026102 | PHP code (`<?php`/`<?=`) in an upload filename (session injection) | CRITICAL |
| 2026103 | `\|O:` serialized object in an upload filename (handler-mismatch chain C) | CRITICAL |
| 2026104 | >10KB upload filename (session inflation for chain E) | MEDIUM |
| 2026105 | chunked multipart POST (`post_max_size` bypass for chain D OOM) | MEDIUM |
| 2026106 | session-file path in URL (LFI trigger, chain A) | HIGH |
| 2026110 | PHP OOM "memory exhausted" in response | HIGH |
| 2026111 | "Session object destruction failed" in response (stale-BG exploitation) | CRITICAL |
| 2026112 | anomalous PHPSESSID cookie length (heap leak) | CRITICAL |
| 2026115 | small upload-progress probes ≥3/60s (scanner recon) | LOW |
| 2026116 | vulnerable PHP version in response header | INFO |

Sigma highlights: webserver-log rule (POST `.php` + `PHP_SESSION_UPLOAD_PROGRESS` keyword, level high); oversized-multipart POST + 500/502/503 with ≥5MB body (level medium); process-creation — shell/interpreter child of php-fpm/php-cgi/apache2/httpd (level critical); file-event — PHP code written into `sess_*` session files (level critical); PHP error logs — "Allowed memory size … exhausted" especially with "in Unknown on line 0" (OOM in SAPI parsing, not user code).

### Deployment

```bash
# Suricata
cp php2shell.rules /etc/suricata/rules/ && echo "  - php2shell.rules" >> /etc/suricata/suricata.yaml && suricatasc -c reload-rules
# ModSecurity — Apache or Nginx with the connector
cp modsecurity.conf /etc/modsecurity/conf.d/php2shell.conf && systemctl reload apache2  # or nginx
# OpenResty — inside the server block
#   access_by_lua_block { require("php2shell").check() }        -- block mode
#   access_by_lua_block { require("php2shell").check({ log_only = true }) }  -- tune first
```

Deploy request-side AND response-side layers: request-side stops the chains; response-side (2026110-2026112) catches exploitation that bypassed the front (e.g. padded past a 64KB WAF body-inspection window — attack bodies can exceed it by design).

## Mitigation ladder

1. **Patch PHP** — the only complete fix: 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+. EOL branches (5.x, 7.x, 8.0, 8.1) have no fix — migrate or accept compensating controls. The Zend OOM corruption (chain D) is engine-core; no INI setting fixes it.
2. **Reduce the surface immediately** — `session.upload_progress.enabled = Off` (breaks the rfc1867 primitive for chains A/C/E) + `session.use_only_cookies = On` + `session.use_strict_mode = On`. Does NOT fix the var_destroy UAF (B) or the OOM chains (D/E).
3. **WAF block** of `PHP_SESSION_UPLOAD_PROGRESS` in multipart bodies (SID 2026100 / rule 9900100) — near-zero legitimate use.
4. **Consistency checks** — one `session.serialize_handler` (php_serialize) across all directories (kills the mismatch precondition for chain C); `find /var/www -name '.user.ini' -exec grep -l serialize_handler {} +`.

## IR hunting queries

```bash
# front-line web logs
grep -r "PHP_SESSION_UPLOAD_PROGRESS" /var/log/nginx/ /var/log/apache2/
# chain-A LFI trigger attempts
grep -rE "sess_[a-f0-9]{32}" /var/log/nginx/access.log
# OOM in SAPI (not userland) — the "Unknown on line 0" signature
grep -r "Allowed memory size" /var/log/php*.log | grep "Unknown on line 0"
# successful-execution follow-on: shells spawned by the PHP worker
grep -rE "php-fpm.*(sh|bash|python|nc) -c" /var/log/audit/audit.log
# session-file poisoning (Sigma file-event equivalent)
grep -rlE "<\?php|system\(|eval\(" /var/lib/php/sessions/ 2>/dev/null
```

Post-exploitation indicators to sweep for: unexpected files under the session save_path, `PHPSESSID` values of anomalous length, worker restarts (502 bursts) aligned with large multipart POSTs, and shell processes parented by php-fpm/php-cgi/apache2.

## References

- Upstream toolkit (rules, lab, analysis): https://github.com/ikow/php2shell-poc
- Advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (php/php-src)
- Writeup: https://qideng.substack.com/p/php2shell-dissecting-phps-critical
- Community detection: https://github.com/corelight/php2shell-detect (Zeek + Suricata)
