# php2shell lab — engagement-owned PHP matrix (CVE-2026-109618 / CVE-2026-109619)

Self-contained Docker lab mirroring `benchmarks/dvba_android` (one dir, no
runner integration, pinned artifacts). Built from upstream `php2shell-poc`
(github.com/ikow/php2shell-poc, MIT) pinned at commit
31519e6d8a84dee1df1262961ed1bebb65accadd; the app/index.php here is a
minimal upstream-derived harness, not a vendored exploit.

The full PHP 5.6-8.5 matrix is covered: EOL branches (5.6/7.4/8.0/8.1) are
FPM-only, mirroring the upstream lab's shape - a single vulnerable instance
each, since no later minor exists to patch against. Supported branches
(8.2/8.3/8.4/8.5) each get a vulnerable+patched FPM pair; 8.2 additionally
carries the zero-dependency mod_php surface.

**Loopback only** — every port binds `127.0.0.1` explicitly; nothing is
reachable off-box.

| Service | Image | Port | Role |
|---|---|---|---|
| `php-fpm-vuln` | php:8.2.34-fpm + nginx | 127.0.0.1:18056 | vulnerable FPM (chain E deterministic under `pm.max_children=1`) |
| `php-fpm-patched` | php:8.2.35-fpm + nginx | 127.0.0.1:18057 | patched control (tier-4 must show graceful OOM) |
| `php-mod-vuln` | php:8.2.34-apache (mod_php) | 127.0.0.1:18058 | vulnerable mod_php (chain D zero-dependency surface) |
| `php-fpm-vuln-56` | php:5.6.40-fpm + nginx | 127.0.0.1:18059 | vulnerable FPM, EOL branch (final 5.6 release) |
| `php-fpm-vuln-74` | php:7.4.33-fpm + nginx | 127.0.0.1:18060 | vulnerable FPM, EOL branch (final 7.4 release) |
| `php-fpm-vuln-80` | php:8.0.30-fpm + nginx | 127.0.0.1:18061 | vulnerable FPM, EOL branch (final 8.0 release) |
| `php-fpm-vuln-81` | php:8.1.31-fpm + nginx | 127.0.0.1:18062 | vulnerable FPM, EOL branch (final 8.1 release) |
| `php-fpm-vuln-83` | php:8.3.17-fpm + nginx | 127.0.0.1:18063 | vulnerable FPM, supported branch |
| `php-fpm-patched-83` | php:8.3.18-fpm + nginx | 127.0.0.1:18064 | patched control, supported branch |
| `php-fpm-vuln-84` | php:8.4.4-fpm + nginx | 127.0.0.1:18065 | vulnerable FPM, supported branch |
| `php-fpm-patched-84` | php:8.4.5-fpm + nginx | 127.0.0.1:18066 | patched control, supported branch |
| `php-fpm-vuln-85` | php:8.5.0-fpm + nginx | 127.0.0.1:18067 | vulnerable FPM, supported branch |
| `php-fpm-patched-85` | php:8.5.1-fpm + nginx | 127.0.0.1:18068 | patched control, supported branch |

## Bring up / tear down

```bash
docker compose up -d --build          # from this directory
docker compose ps
docker compose down -v                # when done
```

## Use

This is the ONLY sanctioned place to run the tier-4 OOM differential (the
`--oom-differential` flag verifies loopback/RFC1918/RFC5737 before sending —
these hosts qualify):

```bash
# tiers 1-3 against the vulnerable FPM container
python3 ../../tools/php2shell_check.py http://127.0.0.1:18056/index.php --json
# tier 4 (destructive: crashes unpatched workers) — lab only
python3 ../../tools/php2shell_check.py http://127.0.0.1:18056/index.php --json --oom-differential
# negative control: patched container, tier 4 must NOT crash the worker
python3 ../../tools/php2shell_check.py http://127.0.0.1:18057/index.php --json --oom-differential
```

Expected: `php-fpm-vuln` VULNERABLE/HIGH (8.2.34 FPM, chains A B C E),
`php-fpm-patched` PATCHED (8.2.35), `php-mod-vuln` VULNERABLE (chains A B D).
The tier-4 differential: connection reset / empty 500 / 502 on the two
8.2.34 containers, normal or graceful-OOM response on 8.2.35.

Weaponized chains A-C (upstream POCs) may be exercised against these
containers from a clone of the upstream repo at the pinned commit — never
vendored into this suite:

```bash
git clone https://github.com/ikow/php2shell-poc /tmp/php2shell-poc
git -C /tmp/php2shell-poc checkout 31519e6d8a84dee1df1262961ed1bebb65accadd
# upstream scanner against the lab matrix
python3 /tmp/php2shell-poc/scanner/check.py --targets <(printf 'http://127.0.0.1:18056\nhttp://127.0.0.1:18057\nhttp://127.0.0.1:18058\n')
```

Detection-rule validation (Suricata/Sigma/ModSecurity/OpenResty) pairs this
lab with `skills/dfir/reference/scenarios/log-analysis/php2shell-detection.md`.
