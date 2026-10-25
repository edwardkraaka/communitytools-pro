#!/usr/bin/env python3
"""Tiered, NON-destructive-by-default php2shell engagement checker.

Detects the attack primitives behind CVE-2026-109618 / CVE-2026-109619 (PHP
`session.upload_progress` + Zend OOM pre-auth RCE, disclosed 2026-10-21,
CVSS 9.2; GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp) on an authorized target.

Adapted for this suite from the upstream scanner in the php2shell-poc toolkit
(github.com/ikow/php2shell-poc, MIT license, scanner/check.py), pinned at
upstream commit 31519e6d8a84dee1df1262961ed1bebb65accadd. The HTTP layer and
tier logic are adapted from upstream; the tier-4 gating, verdict→RoE mapping,
engagement JSON shape and exit-code contract are suite additions.

Tiers (progressive; each is an importable function, all folded into scan()):
  1. Version fingerprint — passive GET; PHP version + SAPI guess + patched math
  2. upload_progress reachability — 1-2 small multipart POSTs (~2KB)
  3. Session write verification — marker filename POST + read-back GET
  4. OOM differential — REFUSED unless --oom-differential is passed AND the
     target resolves to loopback/private/RFC 5737 documentation space. This
     tier sends a ~2MB multipart designed to exceed memory_limit and crash
     unpatched PHP workers: it is a worker-killing availability event, i.e.
     the destructive-action class the suite's standing prohibition
     ("no DoS / availability disruption") refuses. Default runs never send it.

stdlib only; deterministic (no threads). Deterministic tool output is usable
as a `tools/NNN_*.md` corroborator for coverage-gate negatives.

Usage:
  python3 tools/php2shell_check.py http://127.0.0.1:8080            # tiers 1-3
  python3 tools/php2shell_check.py --targets urls.txt --json        # batch
  python3 tools/php2shell_check.py http://127.0.0.1:8080 --oom-differential

Exit codes:
  0   at least one target VULNERABLE or LIKELY_VULNERABLE
  1   all targets PATCHED
  2   all targets UNKNOWN/ERROR (or usage/refusal)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import uuid
from urllib.parse import urlparse

VERSION = 1

# Patched version boundaries per branch (>= is patched). Branches absent here
# are EOL (5.x, 7.x, 8.0, 8.1) with no fix — treat as vulnerable.
PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# session.upload_progress was introduced in 5.4.0 — nothing before it is affected.
VULN_FLOOR = (5, 4, 0)

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
UPSTREAM = "github.com/ikow/php2shell-poc@31519e6d8a84dee1df1262961ed1bebb65accadd"

TIER4_GATING = (
    "Tier 4 (OOM differential) sends an oversized multipart that EXCEEDS the "
    "target's memory_limit during SAPI parsing: on unpatched PHP it crashes "
    "the worker (empty 500 / reset / 502). That is a worker-killing "
    "availability event — the destructive-action class the engagement "
    'prohibition "no DoS / availability disruption" refuses. It is allowed '
    "ONLY with an explicit opt-in (--oom-differential) against a target that "
    "resolves to loopback, RFC 1918, or RFC 5737 documentation space — i.e. "
    "your own lab (benchmarks/php2shell)."
)


# ══ HTTP layer — raw sockets, no deps (adapted from upstream) ═════════════

def _connect(host, port, tls=False, timeout=10):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def _recv_all(sock, timeout=10):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            chunks.append(d)
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            break
    return b"".join(chunks)


def _parse_response(raw):
    """Raw HTTP response bytes -> (status, headers_dict, body_bytes)."""
    if not raw:
        return 0, {}, b""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    status = int(m.group(1)) if m else 0
    headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def http_request(host, port, method, path, headers=None, body=None,
                 tls=False, timeout=10):
    hdrs = {"Host": host, "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    raw_req = req.encode("latin-1")
    if body:
        raw_req += body if isinstance(body, bytes) else body.encode("latin-1")
    try:
        sock = _connect(host, port, tls=tls, timeout=timeout)
        sock.sendall(raw_req)
        raw_resp = _recv_all(sock, timeout=timeout)
        sock.close()
        return _parse_response(raw_resp)
    except (socket.error, ssl.SSLError, OSError) as e:
        return 0, {}, str(e).encode()


def parse_target(url):
    u = urlparse(url if "://" in url else f"http://{url}")
    tls = u.scheme == "https"
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if tls else 80)
    path = u.path or "/"
    return host, port, tls, path


# ══ Version utilities ═════════════════════════════════════════════════════

def parse_version(ver_str):
    """'8.2.34' (or 'PHP/8.2.34') -> (8, 2, 34) or None."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str or "")
    return tuple(int(x) for x in m.groups()) if m else None


def is_vulnerable(ver_tuple):
    if ver_tuple < VULN_FLOOR:
        return False
    patched = PATCHED_VERSIONS.get(ver_tuple[:2])
    if patched is None:  # EOL branch — no fix exists
        return True
    return ver_tuple < patched


def version_recommendation(ver_tuple):
    if ver_tuple is None:
        return "version unknown — manual check required"
    patched = PATCHED_VERSIONS.get(ver_tuple[:2])
    if patched is None:
        return (f"PHP {'.'.join(map(str, ver_tuple))} is EOL — no fix; upgrade to a "
                f"supported branch (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+)")
    if ver_tuple < patched:
        return f"upgrade to PHP {'.'.join(map(str, patched))}+"
    return "version is patched"


# ══ Tier 1: version fingerprint ═══════════════════════════════════════════

def check_version(host, port, path, tls, timeout=10):
    result = {"version": None, "sapi": None, "vulnerable": None, "source": None}
    status, headers, body = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if status == 0:
        result["source"] = "connection_failed"
        return result

    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        result["version"] = m.group(1)
        result["source"] = "x-powered-by"
        result["sapi"] = "mod_php" if "apache" in server.lower() else "fpm"
    else:
        sm = re.search(r"PHP/(\d+\.\d+\.\d+)", server)
        if sm:
            result["version"] = sm.group(1)
            result["source"] = "server-header"
            result["sapi"] = "mod_php"
    if result["sapi"] is None:
        sl = server.lower()
        if "apache" in sl:
            result["sapi"] = "mod_php"
        elif "nginx" in sl:
            result["sapi"] = "fpm"
    if result["version"] is None and body:
        bm = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if bm:
            result["version"] = bm.group(1).decode()
            result["source"] = "body"
    if result["version"]:
        vt = parse_version(result["version"])
        if vt:
            result["vulnerable"] = is_vulnerable(vt)
    return result


# ══ Tier 2: upload_progress reachability ══════════════════════════════════

def check_upload_progress(host, port, path, tls, timeout=10):
    result = {"reachable": False, "session_fixation": False, "details": ""}
    boundary = "SCANBOUND" + uuid.uuid4().hex[:8]

    # Probe 1: multipart POST without cookie — a Set-Cookie: PHPSESSID back
    # means the rfc1867 upload_progress handler processed the request.
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    status, resp_headers, _ = http_request(
        host, port, "POST", path,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=body, tls=tls, timeout=timeout)
    if status == 0:
        result["details"] = "connection failed"
        return result
    set_cookie = resp_headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        result["reachable"] = True
        result["details"] = "upload_progress handler active (session created on multipart POST)"
    elif status in (200, 301, 302):
        result["details"] = (f"HTTP {status} but no session cookie — endpoint may not "
                             "call session_start()")
    else:
        result["details"] = f"HTTP {status}"

    # Probe 2: session fixation via POST body (rfc1867 accepts PHPSESSID from
    # the multipart body, ignoring use_only_cookies).
    sid2 = "fixcheck" + uuid.uuid4().hex[:16]
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid2}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    status2, resp_headers2, _ = http_request(
        host, port, "POST", path,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=body2, tls=tls, timeout=timeout)
    sc2 = resp_headers2.get("set-cookie", "")
    if sid2 in sc2:
        result["reachable"] = True
        result["session_fixation"] = True
        result["details"] = "session fixation via POST body confirmed (rfc1867 accepts PHPSESSID field)"
    elif "PHPSESSID" in sc2 and result["reachable"]:
        result["details"] += " (session fixation blocked — use_only_cookies may be On)"
    return result


# ══ Tier 3: session write verification ════════════════════════════════════

def check_session_write(host, port, path, tls, timeout=10):
    """Marker-filename injection probe: harmless marker, read-back check."""
    result = {"injectable": False, "details": ""}
    marker = "___PHP2SHELL_PROBE_" + uuid.uuid4().hex[:8] + "___"
    sid = "writecheck" + uuid.uuid4().hex[:16]
    boundary = "WRITEBOUND" + uuid.uuid4().hex[:8]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"x\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{marker}"\r\n\r\n'
        f"Z\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={sid}"}
    status, _, _ = http_request(host, port, "POST", path, headers=hdrs,
                                body=body, tls=tls, timeout=timeout)
    if status == 0:
        result["details"] = "injection request failed"
        return result
    _, _, resp_body = http_request(host, port, "GET", path,
                                   headers={"Cookie": f"PHPSESSID={sid}"},
                                   tls=tls, timeout=timeout)
    if marker.encode() in resp_body:
        result["injectable"] = True
        result["details"] = "raw filename found in session response — injection primitive confirmed"
    else:
        result["details"] = ("marker not reflected (expected unless the endpoint dumps "
                             "session contents; tier-2 reachability remains the signal)")
    return result


# ══ Tier 4: OOM differential — gated ══════════════════════════════════════

def target_is_lab_safe(host):
    """True iff the resolved host is loopback / RFC 1918 / RFC 5737 doc space.

    Tier 4 crashes unpatched workers, so it is confined to engagement-owned
    lab space. DNS names resolve via getaddrinfo; unresolvable -> False.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip in ipaddress.ip_network("192.0.2.0/24")
                or ip in ipaddress.ip_network("198.51.100.0/24")
                or ip in ipaddress.ip_network("203.0.113.0/24")):
            return False
    return bool(infos)


def build_oom_body():
    """~2MB multipart of deeply-nested keys — exceeds a 32M memory_limit only
    when the engine's per-field hashtable overhead multiplies it (upstream's
    approach). Kept as its own function so tests can size it without sending."""
    boundary = "OOMPROBE"
    nested_key = "a" + "[x]" * 60
    parts = []
    for i in range(800):
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{nested_key}{i}"\r\n\r\n'
            f"{'A' * 2048}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("latin-1")


def check_oom(host, port, path, tls, timeout=15):
    """OOM differential probe. DESTRUCTIVE — crashes unpatched PHP workers.
    Only reachable via --oom-differential on a lab-safe target (see main())."""
    result = {"vulnerable": None, "behavior": "", "details": ""}
    base_status, _, _ = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if base_status == 0:
        result["details"] = "baseline request failed"
        return result

    oom_body = build_oom_body()
    oom_status, _, oom_resp = http_request(
        host, port, "POST", path,
        headers={"Content-Type": "multipart/form-data; boundary=OOMPROBE"},
        body=oom_body, tls=tls, timeout=timeout)

    if oom_status == 0:
        result["vulnerable"] = True
        result["behavior"] = "connection_reset"
        result["details"] = "OOM probe caused connection reset — unpatched crash behavior"
    elif oom_status == 502:
        result["vulnerable"] = True
        result["behavior"] = "502_gateway"
        result["details"] = "OOM probe caused 502 — FPM worker crash (unpatched)"
    elif oom_status == 500:
        text = oom_resp.decode("latin-1", "replace")
        if "Allowed memory size" in text:
            result["behavior"] = "memory_error_500"
            result["details"] = "OOM error returned — may be patched (soft OOM) or unpatched"
        elif len(oom_resp) == 0:
            result["vulnerable"] = True
            result["behavior"] = "empty_500"
            result["details"] = "empty HTTP 500 — worker crash without error output (unpatched)"
        else:
            result["behavior"] = "nonempty_500"
            result["details"] = f"HTTP 500 with {len(oom_resp)}B body"
    elif oom_status == base_status:
        result["behavior"] = "normal_response"
        result["details"] = (f"OOM probe returned HTTP {oom_status} same as baseline — "
                             "memory_limit not reached or post_max_size blocked")
    else:
        result["behavior"] = f"http_{oom_status}"
        result["details"] = f"OOM probe returned HTTP {oom_status}"

    post_status, _, _ = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if post_status == 0 and base_status > 0:
        result["vulnerable"] = True
        result["details"] += " + worker did not recover"
    elif post_status == 502 and base_status != 502:
        result["vulnerable"] = True
        result["details"] += " + subsequent request got 502 (worker dead)"
    return result


# ══ Orchestrator ══════════════════════════════════════════════════════════

def chains_for(sapi, verdict):
    if verdict not in ("VULNERABLE", "LIKELY_VULNERABLE"):
        return []
    if sapi == "fpm":
        return ["A", "B", "C", "E"]
    if sapi == "mod_php":
        return ["A", "B", "D"]
    return ["A", "B", "C", "D", "E"]  # SAPI unknown — do not narrow


def scan(url, path=None, timeout=10, oom=False):
    host, port, tls, url_path = parse_target(url)
    if path:
        url_path = path
    result = {
        "tool": "php2shell_check",
        "tool_version": VERSION,
        "cves": list(CVE_IDS),
        "upstream": UPSTREAM,
        "target": url, "host": host, "port": port, "tls": tls, "path": url_path,
        "verdict": "UNKNOWN", "confidence": "LOW",
        "version": None, "sapi": None, "tiers": {}, "chains": [],
        "tier4_status": "refused" if not oom else "not_run",
        "recommendation": "", "error": None,
    }

    try:
        result["tiers"]["version"] = check_version(host, port, url_path, tls, timeout)
        result["version"] = result["tiers"]["version"].get("version")
        result["sapi"] = result["tiers"]["version"].get("sapi")
    except Exception as e:  # noqa: BLE001 — tier isolation
        result["tiers"]["version"] = {"error": str(e)}

    try:
        result["tiers"]["upload_progress"] = check_upload_progress(host, port, url_path, tls, timeout)
    except Exception as e:  # noqa: BLE001
        result["tiers"]["upload_progress"] = {"error": str(e)}

    if result["tiers"].get("upload_progress", {}).get("reachable"):
        try:
            result["tiers"]["session_write"] = check_session_write(host, port, url_path, tls, timeout)
        except Exception as e:  # noqa: BLE001
            result["tiers"]["session_write"] = {"error": str(e)}

    if oom:
        if target_is_lab_safe(host):
            try:
                result["tiers"]["oom"] = check_oom(host, port, url_path, tls, max(timeout, 15))
                result["tier4_status"] = "run"
            except Exception as e:  # noqa: BLE001
                result["tiers"]["oom"] = {"error": str(e)}
                result["tier4_status"] = "error"
        else:
            result["tier4_status"] = "refused_target_not_lab"
            result["error"] = "tier 4 refused: target is not loopback/RFC1918/RFC5737"

    ver = result["tiers"].get("version", {})
    up = result["tiers"].get("upload_progress", {})
    oomr = result["tiers"].get("oom", {})
    ver_vuln = ver.get("vulnerable")
    up_reach = up.get("reachable", False)
    oom_vuln = oomr.get("vulnerable")

    if oom_vuln is True:
        result["verdict"], result["confidence"] = "VULNERABLE", "HIGH"
    elif ver_vuln is True and up_reach:
        result["verdict"], result["confidence"] = "VULNERABLE", "HIGH"
    elif ver_vuln is True:
        result["verdict"], result["confidence"] = "VULNERABLE", "MEDIUM"
    elif ver_vuln is False and not oom_vuln:
        result["verdict"], result["confidence"] = "PATCHED", "HIGH" if up_reach else "MEDIUM"
    elif up_reach and ver_vuln is None:
        result["verdict"], result["confidence"] = "LIKELY_VULNERABLE", "MEDIUM"
    elif ver.get("source") == "connection_failed":
        result["verdict"] = "ERROR"
        result["error"] = result.get("error") or "connection failed"
    else:
        result["verdict"], result["confidence"] = "UNKNOWN", "LOW"

    result["chains"] = chains_for(result["sapi"], result["verdict"])
    result["recommendation"] = version_recommendation(
        parse_version(result["version"]) if result["version"] else None)
    return result


# ══ Output ════════════════════════════════════════════════════════════════

RED, GRN, YLW, DIM, RST, BLD = ("\033[91m", "\033[96m", "\033[93m",
                                "\033[2m", "\033[0m", "\033[1m")
VERDICT_COLORS = {"VULNERABLE": RED, "LIKELY_VULNERABLE": YLW,
                  "PATCHED": GRN, "UNKNOWN": DIM, "ERROR": RED}


def _c(text, color):
    return f"{color}{text}{RST}" if sys.stdout.isatty() else text


def format_text(r):
    lines = [_c(f"[*] {r['target']} (php2shell: {'/'.join(r['cves'])})", BLD)]
    ver = r.get("version") or "unknown"
    src = r["tiers"].get("version", {}).get("source") or ""
    lines.append(f"    PHP {ver}{' (' + src + ')' if src else ''} | SAPI: {r.get('sapi') or 'unknown'}")
    up = r["tiers"].get("upload_progress", {})
    if up:
        reach = "reachable" if up.get("reachable") else "not reachable"
        fix = " | session fixation: yes" if up.get("session_fixation") else ""
        lines.append(f"    upload_progress: {reach}{fix}")
    sw = r["tiers"].get("session_write", {})
    if sw and "error" not in sw:
        mark = _c("injection confirmed", RED) if sw.get("injectable") else sw.get("details", "not tested")
        lines.append(f"    session write: {mark}")
    t4 = r.get("tier4_status")
    if t4 == "run":
        oomr = r["tiers"].get("oom", {})
        mark = _c("crash confirmed", RED) if oomr.get("vulnerable") else oomr.get("behavior", "")
        lines.append(f"    OOM differential: {mark}")
    elif t4 and t4 != "not_run":
        lines.append(_c(f"    OOM differential: {t4} — {TIER4_GATING}", DIM))
    lines.append("")
    lines.append(_c(f"    Verdict: {r['verdict']} ({r['confidence']})",
                    VERDICT_COLORS.get(r["verdict"], "")))
    if r["chains"]:
        lines.append(f"    Applicable chains: {', '.join(r['chains'])}")
    if r["recommendation"]:
        lines.append(f"    {r['recommendation']}")
    if r.get("error"):
        lines.append(f"    Error: {r['error']}")
    return "\n".join(lines)


def format_json(r):
    return json.dumps(r, indent=2, default=str, sort_keys=True)


# ══ CLI ═══════════════════════════════════════════════════════════════════

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="php2shell tiered check — CVE-2026-109618 / CVE-2026-109619 "
                    "(tiers 1-3 only; tier 4 requires explicit opt-in)")
    ap.add_argument("target", nargs="?", help="target URL (http:// or https://)")
    ap.add_argument("--targets", "-f", metavar="FILE", help="file of URLs, one per line (- for stdin)")
    ap.add_argument("--path", "-p", help="override endpoint path (default from URL or /)")
    ap.add_argument("--oom-differential", action="store_true",
                    help="OPT-IN tier 4: DESTRUCTIVE OOM probe — crashes unpatched "
                         "PHP workers; target must resolve to loopback/RFC1918/RFC5737")
    ap.add_argument("--json", "-j", action="store_true", help="JSON output")
    ap.add_argument("--timeout", type=int, default=10, help="per-request timeout seconds")
    ap.add_argument("--quiet", "-q", action="store_true", help="only show vulnerable targets")
    args = ap.parse_args(argv)

    if args.oom_differential:
        print(f"[!] {TIER4_GATING}", file=sys.stderr)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        if args.targets == "-":
            targets.extend(l.strip() for l in sys.stdin.read().splitlines()
                           if l.strip() and not l.startswith("#"))
        else:
            with open(args.targets, encoding="utf-8") as f:
                targets.extend(l.strip() for l in f.read().splitlines()
                               if l.strip() and not l.startswith("#"))
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    if not uniq:
        ap.error("provide a target URL or --targets file")

    results = [scan(t, path=args.path, timeout=args.timeout,
                    oom=args.oom_differential) for t in uniq]

    if args.json:
        print(format_json(results[0]) if len(results) == 1
              else json.dumps(results, indent=2, default=str, sort_keys=True))
    else:
        for r in results:
            if args.quiet and r["verdict"] not in ("VULNERABLE", "LIKELY_VULNERABLE"):
                continue
            print(format_text(r))
            print()

    verdicts = {r["verdict"] for r in results}
    if verdicts & {"VULNERABLE", "LIKELY_VULNERABLE"}:
        return 0
    if verdicts & {"PATCHED"}:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
