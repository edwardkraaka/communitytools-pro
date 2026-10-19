# Validation Output & Coordinator Loop

Companion to [VALIDATION.md](VALIDATION.md): the coordinator-side interleaved loop, the Validated/Rejected verdict-output JSON schemas, and the caught-failure catalogue. The canonical checks and the proof-package layout live there.

## Coordinator: interleaved per-finding validation

The coordinator does not batch all validators at the end. Immediately after INTEGRATE materializes a candidate — before the next THINK/batch — it runs the convergence loop for that candidate on **fresh** blind agents:

```python
validator_role = Read("skills/coordination/reference/validator-role.md")

# Right after INTEGRATE produces THIS candidate — before the next batch:
Agent(prompt=f"{validator_role}\n\n"
             f"finding_id: {finding['id']}\n"
             f"finding_json_path: {findings_file}\n"
             f"raw_dir: {{OUTPUT_DIR}}/recon/\n"
             f"executor_log: {{OUTPUT_DIR}}/logs/{executor}.log\n"
             f"findings_dir: {{OUTPUT_DIR}}/findings/\n"
             f"output_dir: {{OUTPUT_DIR}}/artifacts/",
      run_in_background=True)
# → CONFIRMED | REJECTED | CURE (close named gaps, re-validate on fresh agents) | DROPPED
```

Per terminal verdict, the coordinator:
1. Routes CONFIRMED → `{OUTPUT_DIR}/artifacts/validated/{id}.json`, REJECTED → `false-positives/{id}.json`, uncured DROPPED → `dropped/{id}.json`.
2. Cross-executor dedupe (same URL + same CWE → drop duplicate).
3. **Coverage-by-VALID:** a class flips to `covered` only on a `VALID`/`REPAIRED` finding, a justified N/A, or a genuine negative. A class whose only candidates were REJECTED/DROPPED stays `pending`, so search continues — this is the verdict→search feedback edge.

## Output: Validated

`{OUTPUT_DIR}/artifacts/validated/{id}.json`:

```json
{
  "finding_id": "F-001",
  "valid": true,
  "proof_dir": "findings/finding-001/evidence/validation/",
  "checks": {
    "cvss_consistency": {"passed": true, "detail": "CRITICAL matches CVSS 9.1"},
    "evidence_exists": {"passed": true, "detail": "All required files present"},
    "poc_validation": {"passed": true, "detail": "Valid Python, target referenced, output matches", "proof_file": "poc-rerun-output.txt"},
    "claims_vs_raw": {"passed": true, "detail": "All 5 claims corroborated"},
    "log_corroboration": {"passed": true, "detail": "All 4 phases with distinct timestamps"},
    "rootcause_severity_floor": {"passed": true, "detail": "Recomputed band HIGH matches/within one band of executor band"}
  }
}
```

## Output: Rejected

`{OUTPUT_DIR}/artifacts/false-positives/{id}.json`:

```json
{
  "finding_id": "F-009",
  "finding_title": "Information Disclosure via Prelogin Response",
  "source_file": "{OUTPUT_DIR}/findings/executor-findings.json",
  "valid": false,
  "failed_checks": ["cvss_consistency", "evidence_exists", "log_corroboration"],
  "checks": {
    "cvss_consistency": {"passed": false, "detail": "Severity 'LOW' does not match CVSS 5.3 (expected MEDIUM)"},
    "evidence_exists":  {"passed": false, "detail": "No findings/F-009/ directory"},
    "poc_validation":   {"passed": true,  "detail": "Valid Python, target referenced"},
    "claims_vs_raw":    {"passed": true,  "detail": "All 2 claims corroborated"},
    "log_corroboration":{"passed": false, "detail": "Bulk verify timestamps detected"}
  },
  "original_finding": { "...full original..." }
}
```

Rejected findings do NOT appear in the final report — not in findings, appendix, or summary counts. The `false-positives/` directory is the sole record. Reviewers can override via inspection if a validator was wrong.

## What the Validator Catches

1. Severity mislabeling (CVSS 5.3 → LOW; should be MEDIUM)
2. Ghost findings (no per-finding directory with PoC and evidence)
3. Broken PoCs (syntax errors or no target reference)
4. Hallucinated claims (HTTP 503 with no raw scan output supporting it)
5. Fabricated port states (port "open" with no nmap output)
6. TLS inflation (TLS issues not in openssl output)
7. Unverified CVE references (CVE named without scan evidence)
8. Bulk fabrication (all findings "verified" at the same timestamp)
9. Incomplete workflow (missing recon/experiment/test/verify)
10. Unsubstantiated validation (validator passed but `validation-summary.md` missing/empty)
11. Incomplete evidence packages (no `verification-script.py`, missing screenshots for a web target)
