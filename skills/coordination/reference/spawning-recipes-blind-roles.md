# Spawning Recipes — Blind Roles

Blind-role spawn recipes split from [spawning-recipes.md](spawning-recipes.md): the Skeptic and both Validators — every role spawned blind to `attack-chain.md`. Executor, coordinator, patterns, and anti-pattern recipes stay there.

## Skeptic (mandatory at experiments 5, 15, 25)

Blind to attack-chain. Argues against the dominant theory.

```python
skeptic_role  = Read("skills/coordination/reference/skeptic-role.md")
recon_listing = Bash(f"ls -la {output_dir}/recon/")

Agent(description=f"Skeptic: experiment {N}", prompt=f"""{skeptic_role}

OBJECTIVE: {objective}
OUTPUT_DIR: {output_dir}
EXPERIMENT_COUNT: {N}

EXPERIMENTS:
{experiments}

RECON_LISTING:
{recon_listing}
""", run_in_background=True)
```

Forbidden: reading `attack-chain.md`, skill files, RESEARCH_BRIEF.

## Validator — finding (interleaved, blind — the instant INTEGRATE materializes a candidate)

Spawn this **right after INTEGRATE** produces the candidate, before the next batch — not in a downstream one-shot pass. Re-spawn a **fresh** validator each cure round so the blind contract holds across the whole convergence loop.

```python
validator_role = Read("skills/coordination/reference/validator-role.md")
validation_doc = Read("skills/coordination/reference/VALIDATION.md")

Agent(description=f"Validate finding {finding_id}", prompt=f"""{validator_role}

class: finding
finding_id: {finding_id}
FINDING_DIR: {output_dir}/findings/finding-{finding_id}/
TARGET_URL: {target_url}
OUTPUT_DIR: {output_dir}/artifacts

VALIDATION_PROCEDURE:
{validation_doc}
""", run_in_background=True)
# → CONFIRMED (validated/) | REJECTED (false-positives/) | CURE | DROPPED (dropped/)
```

Forbidden: attack-chain, other findings, executor logs, skill files (except VALIDATION.md), RESEARCH_BRIEF.

## Validator — engagement (once at loop end, blind)

```python
validator_role = Read("skills/coordination/reference/validator-role.md")

Agent(description=f"Validate engagement thoroughness", prompt=f"""{validator_role}

class: engagement
OUTPUT_DIR: {output_dir}
""", run_in_background=True)
```

Forbidden: attack-chain, finding internals, validator-finding artifacts.
