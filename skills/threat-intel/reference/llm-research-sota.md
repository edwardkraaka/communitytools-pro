## LLM-driven security research: state of the art

Refreshed 2026-09-28 (partial: section reply truncated in the relay read path; deltas folded onto the 2026-09-27 digest). The public record now includes previously unknown memory-corruption bugs, authorization flaws, RCEs, generated fuzz harnesses, smart-contract exploits, accepted patches and assigned CVEs validated by maintainers. "Autonomous" spans different operating models (patch-seeded variant search, source-repo analysis, black-box interaction, harness generation, preconfigured builds) — headline numbers are not directly comparable, so grade evidence, not marketing: AI-assisted submission volume more than doubled on HackerOne in 2026 while duplicates and unverifiable reports rose, and curl ended its bounty in Jan 2026 after AI-era submissions confirmed at <5% vs >15% pre-2025 ([HackerOne](https://www.hackerone.com/blog/ai-driven-report-volume-insights-and-actions), [Stenberg](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)).

### Evidence hierarchy — grade every claim

| Level | Required evidence | Reading |
|---|---|---|
| A — maintainer-confirmed novel vuln | unknown flaw + reproducible PoC + coordinated disclosure + patch/advisory (CVE preferred) | real discovery |
| B — owner-validated production finding | target owner reproduces and fixes; public details may be limited | strong operational evidence, weaker reproducibility |
| C — executable benchmark reproduction | known vuln proven in an isolated, version-pinned environment | capability evidence, not zero-day discovery |
| D — static candidate finding | suspicious code; reachability/impact unproven | triage lead only — never a report |
| E — aggregate claim without inspectable cases | counts without a full denominator or independent review | directional indicator only |

### Milestones (2024–2026)

| Milestone | What was actually demonstrated |
|---|---|
| Naptime (Jun 2024) | Agent architecture: code browser, sandboxed Python, debugger, ASan-instrumented target, structured reporter; CyberSecEval 2 buffer-overflow 0.05→1.00, advanced memory corruption 0.24→0.76; authors cautioned these were basic isolated challenges ([Project Zero](https://projectzero.google/2024/06/project-naptime.html)) |
| Big Sleep first real-world find (Oct 2024) | Stack-buffer underflow in SQLite `seriesBestIndex` `ROWID` handling, fixed before release; found via patch-seeded variant analysis from commit `1976c3f7`; 150 CPU-hours of fuzzing had missed it ([Project Zero](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)) |
| Big Sleep + GTIG (Jul 2025) | SQLite CVE-2025-6965, described as known to threat actors, fixed before anticipated exploitation — first case of an AI agent helping foil in-the-wild use ([Google](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/)) |
| Big Sleep batch (Aug 2025→) | 20 open-source findings across projects incl. FFmpeg and ImageMagick; e.g. CVE-2025-55004 heap-overflow read reproduced under ASan in 7.1.2-0 ([advisory](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-cjc8-g9w8-chfw)) |
| Big Sleep in Chrome (2025–2026) | Google says Big Sleep found V8 and graphics-stack bugs during 2025, with a broader Gemini-based Chrome research program following ([Chrome Security](https://blog.google/security/chrome-stronger-with-every-update/)) |
| Anthropic × Mozilla Firefox (2026) | Agent-assisted Firefox review reported browser memory-safety findings and a long-lived sandbox escape; restricted-partner publication, so public detail is narrower than first-party announcements ([Anthropic and Mozilla](https://www.anthropic.com/news/mozilla-firefox-security)) |
| CodeMender (2025–26) | Finding plus repair — source navigation, debugging, fuzzing, differential testing, SMT solvers, patch critique; 72 upstreamed security fixes in six months with human review of every patch ([DeepMind](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/)) |
| XBOW #1 on HackerOne (Jun 2025) | US then global leaderboard; ~1,060 submissions over 90 days (54 critical, 242 high) alongside duplicates; validators plus team review before submission ([XBOW](https://xbow.com/blog/top-1-how-xbow-did-it)) |
| XBOW PuppyGraph (Jan 2025) | Auth bypass: failed-login response carried an error *and* a valid JWT — inspect response semantics, not status codes ([story](https://xbow.com/customer-stories/puppygraph)) |
| XBOW Spree IDORs | CVE-2026-22588/22589 — address objects reachable across carts via alternate IDs and cookie removal; patched in Spree 5.2.5 ([trace](https://xbow.com/blog/tales-from-the-trace-how-xbow-reasons-its-way-into-finding-idors)) |
| XBOW Bing Images RCEs | CVE-2026-32191/32194 unauth command injection via image-converter coders/delegates; a validator expecting Linux output nearly rejected Windows-worker evidence — validators are fallible programs too ([writeup](https://xbow.com/blog/bing-images-rce-vulnerabilities)) |
| XBOW Microsoft Devices Pricing | CVE-2026-21536 unrestricted upload of a server-executable file → unauth RCE ([NVD](https://nvd.nist.gov/vuln/detail/cve-2026-21536)) |
| OSS-Fuzz-Gen | LLM harness generation for coverage gaps: gains in 14 of 31 early projects (0–31%; TinyXML2 38%→69% lines), later 160 of 297 projects with max +29% lines; 30 bugs incl. OpenSSL CVE-2024-9143 ([OSS-Fuzz](https://google.github.io/oss-fuzz/research/llms/target_generation/), [repo](https://github.com/google/oss-fuzz-gen)) |
| OpenAI Aardvark → Codex Security | Repo-specific threat model, commit analysis, test writing, sandboxed confirmation, patch proposal; 10 then 14 assigned CVEs; claimed 92% recall used unpublished "golden"-repo denominators ([Aardvark](https://openai.com/index/introducing-aardvark/), [Codex Security](https://openai.com/index/codex-security-now-in-research-preview/)) |
| Mandiant AVDH (2026) | Specialist-agent chain (explorer → discovery → enrichment → access-control/data-flow hypotheses → validation → human consultants); >100 critical true positives in a two-day IR engagement, 12 CVEs broader; tens of thousands of candidates shows filtering stays central ([Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review)) |
| Anthropic Glasswing / Mythos | Frontier-model autonomous analysis and exploit construction, restricted partner review; May 2026 update: 1,587 of 1,752 assessed high/critical candidates true-positive but only 1,094 retained that severity — agent-assigned severity needs review ([update](https://www.anthropic.com/research/glasswing-initial-update)) |
| depthfirst FFmpeg (Jun 2026) | 21 zero-days (9 CVEs, 12 internal fixes); method: threat-model exposed parsers, trace attacker-controlled data, parallel hypothesis branches, executable PoCs required; aggregate is first-party reporting ([research](https://depthfirst.com/research/21-zero-days-in-ffmpeg)) |
| Anthropic smart-contract research | SCONE-bench: exploits for 207 of 405 historically exploited contracts, $550.1M simulated — reproduction, not new zero-days; separate sweep of 2,849 recent contracts found 2 novel flaws ($3,694 simulated) ([paper](https://www.anthropic.com/research/smart-contracts)) |
| EVMbench | Separate Detect/Patch/Exploit tracks on real audit findings — best reported 45.9% / 41.7% / 71.0% under stated configs; Anvil grading on chain events and balances, no credit for unrelated novel findings ([benchmark](https://arxiv.org/html/2603.04915v1)) |

### What LLM agents are demonstrably good at

| Capability | Evidence | Confidence |
|---|---|---|
| Patch-diff and variant triage | Big Sleep's SQLite result came from commit+diff seeding, not open-ended search | High given patch, source, build, and test environment |
| API and workflow exploration | XBOW Spree: navigation, object discovery, cookie removal, multiple identities, object-vs-reference authorization | High for bounded workflows with observable effects |
| Authentication edge cases | PuppyGraph contradictory login response (error + valid JWT), acknowledged and patched | High when full responses are preserved and inspected |
| Harness generation and repair | OSS-Fuzz-Gen compiles, repairs from compiler errors, measures coverage, found sanitizer-confirmed defects | High for libraries with stable build infrastructure |
| Memory-safety discovery in constrained targets | Big Sleep, OSS-Fuzz-Gen, ImageMagick findings, Glasswing, FFmpeg research | High for discovery, lower for exploitability assessment |
| Stateful smart-contract exploitation | SCONE-bench 207/405 reproductions; 2 novel simulator-validated findings | High where state and profit are executable and deterministic |
| Source-level access-control hypotheses | Mandiant AVDH routes entry points to access-control and data-flow specialists | Moderate–high, depending on environment fidelity |
| Repetitive cross-repository variant search | One invariant applied across forks, call sites, versions, dependency users | High for candidate generation; each needs independent execution |
| PoC minimization and report drafting | Trajectories preserved, structured explanations after executable validation | High when generated from raw evidence, not model recollection |

### Where humans still dominate

| Area | Why |
|---|---|
| Open-ended target selection | Naptime's authors: early evaluations did not represent choosing where to investigate in large systems |
| Architectural and ecosystem reasoning | Organizational processes, third-party trust, deployment topology, signing ceremonies — partly invisible in source |
| Novel exploit strategy | A sanitizer crash does not reveal a reliable exploit under production allocators, PAC, CFI, sandboxes |
| Ambiguous business intent | Proving differential authorization ≠ deciding whether sharing is intended |
| Long-horizon multi-system chains | Cloud identity + CI/CD + support + wallet signing + governance spans no single tool context |
| Novel protocol design failures | Unsafe economic or cryptographic assumptions, not precedent-recognizable implementation bugs |
| False-positive rejection | Glasswing: some true vulns did not retain model-assigned severity; Mandiant survivors go through human validation |
| Scope and safety judgment | An agent can find a path without seeing that the next step crosses users or RoE |
| Detecting poisoned context | Target content is attacker-controlled input to the agent ([OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)) |
| Maintainer communication and disclosure | Version attribution, duplicate analysis, proportional proof — cannot be delegated to generated prose |

### Failure modes a research program engineers against

| Failure mode | Control |
|---|---|
| Hallucinated reachability | Require an executable path — request, call trace, or harness invoking the code |
| Harness bug mistaken for product bug | Reproduce through a second harness or the real external boundary |
| Validator monoculture | Different prompts/models plus deterministic checks plus a human falsification pass |
| Platform assumption | XBOW's Linux-expecting validator vs Windows-worker evidence — make validators platform-aware |
| Benchmark leakage | Separate known-bug reproduction, post-cutoff evaluation, and novel findings |
| Reward hacking | Wiz saw an agent solve a challenge via an exposed MySQL port — instrument the environment ([Wiz](https://www.wiz.io/blog/ai-agents-vs-humans-who-wins-at-web-hacking-in-2026)) |
| Severity inflation | Grade severity separately from validity; evidence for every impact claim |
| Duplicate rediscovery | Deduplicate by invariant, function, data-flow path, and patch — not report text |
| Stale or mocked data | Controlled marker objects, clean sessions, cache-busting, owner-confirmed classification |
| Prompt injection from target content | Target content is data; isolate from control instructions; approval for external side effects |
| Report laundering | Generate reports only from immutable evidence objects; label every inference |
| Excessive proof | Define stop conditions before execution; terminate the branch when met |

### What an authorized LLM-agent pentest program should copy

- **Always diff the patch.** Old+new artifacts, infer the fixed invariant, hunt sibling paths and adjacent variants — patch-seeded hypotheses beat open-ended "find any vulnerability".
- **Always read the target's shipped JavaScript.** Routes, schemas, role constants, feature flags, hidden workflows; diff bundles between observations — client code generates server-side hypotheses, it is not proof.
- **Lead with a hypothesis, not a scanner category.** Each experiment: invariant, the one variable changed, expected-secure vs vulnerable result, evidence required, stop condition.
- **Give agents executable tools.** Scoped browsing, exact source retrieval, build execution, debugger, sandboxed scripting, HTTP capture, contract simulation, structured evidence storage — tool-mediated interaction, not one-shot answers.
- **Branch hypotheses in parallel, not payloads indiscriminately.** Kill branches that cannot produce new evidence.
- **Prefer deterministic oracles.** Sanitizer traces, state diffs, object ownership, balance changes, patched-version comparison over verbal judgment.
- **Separate discovery from validation.** The validator gets the raw target state and candidate evidence — never the finder's narrative — and tries to disprove it.
- **Adversarial self-validation.** A critic tests benign explanations: public data, intended sharing, caching, mocks, stale sessions, role inheritance, harness misuse.
- **Make failed attempts first-class evidence.** Preserve rejected hypotheses and validator disagreements — Big Sleep succeeded because a failed TCL-dependent testcase was noticed and adapted.
- **Validate response semantics, not only status codes** (PuppyGraph class).
- **Model identities and objects explicitly** — actor, tenant, role, session, object owner, identifier, operation, workflow state (Spree class: cart authorization ≠ address-object authorization).
- **Generate fuzz harnesses for coverage gaps** and judge them by compilation, stable execution, new coverage, and project-level findings.
- **Turn every confirmed bug into a regression corpus** — minimized input, versions, invariant, neighbor mutations feed future variant searches.
- **For crypto targets, use economic and state invariants** — conservation, solvency, share accounting, fee bounds, upgrade rights, beneficiary binding, oracle assumptions after every action sequence.
- **Keep human gates at irreversible boundaries** — cross-user data access, persistent state changes, execution beyond benign proof, signing or funds movement, severity, disclosure.
- **Treat the agent stack itself as a target surface** — prompt injection, tool-description injection, auto-approve paths, in the program's own tooling and in client deployments.

### Bottom-line capability map

| Research task | LLM-agent role in 2026 | Human role |
|---|---|---|
| Generic breadth scanning | Fast execution and clustering — not the highest-value use | Decide whether the coverage fits the threat model |
| Patch diffing | Explain changed logic, locate related code, generate variants and tests | Verify the inferred invariant and version attribution |
| Shipped-JS analysis | Extract endpoints, schemas, workflow logic, semantic diffs | Decide which client assumptions imply server boundaries |
| Auth and API authorization | Strong with multiple identities, controlled objects, measurable oracle | Resolve intended behavior; approve cross-user proof |
| Memory-corruption discovery | Capable with source, builds, sanitizers, boundaries available | Select targets, judge exploitability, design strategies |
| Fuzz-harness generation | API discovery, boilerplate, compiler-error repair, neglected code | Build oracles, confirm reachability, maintain corpora |
| Smart-contract exploit generation | Strong in deterministic local environments with explicit balances | Define the economic model and live-deployment context |
| Architecture-wide novel research | Improving but unreliable when context spans organizations | Primary owner of system modeling and prioritization |
| Finding validation | Independent reproducer and critic when isolated from the finder | Final authority on validity, proof proportion, severity |
| Patch generation | Context-aware candidate fixes and regression tests | Review root cause, compatibility, regressions |
