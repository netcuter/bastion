# Bastion v3.1 — Roadmap

See `docs/DESIGN.md` for full implementation blueprints.

## In Progress

- [ ] **Feature #3: Agent Guardrails Layer** (`security_audit/ai/guardrails.py`)
  - Scope allowlist, rate-limit, dry-run, HITL approval gate, action ledger (JSONL)
  - Foundation for all AI-driven features

- [ ] **Feature #5: SBOM + VEX + EPSS** (CycloneDX 1.6)
  - `reporters/cyclonedx_reporter.py` + `reporters/vex_reporter.py`
  - OSV.dev + EPSS integrations with 24h cache

- [ ] **Feature #2: Reachability Analysis** (`core/reachability.py`)
  - Entrypoint detectors: Flask, Django, FastAPI, Express, Spring, Laravel, CLI, Celery
  - BFS through existing call graph → REACHABLE / UNREACHABLE / UNKNOWN verdict per finding

- [ ] **Feature #1: Agentic Exploitability Validator** (headline feature)
  - `ai/exploit_agent.py` + `ai/judge_agent.py` + `ai/orchestrator.py` + `ai/sandbox.py`
  - Attacker → Sandbox → Judge 2-agent loop with guardrails on every action
  - Rewrite `ai/ai_local.py` → `StructuredLLMClient` with JSON schema validation

- [ ] **Feature #6: IaC Scanner** (`scanners/iac_scanner.py`)
  - Terraform / Kubernetes / Dockerfile / Docker Compose
  - 15 minimum rules (6 TF, 6 K8s, 3 Dockerfile)

- [ ] **Feature #4: LLM Red-Team Scanner** (`scanners/llm_redteam_scanner.py`)
  - Static: detect tainted system prompts in OpenAI/Anthropic SDK calls
  - Dynamic: ~50 payload corpus (prompt injection, jailbreak, tool poisoning)

- [ ] **Feature #7: DAST Harness** (`core/dast_runner.py`) — capstone
  - Rewrite `ai/evidence_capture.py` (HAR + Playwright screenshots + repro guide)
  - Rewrite `ai/tooling_layer.py` crawler (Playwright-based, robots.txt, OpenAPI discovery)
  - Probes: xss_reflected, sqli_time_based, ssrf, path_traversal, open_redirect

## Pre-work (completed / user action needed)

- [x] README.md → English default; README_PL.md → Polish
- [x] Strip religious/Polish exclamations from all .py files
- [x] Version unified to 3.1.0 via `security_audit/_version.py`
- [x] MCPFileScanner wired into CLI (scans `mcp.json`, `claude_desktop_config.json`)
- [x] .gitignore updated (tool pins, evidence dir, action ledger)
- [ ] **USER ACTION: Rotate GitHub token** — `ghp_UaABZE9...` is in `.git/config`, revoke + switch to SSH
- [ ] **USER ACTION: Rewrite git history** — split 2 mega-commits into semantic history (see `docs/DESIGN.md §A.5`)
- [ ] **Rewrite README.md** with full v3.1 content (comparison table vs SonarQube/Semgrep, new features)

## Ship Checklist (before sending CV to Terra Security)

- [ ] All features have ≥3 passing tests each
- [ ] `CHANGELOG.md` updated with v3.1.0 entry
- [ ] Demo asciinema recorded (`--validate-exploits` pipeline) + linked in README
- [ ] CI green on main
- [ ] README has "How we compare" table (Semgrep / SonarQube / Bastion)
- [ ] Cover letter uses Terra vocabulary: *reachability analysis*, *ambient agents*, *exploitability validation*, *human-in-the-loop*

## Blog Post (after features ship)

Write WordPress post, backdate to before CV send:
- **Title:** "Building a mini-Terra Portal in Python — when SAST meets agentic security"
- Problem: SAST findings ≠ vulnerabilities (the exploitability gap)
- Terra's thesis: agentic validation bridges the gap
- My implementation: bastion v3.1 features
- Demo: asciinema of `--validate-exploits` on vulnerable app
- Link to repo
