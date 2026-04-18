# Bastion — Security Audit System for Web Applications

**English | [Polski](README_PL.md)**

Bastion is an open-source, AI-augmented SAST platform that goes further than pattern matching. It finds vulnerabilities, filters false positives with ML, validates exploitability with a two-agent loop, and captures evidence — all locally, without sending code to the cloud.

![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![OWASP ASVS](https://img.shields.io/badge/OWASP%20ASVS-4.0-purple.svg)
![CWE Top 25](https://img.shields.io/badge/CWE%20Top%2025-2024-red.svg)
![ML FP Reduction](https://img.shields.io/badge/ML%20FP%20reduction-58%25-brightgreen.svg)
![Languages](https://img.shields.io/badge/languages-10+-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

---

## How it's different

| Capability | Semgrep OSS | SonarQube Community | **Bastion** |
|---|---|---|---|
| OWASP Top 10 + CWE Top 25 | ✅ | ✅ | ✅ |
| Framework-aware rules (Django, Express, Spring…) | Partial | Partial | ✅ 9 frameworks |
| Taint tracking / data flow | ✅ | ✅ | ✅ |
| ML false positive reduction | ❌ | ❌ | ✅ 58% FP↓ (validated) |
| Reachability analysis (live entrypoints) | ❌ | ❌ | ✅ v3.1 |
| Exploitability validation (agentic loop) | ❌ | ❌ | ✅ v3.1 |
| Agent safety guardrails (HITL, action ledger) | ❌ | ❌ | ✅ v3.1 |
| MCP server security scanning | ❌ | ❌ | ✅ v3.0 |
| IaC scanning (Terraform / K8s / Dockerfile) | Partial | ❌ | ✅ v3.1 |
| LLM / prompt-injection red-team | ❌ | ❌ | ✅ v3.1 |
| SBOM (CycloneDX 1.6) + VEX + EPSS | ❌ | ❌ | ✅ v3.1 |
| 100% local — no cloud required | ✅ | ✅ | ✅ |
| SARIF output (GitHub Security, GitLab, Azure) | ✅ | ✅ | ✅ |

---

## Architecture

```
                       ┌─────────────────────────────────────────────────┐
                       │                   bastion                        │
                       │                                                   │
  source code ──────>  │  SAST scanners ──> Reachability ──> Exploit     │ ──> SARIF / HTML / SBOM
  MCP configs ──────>  │  (9 languages,     analysis         Validator   │     / CycloneDX VEX
  IaC files ────────>  │  10+ frameworks)   (live routes)   (2-agent     │
                       │                                     loop)        │
                       │         ML FP filter (58% reduction)             │
                       │         Agent Guardrails (HITL, rate-limit)      │
                       └─────────────────────────────────────────────────┘
```

---

## Features

### SAST — Static Analysis

**OWASP Top 10 (CWE-mapped):**
- SQL Injection (CWE-89), XSS (CWE-79), Command Injection (CWE-78)
- Path Traversal (CWE-22), SSRF (CWE-918), XXE (CWE-611)
- CSRF (CWE-352), Insecure Deserialization (CWE-502)
- Weak Cryptography (CWE-327), Hardcoded Credentials (CWE-798)

**CWE Top 25 2024 extensions:**
- IDOR / Broken Access Control (CWE-863), SSTI (CWE-94), JWT issues (CWE-347)
- ReDoS (CWE-1333), Prototype Pollution (CWE-1321), LDAP Injection (CWE-90)
- Race Conditions / TOCTOU, Integer Overflow (CWE-190), File Upload (CWE-434)

**Framework-specific intelligence:**
- **Django** — ORM safe vs. unsafe methods, `mark_safe()`, `@csrf_exempt`
- **Express.js** — NoSQL injection, prototype pollution, CORS misconfigs
- **React** — `dangerouslySetInnerHTML`, localStorage secrets
- **Spring** — missing `@PreAuthorize`, JPA injection
- **Laravel** — `DB::raw()`, Blade escaping, mass assignment
- **FastAPI, NestJS, Rails, Flask** — framework-aware patterns

### ML False Positive Reduction

Random Forest classifier trained on 9 real-world vulnerable applications (5 languages):

| Language | FP Reduction |
|---|---|
| .NET | 72.4% |
| Python | 66.7% |
| Java | 55.8% |
| Node.js | 47.3% |
| PHP | 47.2% |
| **Overall** | **57.8%** |

> 2.3× better than SonarQube's 25% FP reduction. Runs 100% locally — no API calls.

### Reachability Analysis (v3.1)

For every finding, Bastion answers: *"Can user input actually reach this sink?"*

- Detects live HTTP entrypoints: Flask routes, Django `urlpatterns`, FastAPI decorators, Express `app.get/post`, Spring `@RequestMapping`, Laravel `Route::`, Celery tasks
- BFS through the existing call graph → `REACHABLE` / `UNREACHABLE` / `UNKNOWN`
- Unreachable findings grouped separately in reports — not hidden, but de-prioritised

### Agentic Exploitability Validator (v3.1)

Two-agent loop mirrors [Terra Security's Ambient Agent pattern](https://www.terra.security):

```
Static Finding ──> Reachability filter ──> Orchestrator
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         ▼                     ▼                     ▼
                   Attacker Agent         Sandbox              Judge Agent
                   (crafts PoC)      (executes safely)    (rules verdict)
                         │                                            │
                         └──────────── Guardrails (every action) ────┘
```

- **Attacker Agent** — LLM generates minimal PoC, outputs structured JSON
- **Sandbox** — subprocess with 30s timeout, localhost-only network
- **Judge Agent** — separate context, sees only raw output (no attacker reasoning)
- **Verdict:** `CONFIRMED` / `REFUTED` / `INDETERMINATE` with confidence score + evidence

### Agent Guardrails (v3.1)

Every autonomous action passes through `GuardrailsEngine`:

- **Scope allowlist/denylist** — glob patterns (e.g., block `*.gov`, `prod.*`)
- **Rate limiting** — per-minute and per-target limits
- **Risk tiers** — `READ_ONLY` / `NETWORK_SAFE` auto-approved; `NETWORK_WRITE` / `EXPLOIT` require human approval
- **Dry-run mode** — simulate without executing (default: on)
- **Action ledger** — append-only JSONL audit trail of every agent action

### MCP Security Scanner (v3.0)

Scans Model Context Protocol servers and config files for AI agent attack patterns:

- **Tool Poisoning** — detects hidden malicious instructions in tool descriptions
- **Rug Pull Detection** — SHA256 hash tracking; alerts if tool descriptions change after approval
- **Prompt Injection** — YARA-like patterns for privilege escalation, data exfiltration, meta-instructions
- **Static scan** — detects `mcp.json` / `claude_desktop_config.json` in project tree automatically
- **Optional:** Cisco AI Defense API + LLM-as-judge analyzer

```bash
# Scan MCP server
python3 -m security_audit.scanners.mcp_security_scanner --server https://mcp.example.com/mcp

# Test a tool description
python3 -m security_audit.scanners.mcp_security_scanner --test-pattern "suspicious text..."
```

### IaC Scanner (v3.1)

Covers the cloud attack surface Bastion previously lacked:

**Terraform:** S3 public ACL, security group `0.0.0.0/0` on SSH/RDP, wildcard IAM policies, public RDS instances, hardcoded credentials  
**Kubernetes:** `privileged: true`, `hostNetwork`, root containers, `hostPath` mounts, missing resource limits, dangerous capabilities  
**Dockerfile:** `USER root`, `latest` tag in `FROM`, `ADD` over HTTP, `curl|bash` patterns

### LLM / Prompt-Injection Red-Team Scanner (v3.1)

**Static mode** — scans source code for:
- Unsanitized `{user_input}` in system prompts (OpenAI, Anthropic, LangChain, Ollama)
- Tool-call handlers without action allowlists

**Dynamic mode** — sends ~50 curated payloads to a live LLM endpoint:
- Prompt injection, jailbreak primitives, tool-call poisoning, output-boundary escape
- All requests gated through Guardrails with `EXPLOIT` risk tier

### SBOM + VEX + EPSS (v3.1, CycloneDX 1.6)

- Emits **CycloneDX 1.6 JSON** SBOMs for every scanned project
- Cross-checks against **OSV.dev** (real-time CVE data) with 24h local cache
- Enriches each CVE with **EPSS score** (probability of exploitation in the wild)
- Outputs **VEX statements** (affected / not_affected / fixed / under_investigation)

### Secrets Detection

AWS keys, GitHub tokens, Google API keys, Slack, Stripe, Twilio, SendGrid, JWT tokens, RSA/SSH/PGP private keys, PostgreSQL/MySQL/MongoDB connection strings, and generic API key patterns.

### OWASP ASVS 4.0 Compliance

Full verification across V2–V14 at Level 1, 2, and 3.

---

## Quick Start

```bash
git clone https://github.com/netcuter/bastion.git
cd bastion
pip install -r requirements.txt   # optional — core works on stdlib only

# Basic scan
python3 security_audit_cli.py --path /path/to/project

# With ML false-positive reduction
python3 security_audit_cli.py --path . --ml-fp-reduction

# ASVS Level 2 compliance report
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 2

# Full agentic pipeline (requires local LLM server + target URL)
python3 security_audit_cli.py \
  --path /path/to/code \
  --target-url http://localhost:5000 \
  --validate-exploits \
  --dast \
  --evidence-dir ./evidence/

# Fail CI on HIGH+ findings (SARIF output for GitHub Security)
python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Bastion
        run: python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security.sarif
```

### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
  artifacts:
    reports:
      sast: security.sarif
```

---

## Report Formats

| Format | Use case |
|---|---|
| `json` | Automation, API consumers |
| `html` | Interactive human review |
| `sarif` | GitHub Security, GitLab, Azure DevOps, SonarQube |
| `asvs-json` / `asvs-html` | OWASP ASVS 4.0 compliance audit |
| `cyclonedx` | SBOM for supply-chain / procurement |
| `vex` | VEX statements for triaged vulnerabilities |

---

## Supported Languages & Frameworks

Python (Django, Flask, FastAPI) · JavaScript/TypeScript (Node.js, Express, React, Vue, Angular, NestJS) · PHP (Laravel, Symfony) · Java (Spring, Jakarta EE) · Ruby (Rails) · Go (Gin, Echo, Fiber) · C# (ASP.NET, .NET Core) · Rust (Actix, Rocket) · Kotlin (Spring Boot, Ktor) · Scala (Play, Akka) · Elixir (Phoenix)

IaC: Terraform · Kubernetes · Dockerfile · Docker Compose

---

## Configuration

```json
{
  "scan_options": {
    "max_file_size_mb": 10,
    "excluded_dirs": [".git", "node_modules", "venv"]
  },
  "scanners": {
    "web_vulnerabilities": { "enabled": true },
    "secrets_detector": { "enabled": true },
    "dependency_scanner": { "enabled": true, "severity_threshold": "MEDIUM" },
    "mcp": { "enabled": true }
  }
}
```

---

## Author

**netcuter** — 12 years in web application security

## License

MIT — see [LICENSE](LICENSE)

## Acknowledgments

- OWASP for Top 10 and ASVS documentation
- MITRE for the CWE database
- OSV.dev and FIRST.org for CVE and EPSS data
- The open source security community
