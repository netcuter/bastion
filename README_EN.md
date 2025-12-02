# Web Application Code Security Audit System

**[English](README_EN.md) | [Polski](README.md)**

Comprehensive system for automatic security auditing of web application source code. Detects OWASP Top 10 vulnerabilities, hardcoded secrets, and dependency issues. **Supports OWASP ASVS 4.0 and multiple programming languages.**

![Version](https://img.shields.io/badge/version-2.5.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![ASVS](https://img.shields.io/badge/ASVS-4.0-purple.svg)
![Checkmarx Level](https://img.shields.io/badge/Checkmarx-Enterprise-orange.svg)
![Detection](https://img.shields.io/badge/detection-42--48%20vulns%2F1K%20LOC-green.svg)
![AI](https://img.shields.io/badge/AI-LM%20Studio%20%28Local%29-purple.svg)
![CWE 2025](https://img.shields.io/badge/CWE%20Top%2025-2025-red.svg)
![SAST](https://img.shields.io/badge/SAST-Bandit%20%7C%20Semgrep%20%7C%20CodeQL-green.svg)
![Languages](https://img.shields.io/badge/languages-10+-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Features

### Web Vulnerability Detection
**Classic OWASP Top 10:**
- **SQL Injection** (CWE-89) - detects dangerous SQL concatenations
- **XSS** (CWE-79) - identifies unsafe data rendering
- **Command Injection** (CWE-78) - detects command execution from user input
- **Path Traversal** (CWE-22) - identifies path traversal threats
- **SSRF** (CWE-918) - detects Server-Side Request Forgery vulnerabilities
- **XXE** (CWE-611) - identifies XML parser issues
- **CSRF** (CWE-352) - checks CSRF attack protection
- **Insecure Deserialization** (CWE-502) - detects unsafe deserialization
- **Weak Cryptography** (CWE-327) - identifies weak cryptographic algorithms
- **Hardcoded Credentials** (CWE-798) - detects hardcoded passwords and keys

**🆕 CWE Top 25 2025 - New Patterns:**
- **Code Injection** (CWE-94) - detects eval(), exec() with user input
- **Clickjacking** (CWE-1021) - missing X-Frame-Options headers
- **Improper Authorization / IDOR** (CWE-863) - broken access control
- **Information Disclosure** (CWE-200) - sensitive information leaks
- **Resource Exhaustion / DoS** (CWE-400) - resource exhaustion attacks
- **Mass Assignment** (CWE-915) - mass assignment without field filtering
- **JWT Security Issues** (CWE-347) - weak secrets, missing verification
- **Improper Privilege Management** (CWE-269) - privilege management flaws
- **Open Redirect** (CWE-601) - redirects to external URLs
- **Server-Side Template Injection** (CWE-94) - SSTI in template engines

**🔬 Professional SAST Tool Patterns (2025):**
- **HTTP Request Timeout** (Bandit B113) - detects requests without timeout
- **Archive Extraction** (Bandit B202) - unsafe extractall()
- **Jinja2 Security** (Bandit B701) - autoescape=False in templates
- **TOCTOU Race Conditions** (CVE-2025) - check-then-use patterns
- **ReDoS** (CWE-1333) - catastrophic backtracking in regex
- **Integer Overflow** (CWE-190) - unchecked int() conversions
- **File Upload** (CWE-434) - missing file validation
- **Advanced Crypto** (Bandit) - DES, RC4, ECB mode, weak random
- **Advanced SQL/NoSQL** (Semgrep) - advanced injection patterns
- **LDAP Injection** (CWE-90) - LDAP search vulnerabilities
- **Prototype Pollution** (CWE-1321) - JavaScript Object.assign

### Secrets Detection
- AWS Access Keys & Secret Keys
- GitHub Tokens (PAT, OAuth)
- Google API Keys
- Slack Tokens & Webhooks
- Stripe API Keys
- Database Connection Strings (PostgreSQL, MySQL, MongoDB)
- Private Keys (RSA, SSH, PGP)
- JWT Tokens
- SendGrid, Twilio, MailChimp API Keys
- Generic API keys, passwords, tokens

### Dependency Analysis
- Detects known vulnerabilities in NPM, Python, PHP packages
- Identifies unpinned versions (wildcards)
- Warnings about outdated libraries

### Reporting
- **JSON** - structured format for automation
- **HTML** - visual report with code highlighting
- **SARIF** - standard for integration with GitHub, GitLab, Azure DevOps
- **ASVS JSON/HTML** - OWASP ASVS 4.0 compliance reports

### 🌍 Multi-Language & Framework Support
- **Python** (Django, Flask)
- **JavaScript/TypeScript** (Node.js, Express, React, Vue, Angular)
- **PHP** (Laravel, Symfony)
- **Java** (Spring, Jakarta EE)
- **Ruby** (Ruby on Rails)
- **Go** (Gin, Echo)
- **C#** (ASP.NET, .NET Core)
- **Rust** (Actix, Rocket)
- **Kotlin** (Spring Boot)
- **Scala** (Play Framework)
- **Elixir** (Phoenix)

### 📋 OWASP ASVS 4.0 Compliance
The system implements **Application Security Verification Standard (ASVS) 4.0** compliance verification:
- **Level 1** - Opportunistic (basic verification)
- **Level 2** - Standard (standard verification for most applications)
- **Level 3** - Advanced (advanced verification for critical applications)

Covers all ASVS categories:
- V2: Authentication
- V3: Session Management
- V4: Access Control
- V5: Validation, Sanitization and Encoding
- V6: Stored Cryptography
- V7: Error Handling and Logging
- V8: Data Protection
- V9: Communication
- V10-V14: and more...

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-audit-system.git
cd security-audit-system

# Optional dependency installation (system works on pure Python 3.8+)
pip install -r requirements.txt
```

## 🎯 Quick Start

```bash
# Scan current directory (all scanners)
python3 security_audit_cli.py --path .

# Scan with HTML report
python3 security_audit_cli.py --path . --output html --report report.html

# ASVS Level 2 compliance report
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 2

# Scan only specific types
python3 security_audit_cli.py --path . --scanners web,secrets,asvs,multilang

# Scan with fail on critical issues (CI/CD)
python3 security_audit_cli.py --path . --fail-on critical
```

## 📖 Documentation

- [Usage Guide (English)](USAGE_GUIDE_EN.md) - detailed documentation
- [Usage Guide (Polish)](USAGE_GUIDE.md) - szczegółowa dokumentacja
- [Security Audit README](security_audit/README.md) - technical details

## 🔍 Usage Example

```bash
$ python3 security_audit_cli.py --path examples --output html

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         Security Audit System for Web Applications           ║
║                         Version 1.0.0                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

[*] Starting security audit of: /home/user/system/examples
[*] Registered scanners: 3
[!] Found 11 issue(s) in examples/vulnerable_code.py
[!] Found 14 issue(s) in examples/vulnerable_code.js
[!] Found 3 issue(s) in examples/package.json

[+] Scan completed in 0.02 seconds
[+] Files scanned: 3
[+] Total findings: 28

================================================================================
SCAN SUMMARY
================================================================================
Files scanned:     3
Lines scanned:     220
Scan duration:     0.02 seconds

Findings by severity:
  CRITICAL:        10
  HIGH:            6
  MEDIUM:          11
  LOW:             1
  INFO:            0
================================================================================
```

## 🛠️ CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Audit
        run: |
          python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
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

## 🎨 Supported Languages & Extensions

- **Python** (.py) - Django, Flask, FastAPI
- **JavaScript/TypeScript** (.js, .ts, .jsx, .tsx) - Node.js, React, Vue, Angular
- **PHP** (.php) - Laravel, Symfony
- **Java** (.java) - Spring, Jakarta EE
- **Ruby** (.rb) - Ruby on Rails
- **Go** (.go) - Gin, Echo, Fiber
- **C#** (.cs) - ASP.NET, .NET Core
- **Rust** (.rs) - Actix, Rocket
- **Kotlin** (.kt) - Spring Boot, Ktor
- **Scala** (.scala) - Play Framework, Akka
- **Elixir** (.ex, .exs) - Phoenix
- **HTML/XML** (.html, .htm, .xml)
- **Config Files** (.yml, .yaml, .json, .env)

## 📊 Report Formats

### JSON Report
Structured format ideal for automation and integration with other tools.

### HTML Report
Visual, interactive report with:
- Color-coded severity highlighting
- Code snippets with context
- Remediation recommendations
- Statistics and summary

### SARIF Report
OASIS standard for static analysis results - integrates with:
- GitHub Security
- Azure DevOps
- GitLab Security Dashboard
- SonarQube

## ⚙️ Configuration

Create `config.json` to customize scanning:

```json
{
  "scan_options": {
    "max_file_size_mb": 10,
    "excluded_dirs": [".git", "node_modules", "venv"],
    "included_extensions": [".py", ".js", ".php"]
  },
  "scanners": {
    "web_vulnerabilities": {
      "enabled": true,
      "checks": {
        "sql_injection": true,
        "xss": true,
        "command_injection": true
      }
    },
    "secrets_detector": {
      "enabled": true
    },
    "dependency_scanner": {
      "enabled": true,
      "severity_threshold": "MEDIUM"
    }
  }
}
```

Use: `python3 security_audit_cli.py --path . --config config.json`

## 🏗️ Architecture

```
security-audit-system/
├── security_audit/
│   ├── core/
│   │   ├── engine.py          # Main audit engine
│   │   ├── scanner.py         # Base interface
│   │   └── config.py          # Configuration system
│   ├── scanners/
│   │   ├── web_vulnerabilities.py
│   │   ├── secrets_detector.py
│   │   └── dependency_scanner.py
│   └── reporters/
│       ├── json_reporter.py
│       ├── html_reporter.py
│       └── sarif_reporter.py
├── security_audit_cli.py      # CLI interface
└── examples/                   # Example vulnerable code
```

## 🔐 Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Critical threats requiring immediate action | Fix ASAP |
| **HIGH** | Serious vulnerabilities | Fix within a week |
| **MEDIUM** | Medium threats | Plan remediation |
| **LOW** | Low threats | Consider fixing |
| **INFO** | Informational / best practices | Good practice |

## 📝 Examples

In the `examples/` directory you'll find example vulnerable code:
- `vulnerable_code.py` - Python/Flask with vulnerabilities
- `vulnerable_code.js` - JavaScript/Node.js with vulnerabilities
- `package.json` - Example with vulnerable dependencies

## 🤝 Contributing

Contributions are welcome! To add a new scanner or improve an existing one:

1. Fork the repository
2. Create a branch (`git checkout -b feature/new-scanner`)
3. Commit changes (`git commit -am 'Add new scanner'`)
4. Push to branch (`git push origin feature/new-scanner`)
5. Create Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## ⚠️ Limitations

- The system detects **potential** vulnerabilities - requires verification
- Does not replace manual security review
- Does not detect business logic errors
- Vulnerability database requires updates

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 👤 Author

netcuter

## 🙏 Acknowledgments

- OWASP for Top 10 documentation
- MITRE for CWE database
- Open source community for inspiration

---

**Note**: This system is a helper tool. Always conduct a professional security audit before deploying production applications.
