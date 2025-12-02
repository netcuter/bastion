# Usage Guide - Security Audit System

## Introduction

The Security Audit System is a tool for automatic vulnerability detection in web application code. The system detects popular threats from the OWASP Top 10 list and other security issues.

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd system

# Install dependencies (optional - system works without additional libraries)
pip install -r requirements.txt
```

## Basic Usage

### 1. Scanning a Project

```bash
# Scan current directory
python3 security_audit_cli.py --path .

# Scan a specific directory
python3 security_audit_cli.py --path /path/to/project
```

### 2. Generating Reports

#### JSON Report (default)
```bash
python3 security_audit_cli.py --path . --output json --report report.json
```

#### HTML Report (visual)
```bash
python3 security_audit_cli.py --path . --output html --report report.html
```

#### SARIF Report (for CI/CD integration)
```bash
python3 security_audit_cli.py --path . --output sarif --report report.sarif
```

#### ASVS Compliance Reports
```bash
# ASVS JSON report with Level 2 compliance
python3 security_audit_cli.py --path . --output asvs-json --asvs-level 2

# ASVS HTML report with Level 3 compliance
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 3
```

### 3. Selecting Scanners

```bash
# Only web vulnerability scanning
python3 security_audit_cli.py --path . --scanners web

# Only secrets detection
python3 security_audit_cli.py --path . --scanners secrets

# Multiple scanners
python3 security_audit_cli.py --path . --scanners web,secrets,dependencies,asvs,multilang

# All scanners (default)
python3 security_audit_cli.py --path .
```

### 4. Custom Configuration

```bash
# Copy example configuration
cp config.example.json config.json

# Edit config.json as needed
# Then use:
python3 security_audit_cli.py --path . --config config.json
```

## Advanced Usage

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Run Security Audit
        run: |
          python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
```

#### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - python3 security_audit_cli.py --path . --output sarif --report security.sarif --fail-on high
  artifacts:
    reports:
      sast: security.sarif
```

### Fail on Severity

Useful in CI/CD - causes the pipeline to fail if it finds issues of a certain severity:

```bash
# Fail only on critical
python3 security_audit_cli.py --path . --fail-on critical

# Fail on critical and high
python3 security_audit_cli.py --path . --fail-on high

# Fail on critical, high and medium
python3 security_audit_cli.py --path . --fail-on medium
```

### ASVS Level Selection

Choose the OWASP ASVS verification level:

```bash
# Level 1 - Opportunistic (basic verification)
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 1

# Level 2 - Standard (for most applications)
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 2

# Level 3 - Advanced (for critical applications)
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 3
```

## Detected Vulnerabilities

### 1. SQL Injection (CWE-89)
- Detects dangerous SQL concatenations
- Checks f-string usage in queries
- Identifies lack of parameterization

### 2. Cross-Site Scripting - XSS (CWE-79)
- innerHTML assignments
- document.write
- dangerouslySetInnerHTML (React)
- v-html (Vue.js)
- Unescaped outputs in templates

### 3. Command Injection (CWE-78)
- os.system with user input
- subprocess.call with improper usage
- shell_exec in PHP

### 4. Path Traversal (CWE-22)
- Detects user input usage in file operations
- Identifies "../" sequences

### 5. SSRF (CWE-918)
- requests.get with user input
- axios/fetch with user-controlled URL

### 6. XXE (CWE-611)
- Unsafe XML parser configuration

### 7. CSRF (CWE-352)
- POST endpoints without visible CSRF protection

### 8. Insecure Deserialization (CWE-502)
- pickle.loads
- yaml.load without SafeLoader
- unserialize in PHP

### 9. Weak Cryptography (CWE-327)
- MD5, SHA1
- DES, RC4

### 10. Hardcoded Credentials (CWE-798)
- Passwords in code
- API keys
- Tokens

### 11. Secrets Detection
- AWS Access Keys
- GitHub Tokens
- Google API Keys
- Slack Tokens
- Stripe Keys
- Database Connection Strings
- Private Keys (RSA, SSH, PGP)
- JWT Tokens

### 12. Dependency Vulnerabilities (CWE-1035)
- Known vulnerabilities in libraries
- Outdated versions
- Unpinned dependencies

### 13. ASVS Compliance Checks
- V2: Authentication Verification
- V3: Session Management
- V6: Cryptography
- V7: Error Handling and Logging
- V8: Data Protection
- V9: Communication Security
- V12: File Upload Security
- V13: API Security
- V14: Configuration

### 14. Multi-Language Security Patterns
Framework-specific checks for:
- **Python**: Django, Flask
- **JavaScript**: Express, React, Vue
- **PHP**: Laravel, Symfony
- **Java**: Spring
- **Ruby**: Rails
- **Go**: Gin, Echo
- **C#**: ASP.NET
- **Rust**: Actix, Rocket
- **Kotlin**: Spring Boot
- **Scala**: Play Framework
- **Elixir**: Phoenix

## Configuration

### Example config.json

```json
{
  "scan_options": {
    "max_file_size_mb": 10,
    "excluded_dirs": [".git", "node_modules", "venv"],
    "excluded_files": ["*.min.js"],
    "included_extensions": [".py", ".js", ".php", ".rb", ".go", ".cs", ".rs", ".kt", ".scala", ".ex"]
  },
  "scanners": {
    "web_vulnerabilities": {
      "enabled": true,
      "checks": {
        "sql_injection": true,
        "xss": true,
        "command_injection": true,
        "path_traversal": true,
        "ssrf": true,
        "xxe": true,
        "csrf": true,
        "insecure_deserialization": true,
        "weak_crypto": true,
        "hardcoded_credentials": true
      }
    },
    "secrets_detector": {
      "enabled": true
    },
    "dependency_scanner": {
      "enabled": true,
      "severity_threshold": "MEDIUM"
    },
    "asvs_scanner": {
      "enabled": true,
      "asvs_level": 2
    },
    "multilanguage_scanner": {
      "enabled": true
    }
  }
}
```

## Interpreting Results

### Severity Levels

- **CRITICAL**: Require immediate attention - can lead to full system compromise
- **HIGH**: Serious threats - require quick remediation
- **MEDIUM**: Medium threats - should be fixed in reasonable time
- **LOW**: Low threats - consider fixing
- **INFO**: Informational - best practices

### Example Result

```json
{
  "scanner": "Web Vulnerability Scanner",
  "severity": "CRITICAL",
  "title": "SQL Injection",
  "description": "Direct string concatenation in SQL query",
  "file_path": "/path/to/file.py",
  "line_number": 42,
  "code_snippet": ">>> 42 | query = 'SELECT * FROM users WHERE id=' + user_id",
  "recommendation": "Use parameterized queries or ORM",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021 - Injection"
}
```

### ASVS Compliance Report

ASVS reports include:
- Compliance percentage by category
- Passed vs. failed requirements
- Detailed requirement mapping
- Remediation guidance

## Best Practices

1. **Regular Scanning**: Run audit on every commit/PR
2. **CI/CD Integration**: Automate scanning in your pipeline
3. **Configuration**: Customize scanners for your project
4. **False Positives**: Review results - not all findings are real vulnerabilities
5. **Updates**: Regularly update the system to the latest version
6. **Manual Review**: Always conduct manual security review for critical code
7. **ASVS Levels**: Choose appropriate ASVS level for your application risk profile

## Supported Languages

The system supports:
- Python
- JavaScript/TypeScript
- PHP
- Java
- Ruby
- Go
- C#/.NET
- Rust
- Kotlin
- Scala
- Elixir

## Limitations

1. The system detects **potential** vulnerabilities - requires manual verification
2. Does not replace manual security review
3. Does not detect logical errors in business logic
4. Known vulnerability database in dependencies requires regular updates
5. Static analysis cannot detect runtime-only issues

## Troubleshooting

### Problem: "Permission denied"
**Solution**: Ensure you have read permissions for files

### Problem: Too many false positives
**Solution**: Adjust configuration, add exclusions

### Problem: No vulnerabilities detected in known vulnerable code
**Solution**: Check if the appropriate scanner is enabled and file is in scan scope

### Problem: ASVS scanner not running
**Solution**: Ensure `--scanners` includes "asvs" or run all scanners (default)

### Problem: Multi-language patterns not detected
**Solution**: Verify file extensions are included in configuration

## Help and Support

```bash
# CLI help
python3 security_audit_cli.py --help

# Verbose mode for debugging
python3 security_audit_cli.py --path . --verbose
```

## CLI Arguments Reference

```
--path PATH              Path to scan (default: current directory)
--config CONFIG          Path to configuration file
--output FORMAT          Output format: json, html, sarif, asvs-json, asvs-html
--report FILE            Report output file path
--scanners SCANNERS      Comma-separated scanner list: web,secrets,dependencies,asvs,multilang
--fail-on SEVERITY       Exit with error on severity: critical, high, medium, low
--asvs-level LEVEL       ASVS verification level: 1, 2, 3
--verbose                Enable verbose output
--help                   Show help message
```
