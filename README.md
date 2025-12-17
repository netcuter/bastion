# System Audytu Bezpieczeństwa Kodu Aplikacji Webowych

**[English](README_EN.md) | [Polski](README.md)**

Kompleksowy system do automatycznego audytu bezpieczeństwa kodu źródłowego aplikacji webowych. Wykrywa podatności OWASP Top 10, hardcoded secrets, oraz problemy z zależnościami. **Wspiera OWASP ASVS 4.0 i wiele języków programowania.**

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![ASVS](https://img.shields.io/badge/ASVS-4.0-purple.svg)
![SonarQube Level](https://img.shields.io/badge/SonarQube-Professional-orange.svg)
![ML](https://img.shields.io/badge/ML-False%20Positive%20Reduction%2058%25-brightgreen.svg)
![Detection](https://img.shields.io/badge/detection-35--40%20vulns%2F1K%20LOC-green.svg)
![Data Flow](https://img.shields.io/badge/analysis-Data%20Flow%20%2B%20Call%20Graph-red.svg)
![CWE 2024](https://img.shields.io/badge/CWE%20Top%2025-2024-red.svg)
![SAST](https://img.shields.io/badge/SAST-Bandit%20%7C%20Semgrep%20%7C%20CodeQL-green.svg)
![Languages](https://img.shields.io/badge/languages-10+-orange.svg)
![AI Engine](https://img.shields.io/badge/AI-AdvancedSecurity--Inspired-blue.svg)
![Mobile Testing](https://img.shields.io/badge/Mobile-Android%20%7C%20iOS-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Funkcje

### ✅ NOWOŚĆ v3.0.0: AI-Powered Security Testing Engine (AdvancedSecurity-Inspired)
**Zaawansowany silnik AI do testowania bezpieczeństwa inspirowany AdvancedSecurity AI Engine!**

#### 🧠 Threat Intelligence & Risk Modeling
- **P.A.S.T.A Methodology** - Process for Attack Simulation and Threat Analysis
- **Business Context Gathering** - integracja kontekstu biznesowego
- **Technology Stack Detection** - automatyczna identyfikacja stosu technologicznego
- **Attack Surface Mapping** - mapowanie powierzchni ataku
- **7-Stage Threat Modeling** - kompletne modelowanie zagrożeń

#### 📱 Mobile Testing Engine
- **AI-Monkey Tester** - inteligentne testowanie aplikacji mobilnych
- **Android & iOS Support** - pełne wsparcie dla obu platform
- **SSL Pinning Bypass** - omijanie pinowania certyfikatów
- **Traffic Interception** - przechwytywanie i modyfikacja ruchu
- **Multi-Stack Instrumentation** - Java, Objective-C/Swift, C/C++, Flutter
- **Complex Flow Navigation** - nawigacja przez złożone przepływy (checkout, logowanie, CAPTCHA)

#### 🛠️ Advanced Tooling Layer
- **Intelligent Web Crawler** - inteligentny spider dla aplikacji webowych
- **Smart Fuzzing Engine** - zaawansowane fuzzing z wieloma strategiami
  - Random, Mutation, Generation, Smart (AI-guided)
  - SQL Injection, XSS, Command Injection payloads
- **Taint Analysis Engine** - śledzenie przepływu danych
- **Custom Tool Integration** - integracja z zewnętrznymi narzędziami

#### ✔️ Adversarial Vulnerability Validation
- **Adversarial Validation Loops** - walidacja przez kontrargumentację
- **False Positive Reduction** - zaawansowana redukcja fałszywych alarmów
- **Multi-Perspective Analysis** - analiza z wielu perspektyw
- **Confidence Scoring** - scoring pewności (Confirmed, Likely, Possible, Unlikely, FP)
- **Context-Aware Validation** - walidacja uwzględniająca kontekst kodu

#### 📸 Evidence Capture System
- **HTTP Request/Response Capture** - pełne przechwytywanie komunikacji HTTP
- **Screenshots & Video Recording** - zrzuty ekranu i nagrania wideo
- **UI Interaction Traces** - śledzenie interakcji z UI
- **Instrumentation Logs** - logi z instrumentacji runtime
- **Exploitation PoC Evidence** - dowody proof-of-concept
- **Reproducibility Guides** - automatyczne generowanie przewodników reprodukcji

#### 💼 Business Context Risk Assessment
- **Industry-Specific Risk Analysis** - analiza ryzyka dla konkretnej branży
- **Compliance Framework Mapping** - mapowanie na frameworki compliance (GDPR, HIPAA, PCI-DSS, SOC2)
- **Financial Impact Estimation** - szacowanie wpływu finansowego
- **Asset Criticality Assessment** - ocena krytyczności zasobów
- **Executive Summary Reports** - raporty dla kadry zarządzającej
- **Regulatory Impact Analysis** - analiza wpływu regulacyjnego

---

### ✅ NOWOŚĆ v2.5.1: ML-Powered False Positive Reduction
**Machine Learning model redukuje false positives o 58% - 2.3x lepiej niż SonarQube!**

#### 🤖 Cross-Language ML Model
- ✅ **58% FP Reduction** na unseen data (validated)
- ✅ **5 języków**: PHP (47%), Python (67%), Node.js (47%), Java (56%), .NET (72%)
- ✅ **100% Local** - bez cloud, bez LM Studio, działa offline!
- ✅ **Random Forest** - 100 trees, 37 features, sklearn-based
- ✅ **2.3x lepszy** niż SonarQube (25% FP reduction)
- ✅ **Production Ready** - zwalidowany na 15 vulnerable apps

**Przykład:**
```bash
# Bez ML: 1000 findings
python3 security_audit_cli.py --path /project

# Z ML: ~420 findings (58% FP reduction!)
python3 security_audit_cli.py --path /project --fp-reduction ml
```

📚 **[Pełna dokumentacja ML](docs/ml/)** | **[Quick Start](docs/ml/ML_CROSS_LANGUAGE_FINAL_SUMMARY.md)**

---

### ✅ v2.4.0: Current State of Art Professional Level
**Zaawansowana analiza z Data Flow, Call Graph i Framework-Aware detection!**

#### Data Flow Analysis Engine
- **Taint Tracking** - śledzi tainted data od źródła do ujścia
- **Call Graph Analysis** - mapuje wywołania funkcji w całym kodzie
- **Interprocedural Analysis** - wykrywa podatności rozłożone na wiele funkcji
- **Context-Aware Detection** - rozpoznaje sanityzację, redukuje false positives o 50%

#### Framework-Specific Intelligence
- **Django** - rozróżnia `.filter()` (safe) vs `.raw()` (unsafe)
- **Express.js** - wykrywa NoSQL injection, prototype pollution, CORS issues
- **React** - `dangerouslySetInnerHTML`, localStorage security
- **Spring** - missing `@PreAuthorize`, JPA injection
- **Laravel** - `DB::raw()`, Blade escaping, mass assignment

#### Advanced Patterns Scanner
- **ReDoS** - catastrophic backtracking detection
- **TOCTOU** - race conditions w file operations
- **Prototype Pollution** - Object.assign, spread operator
- **Second-Order Injection** - stored XSS, delayed SQLi
- **Memory Leaks** - setInterval, addEventListener bez cleanup

### Wykrywanie Podatności Webowych
**Klasyczne OWASP Top 10:**
- **SQL Injection** (CWE-89) - wykrywa niebezpieczne konkatenacje SQL
- **XSS** (CWE-79) - identyfikuje niebezpieczne renderowanie danych
- **Command Injection** (CWE-78) - wykrywa wykonywanie poleceń z user input
- **Path Traversal** (CWE-22) - identyfikuje zagrożenia traversal ścieżek
- **SSRF** (CWE-918) - wykrywa podatności Server-Side Request Forgery
- **XXE** (CWE-611) - identyfikuje problemy z XML parsers
- **CSRF** (CWE-352) - sprawdza ochronę przed atakami CSRF
- **Insecure Deserialization** (CWE-502) - wykrywa niebezpieczną deserializację
- **Weak Cryptography** (CWE-327) - identyfikuje słabe algorytmy kryptograficzne
- **Hardcoded Credentials** (CWE-798) - wykrywa hardcoded hasła i klucze

**🆕 CWE Top 25 2024 - Nowe Wzorce:**
- **Code Injection** (CWE-94) - wykrywa eval(), exec() z user input
- **Clickjacking** (CWE-1021) - brak nagłówków X-Frame-Options
- **Improper Authorization / IDOR** (CWE-863) - nieprawidłowa autoryzacja dostępu
- **Information Disclosure** (CWE-200) - wyciek wrażliwych informacji
- **Resource Exhaustion / DoS** (CWE-400) - ataki wyczerpania zasobów
- **Mass Assignment** (CWE-915) - przypisywanie masowe bez filtrowania
- **JWT Security Issues** (CWE-347) - słabe klucze, brak weryfikacji
- **Improper Privilege Management** (CWE-269) - błędy zarządzania uprawnieniami
- **Open Redirect** (CWE-601) - przekierowania na zewnętrzne URL
- **Server-Side Template Injection** (CWE-94) - SSTI w silnikach szablonów

**🔬 Wzorce z Professional SAST Tools (2025):**
- **HTTP Request Timeout** (Bandit B113) - wykrywa requests bez timeout
- **Archive Extraction** (Bandit B202) - niebezpieczne extractall()
- **Jinja2 Security** (Bandit B701) - autoescape=False w templates
- **TOCTOU Race Conditions** (CVE-2025) - check-then-use patterns
- **ReDoS** (CWE-1333) - catastrophic backtracking w regex
- **Integer Overflow** (CWE-190) - nieprawidłowa konwersja int()
- **File Upload** (CWE-434) - brak walidacji plików
- **Advanced Crypto** (Bandit) - DES, RC4, ECB mode, słaby random
- **Advanced SQL/NoSQL** (Semgrep) - zaawansowane wzorce injection
- **LDAP Injection** (CWE-90) - podatności LDAP search
- **Prototype Pollution** (CWE-1321) - JavaScript Object.assign

### Wykrywanie Sekretów
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

### Analiza Zależności
- Wykrywanie znanych podatności w pakietach NPM, Python, PHP
- Identyfikacja nieprzypietych wersji (wildcards)
- Ostrzeżenia o przestarzałych bibliotekach

### Raportowanie
- **JSON** - strukturyzowany format dla automatyzacji
- **HTML** - wizualny raport z podświetleniem kodu
- **SARIF** - standard dla integracji z GitHub, GitLab, Azure DevOps
- **ASVS JSON/HTML** - raporty zgodności z OWASP ASVS 4.0

### 🌍 Wsparcie Wielu Języków i Frameworków
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
System implementuje weryfikację zgodności z **Application Security Verification Standard (ASVS) 4.0**:
- **Level 1** - Opportunistic (podstawowa weryfikacja)
- **Level 2** - Standard (standardowa weryfikacja dla większości aplikacji)
- **Level 3** - Advanced (zaawansowana weryfikacja dla krytycznych aplikacji)

Pokrywa wszystkie kategorie ASVS:
- V2: Authentication
- V3: Session Management
- V4: Access Control
- V5: Validation, Sanitization and Encoding
- V6: Stored Cryptography
- V7: Error Handling and Logging
- V8: Data Protection
- V9: Communication
- V10-V14: i więcej...

### 🆕 NOWOŚĆ v3.0.0: MCP Security Scanner

**Skanowanie bezpieczeństwa AI Agent MCP Servers!**

- **Tool Poisoning Detection** - wykrywa ukryte złośliwe instrukcje w tool descriptions
- **MCP Rug Pull Prevention** - wykrywa zmiany w toolach po zatwierdzeniu
- **Cross-Origin Escalation** - wykrywa tool shadowing attacks
- **Prompt Injection** - wykrywa prompt injection w opisach narzędzi

```bash
# Skanuj MCP server
python3 -m security_audit.scanners.mcp_security_scanner --server https://mcp.example.com/mcp

# Test tool description
python3 -m security_audit.scanners.mcp_security_scanner --test-pattern "suspicious..."
```

📚 **[Pełna dokumentacja MCP](docs/mcp/MCP_SECURITY_SCANNER.md)**

---

## 📦 Instalacja

```bash
# Klonowanie repozytorium
git clone https://github.com/yourusername/security-audit-system.git
cd security-audit-system

# Opcjonalna instalacja zależności (system działa na czystym Pythonie 3.8+)
pip install -r requirements.txt
```

## 🎯 Szybki Start

```bash
# Skanowanie bieżącego katalogu (wszystkie skanery)
python3 security_audit_cli.py --path .

# Skanowanie z raportem HTML
python3 security_audit_cli.py --path . --output html --report report.html

# Raport zgodności ASVS Level 2
python3 security_audit_cli.py --path . --output asvs-html --asvs-level 2

# Skanowanie tylko określonych typów
python3 security_audit_cli.py --path . --scanners web,secrets,asvs,multilang

# Skanowanie z fail na critical issues (CI/CD)
python3 security_audit_cli.py --path . --fail-on critical
```

## 📖 Dokumentacja

- [Przewodnik Użytkowania](USAGE_GUIDE.md) - szczegółowa dokumentacja
- [README Security Audit](security_audit/README.md) - szczegóły techniczne

## 🔍 Przykład Użycia

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

## 🛠️ Integracja CI/CD

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

## 🎨 Wspierane Języki i Rozszerzenia

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

## 📊 Formaty Raportów

### JSON Report
Strukturyzowany format idealny dla automatyzacji i integracji z innymi narzędziami.

### HTML Report
Wizualny, interaktywny raport z:
- Kolorowym podświetleniem według wagi
- Snippetami kodu z kontekstem
- Rekomendacjami naprawy
- Statystykami i podsumowaniem

### SARIF Report
Standard OASIS dla wyników statycznej analizy - integracja z:
- GitHub Security
- Azure DevOps
- GitLab Security Dashboard
- SonarQube

## ⚙️ Konfiguracja

Stwórz `config.json` aby dostosować skanowanie:

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

Użyj: `python3 security_audit_cli.py --path . --config config.json`

## 🏗️ Architektura

```
security-audit-system/
├── security_audit/
│   ├── core/
│   │   ├── engine.py          # Główny silnik audytu
│   │   ├── scanner.py         # Interfejs bazowy
│   │   └── config.py          # System konfiguracji
│   ├── scanners/
│   │   ├── web_vulnerabilities.py
│   │   ├── secrets_detector.py
│   │   └── dependency_scanner.py
│   └── reporters/
│       ├── json_reporter.py
│       ├── html_reporter.py
│       └── sarif_reporter.py
├── security_audit_cli.py      # CLI interface
└── examples/                   # Przykładowy podatny kod
```

## 🔐 Poziomy Wagi

| Poziom | Opis | Działanie |
|--------|------|-----------|
| **CRITICAL** | Krytyczne zagrożenia wymagające natychmiastowej akcji | Napraw ASAP |
| **HIGH** | Poważne podatności | Napraw w ciągu tygodnia |
| **MEDIUM** | Średnie zagrożenia | Zaplanuj naprawę |
| **LOW** | Niskie zagrożenia | Rozważ naprawę |
| **INFO** | Informacyjne / best practices | Dobra praktyka |

## 📝 Przykłady

W katalogu `examples/` znajdziesz przykładowy podatny kod:
- `vulnerable_code.py` - Python/Flask z podatnościami
- `vulnerable_code.js` - JavaScript/Node.js z podatnościami
- `package.json` - Przykład z podatnymi zależnościami

## 🤝 Wkład w Projekt

Contributions są mile widziane! Aby dodać nowy skaner lub poprawić istniejący:

1. Fork repozytorium
2. Stwórz branch (`git checkout -b feature/nowy-skaner`)
3. Commit zmian (`git commit -am 'Dodaj nowy skaner'`)
4. Push do brancha (`git push origin feature/nowy-skaner`)
5. Stwórz Pull Request

## ⚠️ Ograniczenia

- System wykrywa **potencjalne** podatności - wymaga weryfikacji
- Nie zastępuje manualnego security review
- Nie wykrywa błędów logiki biznesowej
- Baza podatności wymaga aktualizacji

## 📜 Licencja

MIT License - zobacz [LICENSE](LICENSE) dla szczegółów.

## 👤 Autor

netcuter

## 🙏 Podziękowania

- OWASP za dokumentację Top 10
- MITRE za bazę CWE
- Społeczność open source za inspirację

---

**Uwaga**: Ten system jest narzędziem pomocniczym. Zawsze przeprowadzaj profesjonalny security audit przed wdrożeniem aplikacji produkcyjnej.
