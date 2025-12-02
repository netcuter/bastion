# Przewodnik Użytkowania - System Audytu Bezpieczeństwa

## Wprowadzenie

System Audytu Bezpieczeństwa to narzędzie do automatycznego wykrywania podatności w kodzie aplikacji webowych. System wykrywa popularne zagrożenia z listy OWASP Top 10 oraz inne problemy bezpieczeństwa.

## Instalacja

```bash
# Klonowanie repozytorium
git clone <repository-url>
cd system

# Instalacja zależności (opcjonalnie - system działa bez dodatkowych bibliotek)
pip install -r requirements.txt
```

## Podstawowe Użycie

### 1. Skanowanie Projektu

```bash
# Skanowanie bieżącego katalogu
python3 security_audit_cli.py --path .

# Skanowanie określonego katalogu
python3 security_audit_cli.py --path /path/to/project
```

### 2. Generowanie Raportów

#### Raport JSON (domyślny)
```bash
python3 security_audit_cli.py --path . --output json --report report.json
```

#### Raport HTML (wizualny)
```bash
python3 security_audit_cli.py --path . --output html --report report.html
```

#### Raport SARIF (do integracji CI/CD)
```bash
python3 security_audit_cli.py --path . --output sarif --report report.sarif
```

### 3. Wybór Skanerów

```bash
# Tylko skanowanie podatności webowych
python3 security_audit_cli.py --path . --scanners web

# Tylko wykrywanie sekretów
python3 security_audit_cli.py --path . --scanners secrets

# Wiele skanerów
python3 security_audit_cli.py --path . --scanners web,secrets,dependencies
```

### 4. Własna Konfiguracja

```bash
# Skopiuj przykładową konfigurację
cp config.example.json config.json

# Edytuj config.json według potrzeb
# Następnie użyj:
python3 security_audit_cli.py --path . --config config.json
```

## Zaawansowane Użycie

### Integracja CI/CD

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

Przydatne w CI/CD - sprawia, że pipeline kończy się błędem jeśli znajdzie problemy o określonej wadze:

```bash
# Błąd tylko dla krytycznych
python3 security_audit_cli.py --path . --fail-on critical

# Błąd dla krytycznych i wysokich
python3 security_audit_cli.py --path . --fail-on high

# Błąd dla krytycznych, wysokich i średnich
python3 security_audit_cli.py --path . --fail-on medium
```

## Wykrywane Podatności

### 1. SQL Injection (CWE-89)
- Wykrywa niebezpieczne konkatenacje SQL
- Sprawdza używanie f-stringów w zapytaniach
- Identyfikuje brak parametryzacji

### 2. Cross-Site Scripting - XSS (CWE-79)
- innerHTML assignments
- document.write
- dangerouslySetInnerHTML (React)
- v-html (Vue.js)
- Nieescapowane outputy w szablonach

### 3. Command Injection (CWE-78)
- os.system z user input
- subprocess.call z niewłaściwym użyciem
- shell_exec w PHP

### 4. Path Traversal (CWE-22)
- Wykrywa użycie user input w operacjach plikowych
- Identyfikuje sekwencje "../"

### 5. SSRF (CWE-918)
- requests.get z user input
- axios/fetch z user-controlled URL

### 6. XXE (CWE-611)
- Niebezpieczna konfiguracja parserów XML

### 7. CSRF (CWE-352)
- Endpointy POST bez widocznej ochrony CSRF

### 8. Insecure Deserialization (CWE-502)
- pickle.loads
- yaml.load bez SafeLoader
- unserialize w PHP

### 9. Weak Cryptography (CWE-327)
- MD5, SHA1
- DES, RC4

### 10. Hardcoded Credentials (CWE-798)
- Hasła w kodzie
- API keys
- Tokeny

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
- Znane podatności w bibliotekach
- Nieaktualne wersje
- Nieprzypięte zależności

## Konfiguracja

### Przykład config.json

```json
{
  "scan_options": {
    "max_file_size_mb": 10,
    "excluded_dirs": [".git", "node_modules", "venv"],
    "excluded_files": ["*.min.js"],
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
    }
  }
}
```

## Interpretacja Wyników

### Poziomy Krytyczności

- **CRITICAL**: Wymagają natychmiastowej uwagi - mogą prowadzić do pełnego przejęcia systemu
- **HIGH**: Poważne zagrożenia - wymagają szybkiej naprawy
- **MEDIUM**: Średnie zagrożenia - powinny być naprawione w rozsądnym czasie
- **LOW**: Niskie zagrożenia - należy rozważyć naprawę
- **INFO**: Informacyjne - dobre praktyki

### Przykład Wyniku

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

## Najlepsze Praktyki

1. **Regularne Skanowanie**: Uruchamiaj audyt przy każdym commicie/PR
2. **Integracja CI/CD**: Automatyzuj skanowanie w pipeline
3. **Konfiguracja**: Dostosuj skanery do swojego projektu
4. **False Positives**: Sprawdzaj wyniki - nie wszystkie wykrycia to prawdziwe podatności
5. **Aktualizacje**: Regularnie aktualizuj system do najnowszej wersji

## Wsparcie Języków

System wspiera:
- Python
- JavaScript/TypeScript
- PHP
- Java
- Ruby
- Go
- C#/.NET

## Ograniczenia

1. System wykrywa **potencjalne** podatności - wymaga manualnej weryfikacji
2. Nie zastępuje manualnego security review
3. Nie wykrywa logicznych błędów w logice biznesowej
4. Baza znanych podatności w zależnościach wymaga regularnych aktualizacji

## Troubleshooting

### Problem: "Permission denied"
**Rozwiązanie**: Upewnij się, że masz uprawnienia do odczytu plików

### Problem: Za dużo false positives
**Rozwiązanie**: Dostosuj konfigurację, dodaj wykluczenia

### Problem: Brak wykrytych podatności w znanym podatnym kodzie
**Rozwiązanie**: Sprawdź czy odpowiedni skaner jest włączony i czy plik jest w zakresie skanowania

## Pomoc i Wsparcie

```bash
# Pomoc CLI
python3 security_audit_cli.py --help

# Verbose mode dla debugowania
python3 security_audit_cli.py --path . --verbose
```
