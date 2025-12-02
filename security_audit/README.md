# System Audytu Bezpieczeństwa Kodu Aplikacji Webowych

Kompleksowy system do automatycznego audytu bezpieczeństwa kodu źródłowego aplikacji webowych.

## Funkcje

### 1. Wykrywanie Podatności OWASP Top 10
- **SQL Injection** - wykrywa potencjalne miejsca wstrzykiwania SQL
- **XSS (Cross-Site Scripting)** - identyfikuje niebezpieczne renderowanie danych
- **CSRF** - sprawdza ochronę przed atakami CSRF
- **Command Injection** - wykrywa niebezpieczne wykonywanie poleceń systemowych
- **Path Traversal** - identyfikuje zagrożenia związane z traversal ścieżek
- **Insecure Deserialization** - wykrywa niebezpieczną deserializację
- **Authentication/Authorization** - analizuje mechanizmy uwierzytelniania
- **Sensitive Data Exposure** - wykrywa potencjalne wycieki danych wrażliwych
- **SSRF (Server-Side Request Forgery)** - identyfikuje zagrożenia SSRF
- **XXE (XML External Entity)** - wykrywa podatności XXE

### 2. Wykrywanie Sekretów
- Klucze API
- Hasła w kodzie
- Tokeny uwierzytelniania
- Klucze prywatne
- Connection stringi z danymi dostępowymi

### 3. Analiza Zależności
- Wykrywanie znanych podatności w bibliotekach
- Sprawdzanie wersji zależności
- Rekomendacje aktualizacji

### 4. Analiza Konfiguracji
- Wykrywanie niebezpiecznych konfiguracji
- Sprawdzanie nagłówków bezpieczeństwa
- Analiza polityk CORS

### 5. Raportowanie
- Raport JSON
- Raport HTML
- Raport w formacie SARIF (dla integracji CI/CD)
- Poziomy krytyczności: CRITICAL, HIGH, MEDIUM, LOW, INFO

## Wspierane Języki

- Python
- JavaScript/TypeScript (Node.js)
- PHP
- Java
- Ruby
- Go
- C#/.NET

## Użycie

```bash
# Podstawowe skanowanie
python3 security_audit_cli.py --path /path/to/project

# Skanowanie z określonym formatem raportu
python3 security_audit_cli.py --path /path/to/project --output html --report report.html

# Skanowanie z konfiguracją
python3 security_audit_cli.py --path /path/to/project --config config.json

# Skanowanie tylko określonych typów podatności
python3 security_audit_cli.py --path /path/to/project --scanners sqli,xss,secrets
```

## Architektura

```
security_audit/
├── core/
│   ├── engine.py          # Główny silnik audytu
│   ├── scanner.py         # Interfejs bazowy dla skanerów
│   └── config.py          # System konfiguracji
├── scanners/
│   ├── web_vulnerabilities.py  # Skanery podatności webowych
│   ├── secrets_detector.py     # Wykrywanie sekretów
│   ├── dependency_scanner.py   # Analiza zależności
│   └── config_analyzer.py      # Analiza konfiguracji
├── reporters/
│   ├── json_reporter.py   # Raport JSON
│   ├── html_reporter.py   # Raport HTML
│   └── sarif_reporter.py  # Raport SARIF
└── security_audit_cli.py  # CLI
```

## Instalacja

```bash
pip install -r requirements.txt
```

## Przykład Wyjścia

```json
{
  "scan_date": "2025-11-14T23:30:00Z",
  "project_path": "/path/to/project",
  "total_issues": 15,
  "critical": 3,
  "high": 5,
  "medium": 4,
  "low": 2,
  "info": 1,
  "findings": [...]
}
```

## Integracja CI/CD

System może być łatwo zintegrowany z pipeline'ami CI/CD:

```yaml
# GitHub Actions example
- name: Security Audit
  run: python3 security_audit_cli.py --path . --output sarif --fail-on critical
```

## Licencja

MIT
