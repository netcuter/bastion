# Contributing to Security Audit System

Dziękujemy za zainteresowanie współtworzeniem Security Audit System! 🎉

## 🤝 Jak możesz pomóc

### 1. Zgłaszanie Błędów
- Użyj GitHub Issues
- Opisz problem szczegółowo
- Dodaj przykładowy kod i output
- Podaj wersję Python i systemu operacyjnego

### 2. Propozycje Nowych Funkcji
- Otwórz Issue z tagiem `enhancement`
- Opisz use case
- Wyjaśnij dlaczego funkcja jest potrzebna

### 3. Pull Requests

#### Proces
1. **Fork** repozytorium
2. **Clone** swojego forka
3. **Stwórz branch** dla zmian
   ```bash
   git checkout -b feature/nowa-funkcja
   ```
4. **Wprowadź zmiany**
5. **Commit** z opisową wiadomością
6. **Push** do swojego forka
7. **Otwórz Pull Request**

#### Standardy Kodu
```python
# Używaj docstrings
def scan_file(file_path: str) -> List[Finding]:
    """
    Scan file for security vulnerabilities

    Args:
        file_path: Path to file to scan

    Returns:
        List of findings
    """
    pass

# Type hints
# PEP 8 compliance
# Descriptive variable names
```

### 4. Dodawanie Nowych Skanerów

#### Przykład
```python
from ..core.scanner import BaseScanner, Finding, Severity

class MyLanguageScanner(BaseScanner):
    def get_name(self) -> str:
        return "My Language Scanner"

    def get_description(self) -> str:
        return "Scans MyLanguage code for vulnerabilities"

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

### 5. Dodawanie Nowych Języków

Aby dodać wsparcie dla nowego języka:

1. **Dodaj rozszerzenie** w `security_audit/core/config.py`:
   ```python
   "included_extensions": [".py", ".js", ".mylang"]
   ```

2. **Stwórz wzorce** w `MultiLanguageScanner`:
   ```python
   self.mylang_patterns = {
       'sql_injection': [
           (r'pattern_here', 'Description'),
       ]
   }
   ```

3. **Dodaj metodę skanowania**:
   ```python
   def _scan_mylang(self, file_path: str, lines: List[str]) -> List[Finding]:
       findings = []
       # Scanning logic
       return findings
   ```

4. **Dodaj do scan()**: Rozpoznaj rozszerzenie i wywołaj metodę

### 6. Testy

Przed submitem PR:
```bash
# Test na przykładach
python3 security_audit_cli.py --path examples

# Sprawdź czy wszystkie skanery działają
python3 security_audit_cli.py --path examples --scanners web,secrets,dependencies,asvs,multilang

# Wygeneruj wszystkie formaty raportów
python3 security_audit_cli.py --path examples --output html
python3 security_audit_cli.py --path examples --output sarif
python3 security_audit_cli.py --path examples --output asvs-html
```

### 7. Dokumentacja

Przy dodawaniu funkcji:
- Aktualizuj README.md
- Dodaj przykłady użycia
- Dokumentuj parametry konfiguracji
- Aktualizuj USAGE_GUIDE.md jeśli potrzeba

## 📋 Checklist PR

- [ ] Kod działa i przechodzi testy
- [ ] Dodano docstrings
- [ ] Używane type hints
- [ ] PEP 8 compliant
- [ ] Zaktualizowana dokumentacja
- [ ] Dodano przykłady jeśli applicable
- [ ] Commit messages są opisowe

## 🐛 Zgłaszanie Podatności Bezpieczeństwa

**Nie otwieraj publicznie issues dla podatności!**

Zamiast tego:
1. Wyślij email do maintainerów
2. Opisz podatność
3. Poczekaj na odpowiedź przed publicznym disclosure

## 📝 Przykładowe Commit Messages

```
✅ Dobre:
- Add Rust security patterns for Actix framework
- Fix XSS detection in JavaScript scanner
- Update ASVS requirements to include V14.5

❌ Złe:
- fix bug
- update code
- changes
```

## 💡 Pomysły na Kontrybuowanie

- **Nowe języki**: Swift, Dart, Haskell
- **Nowe frameworki**: FastAPI, NestJS, Gin
- **Nowe podatności**: LDAP Injection, Template Injection
- **Tłumaczenia**: English README, Chinese docs
- **Performance**: Optymalizacja skanowania dużych projektów
- **Integration**: GitHub Actions, GitLab CI templates

## 🌟 Maintainerzy

Projekt jest otwarty na nowych maintainerów. Jeśli aktywnie kontrybuujesz, możesz zostać maintainerem!

## 📜 Code of Conduct

Przestrzegamy [Code of Conduct](CODE_OF_CONDUCT.md). Szanujmy się wzajemnie!

## ❓ Pytania?

- Otwórz Discussion na GitHubie
- Zadaj pytanie w Issue z tagiem `question`

---

**Dziękujemy za wkład w bezpieczeństwo aplikacji webowych! 🔐**
