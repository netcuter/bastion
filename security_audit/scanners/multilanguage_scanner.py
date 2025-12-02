"""
Multi-Language Web Framework Security Scanner
Supports: Ruby/Rails, Go, C#/ASP.NET, Rust, Kotlin, Scala, Elixir/Phoenix, and more
"""
import re
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity


class MultiLanguageScanner(BaseScanner):
    """Scanner for multiple web frameworks and languages"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Multi-Language Framework Scanner"

    def get_description(self) -> str:
        return "Security scanner for Ruby/Rails, Go, C#, Rust, Kotlin, Scala, and other web frameworks"

    def _init_patterns(self):
        """Initialize language-specific patterns"""

        # ==== RUBY / RAILS ====
        self.ruby_patterns = {
            'sql_injection': [
                (r'\.where\s*\(\s*["\'].*?#\{.*?\}', 'SQL injection via string interpolation in ActiveRecord'),
                (r'\.find_by_sql\s*\(\s*["\'].*?#\{', 'find_by_sql with string interpolation'),
                (r'ActiveRecord::Base\.connection\.execute\s*\(.*?#\{', 'Raw SQL with interpolation'),
            ],
            'xss': [
                (r'\.html_safe\b', 'html_safe bypasses XSS protection'),
                (r'raw\s*\(', 'raw() bypasses HTML escaping'),
                (r'<%=\s*(?!h\s)', 'Unescaped ERB output (use <%=h or <%= sanitize)'),
            ],
            'command_injection': [
                (r'system\s*\(.*?params\[', 'Command injection via params'),
                (r'`.*?#\{.*?params', 'Backtick command execution with params'),
                (r'exec\s*\(.*?params', 'exec with user input'),
                (r'%x\{.*?params', '%x command execution with params'),
            ],
            'mass_assignment': [
                (r'\.new\s*\(params\[', 'Mass assignment vulnerability'),
                (r'\.create\s*\(params\[', 'Mass assignment in create'),
                (r'\.update\s*\(params\[', 'Mass assignment in update'),
            ],
            'deserialization': [
                (r'YAML\.load\s*\(', 'Unsafe YAML deserialization (use YAML.safe_load)'),
                (r'Marshal\.load\s*\(', 'Unsafe Marshal deserialization'),
            ],
            'csrf': [
                (r'protect_from_forgery.*?:null_session', 'Weak CSRF protection'),
                (r'skip_before_action\s+:verify_authenticity_token', 'CSRF protection disabled'),
            ],
        }

        # ==== GO ====
        self.go_patterns = {
            'sql_injection': [
                (r'db\.Query\s*\(\s*fmt\.Sprintf', 'SQL injection via fmt.Sprintf'),
                (r'db\.Exec\s*\(\s*"[^"]*"\s*\+', 'SQL injection via string concatenation'),
                (r'\.QueryRow\s*\(\s*.*?\+\s*', 'SQL query with concatenation'),
            ],
            'command_injection': [
                (r'exec\.Command\s*\(.*?req\.', 'Command injection from HTTP request'),
                (r'exec\.CommandContext\s*\(.*?r\.Form', 'Command execution with form data'),
            ],
            'path_traversal': [
                (r'os\.Open\s*\(.*?req\.(URL|Form)', 'Path traversal in file operations'),
                (r'ioutil\.ReadFile\s*\(.*?r\.URL\.Query', 'File read with user input'),
            ],
            'weak_crypto': [
                (r'md5\.New\(\)', 'MD5 usage detected'),
                (r'sha1\.New\(\)', 'SHA1 usage detected'),
                (r'des\.NewCipher', 'DES cipher usage'),
            ],
            'insecure_tls': [
                (r'InsecureSkipVerify\s*:\s*true', 'TLS certificate validation disabled'),
                (r'tls\.Config.*?InsecureSkipVerify', 'Insecure TLS configuration'),
            ],
        }

        # ==== C# / ASP.NET ====
        self.csharp_patterns = {
            'sql_injection': [
                (r'SqlCommand\s*\([^)]*?\+[^)]*?\)', 'SQL injection via concatenation'),
                (r'ExecuteReader\s*\([^)]*?Request\.', 'SQL query from Request object'),
                (r'\.Query\s*\(\s*\$"', 'String interpolation in SQL query'),
            ],
            'xss': [
                (r'@Html\.Raw\s*\(', 'Html.Raw bypasses encoding'),
                (r'Response\.Write\s*\(Request\.', 'Direct output of request data'),
                (r'InnerHtml\s*=.*?Request\.', 'InnerHtml with user input'),
            ],
            'command_injection': [
                (r'Process\.Start\s*\(.*?Request\.', 'Process.Start with request data'),
                (r'cmd\.StartInfo\.Arguments\s*=.*?Request', 'Command arguments from request'),
            ],
            'path_traversal': [
                (r'File\.ReadAllText\s*\(.*?Request\.', 'File read with request data'),
                (r'FileStream\s*\(.*?Request\.QueryString', 'FileStream with user input'),
            ],
            'weak_crypto': [
                (r'MD5\.Create\(\)', 'MD5 usage'),
                (r'SHA1\.Create\(\)', 'SHA1 usage'),
                (r'DESCryptoServiceProvider', 'DES encryption'),
            ],
            'insecure_deserialization': [
                (r'BinaryFormatter\.Deserialize', 'Unsafe BinaryFormatter deserialization'),
                (r'JavaScriptSerializer\.Deserialize.*?Request', 'Deserialization of request data'),
            ],
            'debug_mode': [
                (r'<compilation.*?debug\s*=\s*"true"', 'Debug mode enabled in web.config'),
                (r'customErrors\s+mode\s*=\s*"Off"', 'Custom errors disabled'),
            ],
        }

        # ==== RUST ====
        self.rust_patterns = {
            'sql_injection': [
                (r'query!\s*\(\s*format!\(', 'SQL injection via format! macro'),
                (r'execute\s*\(\s*&format!\(', 'Query execution with formatted string'),
            ],
            'command_injection': [
                (r'Command::new\(.*?req\.', 'Command execution with request data'),
                (r'\.spawn\(\).*?unwrap\(\)', 'Unsafe command spawning'),
            ],
            'unsafe_code': [
                (r'\bunsafe\s+\{', 'Unsafe code block (review carefully)'),
                (r'std::mem::transmute', 'Memory transmute (potential UB)'),
            ],
        }

        # ==== KOTLIN / SPRING ====
        self.kotlin_patterns = {
            'sql_injection': [
                (r'createNativeQuery\s*\(\s*"[^"]*"\s*\+', 'SQL injection in JPA'),
                (r'jdbcTemplate\.query\s*\(\s*"[^"]*\$\{', 'String template in JDBC query'),
            ],
            'xss': [
                (r'\.html\s*=\s*request\.', 'Direct HTML assignment from request'),
            ],
            'command_injection': [
                (r'Runtime\.getRuntime\(\)\.exec\(.*?request', 'Command execution from request'),
            ],
        }

        # ==== SCALA / PLAY ====
        self.scala_patterns = {
            'sql_injection': [
                (r'SQL\s*\(\s*s"', 'String interpolation in SQL'),
                (r'\.query\s*\[\w+\]\s*\(\s*s"', 'Anorm query with string interpolation'),
            ],
            'xss': [
                (r'Html\s*\(', 'Unescaped HTML in Play'),
            ],
        }

        # ==== ELIXIR / PHOENIX ====
        self.elixir_patterns = {
            'sql_injection': [
                (r'query!\s*\(.*?".*?#\{', 'SQL injection via string interpolation'),
                (r'Repo\.query\s*\(.*?#\{', 'Ecto query with interpolation'),
            ],
            'xss': [
                (r'raw\s*\(', 'Unescaped HTML output'),
            ],
            'command_injection': [
                (r'System\.cmd\s*\(.*?params', 'Command execution with params'),
            ],
        }

        # ==== FRAMEWORK-SPECIFIC ====
        self.framework_patterns = {
            'django': [
                (r'\.raw\s*\([^)]*?format\(', 'Django raw SQL with format'),
                (r'\.extra\s*\(.*?params', 'Django .extra() with params'),
                (r'mark_safe\s*\(', 'mark_safe bypasses escaping'),
            ],
            'laravel': [
                (r'DB::raw\s*\(', 'Laravel raw SQL (verify parameterization)'),
                (r'\{!!\s*\$', 'Unescaped Blade output'),
            ],
            'express': [
                (r'app\.disable\s*\(\s*["\']x-powered-by', 'X-Powered-By header disabled (good)'),
                (r'app\.use\(.*?cors\(\{.*?origin\s*:\s*["\']?\*', 'Permissive CORS'),
            ],
            'spring': [
                (r'@RequestMapping.*?(?!@PreAuthorize)', 'Endpoint without authorization'),
                (r'\.formLogin\(\)\.disable\(\)', 'Form login disabled'),
            ],
        }

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan file based on language/framework"""
        findings = []
        lines = content.splitlines()

        # Detect language/framework and scan accordingly
        if file_type == 'rb':
            findings.extend(self._scan_ruby(file_path, lines))
        elif file_type == 'go':
            findings.extend(self._scan_go(file_path, lines))
        elif file_type == 'cs':
            findings.extend(self._scan_csharp(file_path, lines))
        elif file_type == 'rs':
            findings.extend(self._scan_rust(file_path, lines))
        elif file_type == 'kt':
            findings.extend(self._scan_kotlin(file_path, lines))
        elif file_type == 'scala':
            findings.extend(self._scan_scala(file_path, lines))
        elif file_type in ['ex', 'exs']:
            findings.extend(self._scan_elixir(file_path, lines))

        # Framework-specific checks
        findings.extend(self._scan_frameworks(file_path, lines, content))

        return findings

    def _scan_ruby(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Ruby/Rails code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.ruby_patterns['sql_injection'],
            "Ruby SQL Injection", Severity.CRITICAL,
            "Use parameterized queries or ActiveRecord query methods. Avoid string interpolation in SQL.",
            "CWE-89", "Ruby/Rails Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.ruby_patterns['xss'],
            "Ruby XSS Vulnerability", Severity.HIGH,
            "Avoid html_safe and raw(). Use sanitize() or proper escaping.",
            "CWE-79", "Ruby/Rails Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.ruby_patterns['command_injection'],
            "Ruby Command Injection", Severity.CRITICAL,
            "Never use user input in system(), exec(), or backticks. Use Shellwords.escape.",
            "CWE-78", "Ruby/Rails Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.ruby_patterns['mass_assignment'],
            "Ruby Mass Assignment Vulnerability", Severity.HIGH,
            "Use strong parameters to whitelist allowed attributes.",
            "CWE-915", "Ruby/Rails Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.ruby_patterns['deserialization'],
            "Ruby Unsafe Deserialization", Severity.CRITICAL,
            "Use YAML.safe_load instead of YAML.load. Avoid Marshal.load with untrusted data.",
            "CWE-502", "Ruby/Rails Security"
        ))

        return findings

    def _scan_go(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Go code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.go_patterns['sql_injection'],
            "Go SQL Injection", Severity.CRITICAL,
            "Use prepared statements with placeholders ($1, $2) instead of string concatenation.",
            "CWE-89", "Go Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.go_patterns['command_injection'],
            "Go Command Injection", Severity.CRITICAL,
            "Validate and sanitize command arguments. Avoid using user input directly.",
            "CWE-78", "Go Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.go_patterns['weak_crypto'],
            "Go Weak Cryptography", Severity.MEDIUM,
            "Use SHA-256 or SHA-3 instead of MD5/SHA1. Use AES instead of DES.",
            "CWE-327", "Go Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.go_patterns['insecure_tls'],
            "Go Insecure TLS Configuration", Severity.CRITICAL,
            "Never set InsecureSkipVerify to true in production.",
            "CWE-295", "Go Security"
        ))

        return findings

    def _scan_csharp(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan C#/ASP.NET code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.csharp_patterns['sql_injection'],
            "C# SQL Injection", Severity.CRITICAL,
            "Use SqlParameter or Entity Framework to prevent SQL injection.",
            "CWE-89", "C#/ASP.NET Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.csharp_patterns['xss'],
            "C# XSS Vulnerability", Severity.HIGH,
            "Use @Html.Encode() or Razor's automatic encoding. Avoid Html.Raw().",
            "CWE-79", "C#/ASP.NET Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.csharp_patterns['insecure_deserialization'],
            "C# Insecure Deserialization", Severity.CRITICAL,
            "Avoid BinaryFormatter. Use JSON or XML serialization with type validation.",
            "CWE-502", "C#/ASP.NET Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.csharp_patterns['debug_mode'],
            "C# Debug Mode Enabled", Severity.MEDIUM,
            "Disable debug mode in production (compilation debug=false, customErrors=On).",
            "CWE-489", "C#/ASP.NET Security"
        ))

        return findings

    def _scan_rust(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Rust code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.rust_patterns['sql_injection'],
            "Rust SQL Injection", Severity.CRITICAL,
            "Use query parameters instead of format! macro in SQL queries.",
            "CWE-89", "Rust Security"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.rust_patterns['unsafe_code'],
            "Rust Unsafe Code", Severity.INFO,
            "Review unsafe blocks carefully. Ensure memory safety guarantees are maintained.",
            "CWE-119", "Rust Security"
        ))

        return findings

    def _scan_kotlin(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Kotlin/Spring code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.kotlin_patterns['sql_injection'],
            "Kotlin SQL Injection", Severity.CRITICAL,
            "Use JPA parameters or JDBC prepared statements.",
            "CWE-89", "Kotlin Security"
        ))

        return findings

    def _scan_scala(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Scala/Play code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.scala_patterns['sql_injection'],
            "Scala SQL Injection", Severity.CRITICAL,
            "Use Anorm parameters or Slick's typed queries.",
            "CWE-89", "Scala Security"
        ))

        return findings

    def _scan_elixir(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Scan Elixir/Phoenix code"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.elixir_patterns['sql_injection'],
            "Elixir SQL Injection", Severity.CRITICAL,
            "Use Ecto's query builder or parameterized queries.",
            "CWE-89", "Elixir Security"
        ))

        return findings

    def _scan_frameworks(self, file_path: str, lines: List[str], content: str) -> List[Finding]:
        """Scan for framework-specific issues"""
        findings = []

        # Django
        if 'django' in content.lower() or 'from django' in content:
            findings.extend(self._check_patterns(
                file_path, lines, self.framework_patterns['django'],
                "Django Security Issue", Severity.HIGH,
                "Follow Django security best practices.",
                "CWE-89", "Django Framework"
            ))

        # Laravel
        if 'laravel' in content.lower() or '<?php' in content:
            findings.extend(self._check_patterns(
                file_path, lines, self.framework_patterns['laravel'],
                "Laravel Security Issue", Severity.HIGH,
                "Use Eloquent ORM and escaped Blade syntax.",
                "CWE-79", "Laravel Framework"
            ))

        return findings

    def _check_patterns(self, file_path: str, lines: List[str], patterns: List[tuple],
                       title: str, severity: Severity, recommendation: str,
                       cwe_id: str, category: str) -> List[Finding]:
        """Check content against patterns"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=severity,
                        title=title,
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation=recommendation,
                        cwe_id=cwe_id,
                        owasp_category=category
                    )
                    findings.append(finding)

        return findings

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
