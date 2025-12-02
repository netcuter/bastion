"""
ASVS (Application Security Verification Standard) Scanner
Maps findings to ASVS requirements and checks compliance
"""
import re
from typing import List, Dict, Any
from pathlib import Path

from ..core.scanner import BaseScanner, Finding, Severity
from ..asvs import ASVSRequirement, ASVSRequirements, ASVSLevel, ASVSCategory


class ASVSScanner(BaseScanner):
    """Scanner for ASVS compliance verification"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.asvs_level = ASVSLevel(config.get('asvs_level', 1)) if config else ASVSLevel.LEVEL_1
        self.requirements = ASVSRequirements.get_requirements_by_level(self.asvs_level)
        self._init_patterns()

    def get_name(self) -> str:
        return "ASVS Compliance Scanner"

    def get_description(self) -> str:
        return f"Verifies compliance with OWASP ASVS {self.asvs_level.value} requirements"

    def _init_patterns(self):
        """Initialize ASVS-specific detection patterns"""

        # V2: Authentication patterns
        self.weak_password_patterns = [
            (r'(min|minimum)[_-]?(password|pwd)[_-]?(length|len)\s*[=:]\s*[1-7]\D',
             'Password minimum length less than 8 characters'),
            (r'password[_-]?length\s*[=:]\s*[1-7]\D',
             'Password length requirement too short'),
        ]

        self.weak_hash_patterns = [
            (r'(md5|sha1)\s*\(',
             'Weak password hashing algorithm'),
            (r'hashlib\.(md5|sha1)\s*\(',
             'Weak password hashing in Python'),
            (r'(?<!bcrypt\.)hash\s*\(',
             'Potentially weak hashing'),
        ]

        self.rate_limiting_patterns = [
            (r'@(app\.)?route.*?(?!.*rate)', 'Endpoint without rate limiting'),
        ]

        # V3: Session Management patterns
        self.session_exposure_patterns = [
            (r'session[_-]?(id|token).*?(\+|\.format|\%s)',
             'Session token in string manipulation'),
            (r'(session|token)\s*=.*?request\.(args|query)',
             'Session token from URL parameter'),
        ]

        self.cookie_security_patterns = [
            (r'set[_-]?cookie\s*\([^)]*?(?!.*secure)',
             'Cookie without Secure flag'),
            (r'set[_-]?cookie\s*\([^)]*?(?!.*httponly)',
             'Cookie without HttpOnly flag'),
            (r'set[_-]?cookie\s*\([^)]*?(?!.*samesite)',
             'Cookie without SameSite attribute'),
            (r'\.cookie\s*\([^)]*?\)',
             'Cookie configuration (check security flags)'),
        ]

        # V6: Cryptography patterns
        self.weak_crypto_patterns = [
            (r'(DES|3DES|RC4|RC2|MD5|SHA1)\(',
             'Weak cryptographic algorithm'),
            (r'AES.*?ECB',
             'Insecure block cipher mode (ECB)'),
            (r'Cipher\.(AES|DES).*?MODE_ECB',
             'ECB mode detected'),
        ]

        # V7: Error Handling patterns
        self.sensitive_logging_patterns = [
            (r'log.*?(password|passwd|pwd|secret|token|api[_-]?key)',
             'Potential sensitive data in logs'),
            (r'(logger|log|console)\.(info|debug|warn).*?(password|token|secret)',
             'Logging sensitive information'),
        ]

        self.error_disclosure_patterns = [
            (r'debug\s*=\s*True',
             'Debug mode enabled'),
            (r'app\.run\(.*?debug\s*=\s*True',
             'Flask debug mode enabled'),
            (r'DEBUG\s*=\s*True',
             'Django debug mode enabled'),
            (r'ENV\s*=\s*["\']development["\']',
             'Development mode in configuration'),
        ]

        # V8: Data Protection patterns
        self.cache_control_patterns = [
            (r'@cache|\.cache\(',
             'Caching used (verify sensitive data not cached)'),
        ]

        # V9: Communication patterns
        self.http_patterns = [
            (r'https?://(?!localhost|127\.0\.0\.1)',
             'HTTP URL detected (prefer HTTPS)'),
        ]

        self.tls_patterns = [
            (r'ssl[_-]?verify\s*=\s*False',
             'SSL verification disabled'),
            (r'verify\s*=\s*False',
             'Certificate verification disabled'),
            (r'SSLOPT.*?cert_reqs.*?CERT_NONE',
             'SSL certificate validation disabled'),
        ]

        # V12: File Upload patterns
        self.file_upload_patterns = [
            (r'request\.files|request\.file|@.*?upload',
             'File upload endpoint (verify size limits and validation)'),
            (r'save\(.*?request\.files',
             'File save without validation'),
            (r'\.save\(.*?filename',
             'File saved with user-supplied filename'),
        ]

        # V13: API patterns
        self.api_patterns = [
            (r'@(app\.)?(get|post|put|delete|patch)\(',
             'API endpoint (verify authentication and authorization)'),
            (r'CORS\(',
             'CORS configuration (verify not too permissive)'),
            (r'Access-Control-Allow-Origin.*?\*',
             'Permissive CORS policy'),
        ]

        # V14: Configuration patterns
        self.security_header_patterns = [
            (r'Content-Security-Policy',
             'CSP header present'),
            (r'X-Content-Type-Options',
             'X-Content-Type-Options header present'),
            (r'Strict-Transport-Security',
             'HSTS header present'),
            (r'X-Frame-Options',
             'X-Frame-Options header present'),
        ]

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan file for ASVS compliance"""
        findings = []
        lines = content.splitlines()

        # V2: Authentication Verification
        findings.extend(self._check_authentication(file_path, lines))

        # V3: Session Management
        findings.extend(self._check_session_management(file_path, lines))

        # V6: Cryptography
        findings.extend(self._check_cryptography(file_path, lines))

        # V7: Error Handling and Logging
        findings.extend(self._check_error_handling(file_path, lines))

        # V8: Data Protection
        findings.extend(self._check_data_protection(file_path, lines))

        # V9: Communication
        findings.extend(self._check_communication(file_path, lines))

        # V12: Files and Resources
        findings.extend(self._check_file_handling(file_path, lines))

        # V13: API
        findings.extend(self._check_api_security(file_path, lines))

        # V14: Configuration
        findings.extend(self._check_configuration(file_path, lines, file_type))

        return findings

    def _check_authentication(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V2 Authentication requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.weak_password_patterns,
            "ASVS 2.1.1 - Weak Password Policy",
            Severity.MEDIUM,
            "ASVS 2.1.1: Passwords should be at least 12 characters. Implement stronger password requirements.",
            "CWE-521", "ASVS V2.1"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.weak_hash_patterns,
            "ASVS 2.1.7 - Weak Password Storage",
            Severity.CRITICAL,
            "ASVS 2.1.7: Use bcrypt, scrypt, Argon2, or PBKDF2 for password hashing.",
            "CWE-916", "ASVS V2.1"
        ))

        return findings

    def _check_session_management(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V3 Session Management requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.session_exposure_patterns,
            "ASVS 3.1.1 - Session Token Exposure",
            Severity.HIGH,
            "ASVS 3.1.1: Session tokens must not be exposed in URLs or error messages.",
            "CWE-598", "ASVS V3.1"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.cookie_security_patterns,
            "ASVS 3.4.x - Missing Cookie Security Flags",
            Severity.MEDIUM,
            "ASVS 3.4.1-3: Set Secure, HttpOnly, and SameSite flags on session cookies.",
            "CWE-614", "ASVS V3.4"
        ))

        return findings

    def _check_cryptography(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V6 Cryptography requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.weak_crypto_patterns,
            "ASVS 6.2.2 - Weak Cryptographic Algorithm",
            Severity.HIGH,
            "ASVS 6.2.2: Use approved cryptographic algorithms (AES-256, SHA-256, etc.).",
            "CWE-327", "ASVS V6.2"
        ))

        return findings

    def _check_error_handling(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V7 Error Handling requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.sensitive_logging_patterns,
            "ASVS 7.1.1 - Sensitive Data in Logs",
            Severity.MEDIUM,
            "ASVS 7.1.1: Do not log credentials, session tokens, or sensitive data.",
            "CWE-532", "ASVS V7.1"
        ))

        findings.extend(self._check_patterns(
            file_path, lines, self.error_disclosure_patterns,
            "ASVS 7.4.1 - Information Disclosure via Debug Mode",
            Severity.MEDIUM,
            "ASVS 14.3.3 & 7.4.1: Disable debug mode in production environments.",
            "CWE-489", "ASVS V7.4"
        ))

        return findings

    def _check_data_protection(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V8 Data Protection requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.cache_control_patterns,
            "ASVS 8.1.1 - Sensitive Data Caching",
            Severity.LOW,
            "ASVS 8.1.1: Ensure sensitive data is not cached. Set appropriate Cache-Control headers.",
            "CWE-524", "ASVS V8.1"
        ))

        return findings

    def _check_communication(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V9 Communication requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.tls_patterns,
            "ASVS 9.2.1 - Certificate Validation Disabled",
            Severity.CRITICAL,
            "ASVS 9.2.1: Always validate TLS certificates. Never disable SSL verification.",
            "CWE-295", "ASVS V9.2"
        ))

        return findings

    def _check_file_handling(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V12 Files and Resources requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.file_upload_patterns,
            "ASVS 12.x - File Upload Security",
            Severity.MEDIUM,
            "ASVS 12.1.1, 12.3.1, 12.5.1: Validate file uploads (size, type, filename).",
            "CWE-434", "ASVS V12"
        ))

        return findings

    def _check_api_security(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check V13 API requirements"""
        findings = []

        findings.extend(self._check_patterns(
            file_path, lines, self.api_patterns,
            "ASVS 13.x - API Security",
            Severity.INFO,
            "ASVS 13.2.3: Ensure APIs have proper authentication and CSRF protection.",
            "CWE-352", "ASVS V13"
        ))

        return findings

    def _check_configuration(self, file_path: str, lines: List[str], file_type: str) -> List[Finding]:
        """Check V14 Configuration requirements"""
        findings = []

        # Check for presence of security headers (positive check)
        has_security_headers = any(
            re.search(pattern, line, re.IGNORECASE)
            for line in lines
            for pattern, _ in self.security_header_patterns
        )

        if not has_security_headers and file_type in ['py', 'js', 'ts', 'php', 'rb', 'go', 'cs']:
            findings.append(Finding(
                scanner=self.get_name(),
                severity=Severity.MEDIUM,
                title="ASVS 14.4.x - Missing Security Headers",
                description="No security headers detected in code",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="ASVS 14.4.3-7: Implement CSP, HSTS, X-Content-Type-Options, X-Frame-Options headers.",
                cwe_id="CWE-16",
                owasp_category="ASVS V14.4"
            ))

        return findings

    def _check_patterns(self, file_path: str, lines: List[str], patterns: List[tuple],
                       title: str, severity: Severity, recommendation: str,
                       cwe_id: str, asvs_category: str) -> List[Finding]:
        """Check content against ASVS patterns"""
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
                        owasp_category=asvs_category
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

    def get_asvs_compliance_summary(self, all_findings: List[Finding]) -> Dict[str, Any]:
        """Generate ASVS compliance summary"""
        total_reqs = len(self.requirements)
        failed_reqs = set()

        # Map findings to failed requirements
        for finding in all_findings:
            if finding.scanner == self.get_name():
                # Extract ASVS requirement from title
                if "ASVS" in finding.title:
                    failed_reqs.add(finding.title)

        passed_reqs = total_reqs - len(failed_reqs)
        compliance_percentage = (passed_reqs / total_reqs * 100) if total_reqs > 0 else 0

        return {
            "asvs_level": self.asvs_level.value,
            "total_requirements": total_reqs,
            "passed_requirements": passed_reqs,
            "failed_requirements": len(failed_reqs),
            "compliance_percentage": round(compliance_percentage, 2),
            "failed_requirement_details": list(failed_reqs)
        }
