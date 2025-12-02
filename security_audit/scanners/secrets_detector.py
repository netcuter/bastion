"""
Secrets and sensitive data detector
Identifies hardcoded secrets, API keys, tokens, etc.
"""
import re
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity


class SecretsDetector(BaseScanner):
    """Scanner for detecting secrets and sensitive data"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Secrets Detector"

    def get_description(self) -> str:
        return "Detects hardcoded secrets, API keys, tokens, and other sensitive data"

    def _init_patterns(self):
        """Initialize secret detection patterns"""

        # High entropy strings that might be secrets
        self.high_entropy_pattern = re.compile(
            r'["\']([A-Za-z0-9+/=]{32,})["\']'
        )

        # Specific secret patterns with their names and severity
        self.secret_patterns = [
            # AWS
            {
                'name': 'AWS Access Key ID',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': Severity.CRITICAL,
                'description': 'AWS Access Key ID detected'
            },
            {
                'name': 'AWS Secret Access Key',
                'pattern': r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
                'severity': Severity.CRITICAL,
                'description': 'AWS Secret Access Key detected'
            },

            # GitHub
            {
                'name': 'GitHub Personal Access Token',
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'severity': Severity.CRITICAL,
                'description': 'GitHub Personal Access Token detected'
            },
            {
                'name': 'GitHub OAuth Token',
                'pattern': r'gho_[a-zA-Z0-9]{36}',
                'severity': Severity.CRITICAL,
                'description': 'GitHub OAuth Token detected'
            },

            # Google
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'severity': Severity.CRITICAL,
                'description': 'Google API Key detected'
            },
            {
                'name': 'Google OAuth',
                'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'severity': Severity.HIGH,
                'description': 'Google OAuth credentials detected'
            },

            # Slack
            {
                'name': 'Slack Token',
                'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
                'severity': Severity.CRITICAL,
                'description': 'Slack token detected'
            },
            {
                'name': 'Slack Webhook',
                'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
                'severity': Severity.HIGH,
                'description': 'Slack webhook URL detected'
            },

            # Stripe
            {
                'name': 'Stripe API Key',
                'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
                'severity': Severity.CRITICAL,
                'description': 'Stripe live API key detected'
            },
            {
                'name': 'Stripe Restricted Key',
                'pattern': r'rk_live_[0-9a-zA-Z]{24,}',
                'severity': Severity.CRITICAL,
                'description': 'Stripe restricted API key detected'
            },

            # Database Connection Strings
            {
                'name': 'PostgreSQL Connection String',
                'pattern': r'postgres(ql)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+',
                'severity': Severity.CRITICAL,
                'description': 'PostgreSQL connection string with credentials'
            },
            {
                'name': 'MySQL Connection String',
                'pattern': r'mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+',
                'severity': Severity.CRITICAL,
                'description': 'MySQL connection string with credentials'
            },
            {
                'name': 'MongoDB Connection String',
                'pattern': r'mongodb(\+srv)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+',
                'severity': Severity.CRITICAL,
                'description': 'MongoDB connection string with credentials'
            },

            # Private Keys
            {
                'name': 'RSA Private Key',
                'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
                'severity': Severity.CRITICAL,
                'description': 'RSA private key detected'
            },
            {
                'name': 'SSH Private Key',
                'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
                'severity': Severity.CRITICAL,
                'description': 'SSH private key detected'
            },
            {
                'name': 'PGP Private Key',
                'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'severity': Severity.CRITICAL,
                'description': 'PGP private key detected'
            },

            # JWT Tokens
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                'severity': Severity.HIGH,
                'description': 'JWT token detected'
            },

            # Generic API Keys
            {
                'name': 'Generic API Key',
                'pattern': r'(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                'severity': Severity.HIGH,
                'description': 'Generic API key detected'
            },

            # Generic Passwords
            {
                'name': 'Generic Password',
                'pattern': r'(password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'\s]{8,})["\']',
                'severity': Severity.HIGH,
                'description': 'Hardcoded password detected'
            },

            # Generic Secrets
            {
                'name': 'Generic Secret',
                'pattern': r'(secret|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                'severity': Severity.HIGH,
                'description': 'Hardcoded secret detected'
            },

            # Tokens
            {
                'name': 'Generic Token',
                'pattern': r'(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                'severity': Severity.HIGH,
                'description': 'Hardcoded token detected'
            },

            # Twilio
            {
                'name': 'Twilio API Key',
                'pattern': r'SK[a-z0-9]{32}',
                'severity': Severity.CRITICAL,
                'description': 'Twilio API key detected'
            },

            # SendGrid
            {
                'name': 'SendGrid API Key',
                'pattern': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
                'severity': Severity.CRITICAL,
                'description': 'SendGrid API key detected'
            },

            # MailChimp
            {
                'name': 'MailChimp API Key',
                'pattern': r'[a-f0-9]{32}-us[0-9]{1,2}',
                'severity': Severity.HIGH,
                'description': 'MailChimp API key detected'
            },

            # NPM Token
            {
                'name': 'NPM Token',
                'pattern': r'npm_[a-zA-Z0-9]{36}',
                'severity': Severity.CRITICAL,
                'description': 'NPM access token detected'
            },
        ]

        # File patterns to skip (false positives)
        self.skip_patterns = [
            r'example',
            r'sample',
            r'test',
            r'mock',
            r'dummy',
            r'placeholder',
            r'your_api_key_here',
            r'insert_key_here',
            r'xxx+',
            r'\*{3,}',
        ]

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan file for secrets"""
        findings = []
        lines = content.splitlines()

        # Skip certain file types that commonly have false positives
        if file_type in ['min.js', 'map', 'lock', 'jpg', 'png', 'gif']:
            return findings

        for line_num, line in enumerate(lines, start=1):
            # Skip if line matches skip patterns
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in self.skip_patterns):
                continue

            # Check each secret pattern
            for secret_pattern in self.secret_patterns:
                if re.search(secret_pattern['pattern'], line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=secret_pattern['severity'],
                        title=secret_pattern['name'],
                        description=secret_pattern['description'],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Remove hardcoded secrets. Use environment variables or secret management systems.",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021 - Identification and Authentication Failures"
                    )
                    findings.append(finding)

        return findings

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context, masking the secret"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            line = lines[i]
            # Mask the secret in the problematic line
            if i == line_num - 1:
                line = self._mask_secret(line)
                prefix = ">>>"
            else:
                prefix = "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {line}")

        return "\n".join(snippet_lines)

    def _mask_secret(self, line: str) -> str:
        """Mask the secret value in the line"""
        # Mask values in quotes
        line = re.sub(r'(["\'])([A-Za-z0-9+/=_-]{8,})(["\'])', r'\1***REDACTED***\3', line)
        return line
