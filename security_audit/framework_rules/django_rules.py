"""
Django Framework Security Rules
Context-aware security detection for Django applications
"""
import re
from typing import List, Dict, Any, Tuple


class DjangoSecurityRules:
    """
    Django-specific security rules with context awareness
    Distinguishes between safe and unsafe Django patterns
    """

    def __init__(self):
        self._init_safe_patterns()
        self._init_unsafe_patterns()

    def _init_safe_patterns(self):
        """Initialize safe Django patterns"""
        self.safe_patterns = {
            'orm_safe': [
                r'\.objects\.filter\(',
                r'\.objects\.get\(',
                r'\.objects\.all\(',
                r'\.objects\.exclude\(',
                r'\.objects\.create\(',
                r'Q\(',  # Q objects are safe
            ],
            'template_safe': [
                r'render\(request,\s*["\'][^"\']+["\'],\s*{',  # Safe template rendering
                r'{{\s*\w+\s*}}',  # Auto-escaped variables
            ],
            'form_safe': [
                r'forms\.ModelForm',
                r'forms\.Form',
                r'form\.is_valid\(\)',
                r'form\.cleaned_data',
            ],
        }

    def _init_unsafe_patterns(self):
        """Initialize unsafe Django patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'\.objects\.raw\s*\([^)]*(%s|%|format|f["\'])',
                    'severity': 'CRITICAL',
                    'description': 'Django raw SQL with string formatting - SQL Injection',
                    'recommendation': 'Use parameterized queries: .raw("SELECT * FROM table WHERE id = %s", [user_id])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.extra\s*\([^)]*where\s*=\s*[^)]*(%s|format|\+)',
                    'severity': 'CRITICAL',
                    'description': 'Django .extra() with unsafe WHERE clause',
                    'recommendation': 'Use .filter() instead of .extra() or parameterize the WHERE clause',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'cursor\.execute\s*\([^)]*(%|format|f["\'])',
                    'severity': 'CRITICAL',
                    'description': 'Raw cursor.execute with string formatting',
                    'recommendation': 'Use parameterized queries: cursor.execute("SELECT * FROM table WHERE id = %s", [user_id])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'RawSQL\s*\([^)]*(%|format|f["\'])',
                    'severity': 'CRITICAL',
                    'description': 'Django RawSQL with string interpolation',
                    'recommendation': 'Use parameterized RawSQL: RawSQL("WHERE id = %s", [user_id])',
                    'cwe': 'CWE-89',
                },
            ],
            'xss': [
                {
                    'pattern': r'mark_safe\s*\(',
                    'severity': 'HIGH',
                    'description': 'mark_safe() bypasses Django XSS protection',
                    'recommendation': 'Avoid mark_safe() with user input. Use Django template auto-escaping or bleach.clean()',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'SafeString\s*\(',
                    'severity': 'HIGH',
                    'description': 'SafeString bypasses HTML escaping',
                    'recommendation': 'Only use SafeString for trusted content. Escape user input.',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'render_to_string\([^)]*safe\s*=\s*True',
                    'severity': 'HIGH',
                    'description': 'render_to_string with safe=True disables escaping',
                    'recommendation': 'Remove safe=True or ensure content is properly sanitized',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'{%\s*autoescape\s+off\s*%}',
                    'severity': 'HIGH',
                    'description': 'Template autoescape disabled',
                    'recommendation': 'Avoid disabling autoescape. Use |safe filter sparingly.',
                    'cwe': 'CWE-79',
                },
            ],
            'csrf': [
                {
                    'pattern': r'@csrf_exempt',
                    'severity': 'HIGH',
                    'description': 'CSRF protection disabled with @csrf_exempt',
                    'recommendation': 'Remove @csrf_exempt and use {% csrf_token %} in forms',
                    'cwe': 'CWE-352',
                },
                {
                    'pattern': r"MIDDLEWARE.*CSRF.*['\"]\s*#",
                    'severity': 'CRITICAL',
                    'description': 'CSRF middleware commented out or disabled',
                    'recommendation': 'Enable CSRF middleware in settings.MIDDLEWARE',
                    'cwe': 'CWE-352',
                },
            ],
            'mass_assignment': [
                {
                    'pattern': r'\.save\([^)]*commit\s*=\s*True[^)]*\)',
                    'severity': 'MEDIUM',
                    'description': 'Potential mass assignment without field validation',
                    'recommendation': 'Use ModelForm with Meta.fields to whitelist allowed fields',
                    'cwe': 'CWE-915',
                },
            ],
            'debug_mode': [
                {
                    'pattern': r'DEBUG\s*=\s*True',
                    'severity': 'HIGH',
                    'description': 'DEBUG mode enabled (settings.py)',
                    'recommendation': 'Set DEBUG = False in production',
                    'cwe': 'CWE-489',
                },
                {
                    'pattern': r'ALLOWED_HOSTS\s*=\s*\[\s*\*',
                    'severity': 'HIGH',
                    'description': 'ALLOWED_HOSTS set to wildcard',
                    'recommendation': 'Specify explicit allowed hosts: ALLOWED_HOSTS = ["example.com"]',
                    'cwe': 'CWE-346',
                },
            ],
            'insecure_deserialization': [
                {
                    'pattern': r'pickle\.loads?\s*\([^)]*request',
                    'severity': 'CRITICAL',
                    'description': 'Pickle deserialization from request data',
                    'recommendation': 'Use JSON instead of pickle for user data',
                    'cwe': 'CWE-502',
                },
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Check Django code for security issues

        Args:
            code: Source code
            file_path: File path

        Returns:
            List of security findings
        """
        findings = []
        lines = code.splitlines()

        # Check for unsafe patterns
        for category, patterns in self.unsafe_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']

                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if it's a false positive (safe pattern nearby)
                        if not self._is_false_positive(line, lines, line_num):
                            finding = {
                                'file_path': file_path,
                                'line_number': line_num,
                                'severity': pattern_info['severity'],
                                'category': category,
                                'description': pattern_info['description'],
                                'recommendation': pattern_info['recommendation'],
                                'cwe': pattern_info['cwe'],
                                'code_snippet': self._get_snippet(lines, line_num),
                                'framework': 'Django',
                            }
                            findings.append(finding)

        # Check for missing security features
        findings.extend(self._check_missing_security_features(code, file_path, lines))

        return findings

    def _is_false_positive(self, line: str, all_lines: List[str], line_num: int) -> bool:
        """
        Check if detection is a false positive based on context

        Args:
            line: Current line
            all_lines: All lines of code
            line_num: Current line number

        Returns:
            True if false positive, False otherwise
        """
        # Check surrounding lines for safe patterns
        context_start = max(0, line_num - 3)
        context_end = min(len(all_lines), line_num + 3)
        context = ' '.join(all_lines[context_start:context_end])

        # If parameterized query detected nearby, it's likely safe
        if re.search(r',\s*\[[^\]]+\]', context):  # Parameterized array
            return True

        # If using Django ORM safe methods
        for safe_pattern in self.safe_patterns['orm_safe']:
            if re.search(safe_pattern, context):
                return True

        return False

    def _check_missing_security_features(self, code: str, file_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Check for missing security configurations"""
        findings = []

        # Check for missing CSRF middleware (in settings files)
        if 'settings.py' in file_path:
            if 'MIDDLEWARE' in code:
                if 'CsrfViewMiddleware' not in code:
                    findings.append({
                        'file_path': file_path,
                        'line_number': 1,
                        'severity': 'CRITICAL',
                        'category': 'csrf',
                        'description': 'CSRF middleware not found in settings.MIDDLEWARE',
                        'recommendation': 'Add django.middleware.csrf.CsrfViewMiddleware to MIDDLEWARE',
                        'cwe': 'CWE-352',
                        'code_snippet': 'Missing CSRF middleware configuration',
                        'framework': 'Django',
                    })

            # Check for missing security middleware
            if 'SecurityMiddleware' not in code:
                findings.append({
                    'file_path': file_path,
                    'line_number': 1,
                    'severity': 'HIGH',
                    'category': 'security_headers',
                    'description': 'Security middleware not found',
                    'recommendation': 'Add django.middleware.security.SecurityMiddleware to MIDDLEWARE',
                    'cwe': 'CWE-16',
                    'code_snippet': 'Missing Security middleware',
                    'framework': 'Django',
                })

            # Check for missing secret key validation
            if re.search(r'SECRET_KEY\s*=\s*["\'][^"\']{10,}["\']', code):
                # Secret key is hardcoded
                findings.append({
                    'file_path': file_path,
                    'line_number': self._find_line(lines, 'SECRET_KEY'),
                    'severity': 'CRITICAL',
                    'category': 'hardcoded_secret',
                    'description': 'Hardcoded SECRET_KEY in settings',
                    'recommendation': 'Use environment variables: SECRET_KEY = os.environ.get("SECRET_KEY")',
                    'cwe': 'CWE-798',
                    'code_snippet': 'SECRET_KEY = "..."',
                    'framework': 'Django',
                })

        return findings

    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number containing pattern"""
        for i, line in enumerate(lines, start=1):
            if pattern in line:
                return i
        return 1

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)

    def get_safe_alternatives(self, vulnerability_type: str) -> Dict[str, str]:
        """
        Get safe coding alternatives for Django

        Args:
            vulnerability_type: Type of vulnerability

        Returns:
            Dictionary with unsafe and safe examples
        """
        alternatives = {
            'sql_injection': {
                'unsafe': 'User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")',
                'safe': 'User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])',
            },
            'xss': {
                'unsafe': 'return HttpResponse(mark_safe(user_input))',
                'safe': 'return HttpResponse(user_input)  # Auto-escaped',
            },
            'csrf': {
                'unsafe': '@csrf_exempt\\ndef my_view(request): ...',
                'safe': 'def my_view(request): ...  # Remove @csrf_exempt',
            },
        }

        return alternatives.get(vulnerability_type, {})
