"""
React Framework Security Rules
Context-aware security detection for React applications
"""
import re
from typing import List, Dict, Any


class ReactSecurityRules:
    """React-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize React security patterns"""
        self.unsafe_patterns = {
            'xss': [
                {
                    'pattern': r'dangerouslySetInnerHTML\s*=\s*\{\{',
                    'severity': 'HIGH',
                    'description': 'XSS via dangerouslySetInnerHTML',
                    'recommendation': 'Avoid dangerouslySetInnerHTML. Use DOMPurify.sanitize() if necessary.',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'dangerouslySetInnerHTML.*?__html\s*:.*?\{[^}]*\}',
                    'severity': 'CRITICAL',
                    'description': 'XSS - dangerouslySetInnerHTML with dynamic content',
                    'recommendation': 'Sanitize with DOMPurify before rendering',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'<script[^>]*>\s*\{',
                    'severity': 'HIGH',
                    'description': 'Inline script with dynamic content',
                    'recommendation': 'Avoid inline scripts with JSX expressions',
                    'cwe': 'CWE-79',
                },
            ],
            'open_redirect': [
                {
                    'pattern': r'window\.location\s*=.*?props\.',
                    'severity': 'MEDIUM',
                    'description': 'Open redirect via window.location with props',
                    'recommendation': 'Validate URLs against whitelist before redirecting',
                    'cwe': 'CWE-601',
                },
                {
                    'pattern': r'<a\s+href\s*=\s*\{[^}]*props\.',
                    'severity': 'MEDIUM',
                    'description': 'Open redirect in href attribute',
                    'recommendation': 'Validate and sanitize URLs from props',
                    'cwe': 'CWE-601',
                },
            ],
            'javascript_injection': [
                {
                    'pattern': r'eval\s*\([^)]*props\.',
                    'severity': 'CRITICAL',
                    'description': 'JavaScript injection via eval with props',
                    'recommendation': 'Never use eval() with user-controlled data',
                    'cwe': 'CWE-94',
                },
                {
                    'pattern': r'Function\s*\([^)]*props\.',
                    'severity': 'CRITICAL',
                    'description': 'Code injection via Function constructor',
                    'recommendation': 'Avoid Function constructor with dynamic data',
                    'cwe': 'CWE-94',
                },
            ],
            'client_storage': [
                {
                    'pattern': r'localStorage\.setItem\s*\([^)]*token',
                    'severity': 'MEDIUM',
                    'description': 'Storing sensitive token in localStorage',
                    'recommendation': 'Use httpOnly cookies for tokens, not localStorage',
                    'cwe': 'CWE-522',
                },
                {
                    'pattern': r'sessionStorage\.setItem\s*\([^)]*password',
                    'severity': 'HIGH',
                    'description': 'Storing password in sessionStorage',
                    'recommendation': 'Never store passwords in client storage',
                    'cwe': 'CWE-256',
                },
            ],
        }

        self.safe_patterns = {
            'sanitized': [
                r'DOMPurify\.sanitize\(',
                r'sanitizeHtml\(',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check React code for security issues"""
        findings = []
        lines = code.splitlines()

        for category, patterns in self.unsafe_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']

                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if sanitized
                        if not self._is_sanitized(line, lines, line_num):
                            finding = {
                                'file_path': file_path,
                                'line_number': line_num,
                                'severity': pattern_info['severity'],
                                'category': category,
                                'description': pattern_info['description'],
                                'recommendation': pattern_info['recommendation'],
                                'cwe': pattern_info['cwe'],
                                'code_snippet': self._get_snippet(lines, line_num),
                                'framework': 'React',
                            }
                            findings.append(finding)

        return findings

    def _is_sanitized(self, line: str, all_lines: List[str], line_num: int) -> bool:
        """Check if content is sanitized"""
        context_start = max(0, line_num - 2)
        context_end = min(len(all_lines), line_num + 2)
        context = ' '.join(all_lines[context_start:context_end])

        for pattern in self.safe_patterns['sanitized']:
            if re.search(pattern, context):
                return True

        return False

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
