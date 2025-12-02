"""
Spring Framework Security Rules
Context-aware security detection for Spring/Spring Boot applications
"""
import re
from typing import List, Dict, Any


class SpringSecurityRules:
    """Spring Framework-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize Spring security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'createNativeQuery\s*\([^)]*\+',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in JPA native query with concatenation',
                    'recommendation': 'Use parameterized queries: createNativeQuery("SELECT * FROM users WHERE id = :id").setParameter("id", userId)',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'jdbcTemplate\.query\s*\([^)]*\+',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in JdbcTemplate with concatenation',
                    'recommendation': 'Use parameterized queries: jdbcTemplate.query("SELECT * FROM users WHERE id = ?", new Object[]{id}, ...)',
                    'cwe': 'CWE-89',
                },
            ],
            'authorization': [
                {
                    'pattern': r'@RequestMapping[^@]*(?!@PreAuthorize|@Secured)',
                    'severity': 'MEDIUM',
                    'description': 'Endpoint without authorization check',
                    'recommendation': 'Add @PreAuthorize or @Secured annotation to protect endpoint',
                    'cwe': 'CWE-862',
                },
                {
                    'pattern': r'@GetMapping[^@]*(?!@PreAuthorize)',
                    'severity': 'MEDIUM',
                    'description': 'GET endpoint without authorization',
                    'recommendation': 'Add @PreAuthorize("hasRole(\'USER\')") or similar',
                    'cwe': 'CWE-862',
                },
            ],
            'xss': [
                {
                    'pattern': r'@ResponseBody.*?String.*?@RequestParam',
                    'severity': 'HIGH',
                    'description': 'Potential XSS - returning user input directly',
                    'recommendation': 'Use HtmlUtils.htmlEscape() or return JSON instead of HTML',
                    'cwe': 'CWE-79',
                },
            ],
            'csrf': [
                {
                    'pattern': r'\.csrf\(\)\.disable\(\)',
                    'severity': 'HIGH',
                    'description': 'CSRF protection disabled',
                    'recommendation': 'Enable CSRF protection for state-changing operations',
                    'cwe': 'CWE-352',
                },
            ],
            'mass_assignment': [
                {
                    'pattern': r'@ModelAttribute.*?(?!@Valid)',
                    'severity': 'MEDIUM',
                    'description': 'Mass assignment without validation',
                    'recommendation': 'Add @Valid annotation and use DTO with whitelisted fields',
                    'cwe': 'CWE-915',
                },
            ],
            'insecure_deserialization': [
                {
                    'pattern': r'ObjectInputStream.*?readObject',
                    'severity': 'CRITICAL',
                    'description': 'Unsafe deserialization with ObjectInputStream',
                    'recommendation': 'Use JSON or implement custom deserialization with validation',
                    'cwe': 'CWE-502',
                },
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check Spring code for security issues"""
        findings = []
        lines = code.splitlines()

        for category, patterns in self.unsafe_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']

                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = {
                            'file_path': file_path,
                            'line_number': line_num,
                            'severity': pattern_info['severity'],
                            'category': category,
                            'description': pattern_info['description'],
                            'recommendation': pattern_info['recommendation'],
                            'cwe': pattern_info['cwe'],
                            'code_snippet': self._get_snippet(lines, line_num),
                            'framework': 'Spring',
                        }
                        findings.append(finding)

        return findings

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
