"""
Laravel Framework Security Rules
Context-aware security detection for Laravel applications
"""
import re
from typing import List, Dict, Any


class LaravelSecurityRules:
    """Laravel-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize Laravel security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'DB::raw\s*\([^)]*\$',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via DB::raw with variables',
                    'recommendation': 'Use Eloquent ORM or parameterized queries: DB::select("SELECT * FROM users WHERE id = ?", [$id])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'->whereRaw\s*\([^)]*\$',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in whereRaw with variables',
                    'recommendation': 'Use parameterized bindings: whereRaw("id = ?", [$id])',
                    'cwe': 'CWE-89',
                },
            ],
            'xss': [
                {
                    'pattern': r'\{!!\s*\$',
                    'severity': 'HIGH',
                    'description': 'XSS - Unescaped Blade output {!! !!}',
                    'recommendation': 'Use {{ }} for auto-escaped output or sanitize with htmlspecialchars()',
                    'cwe': 'CWE-79',
                },
            ],
            'mass_assignment': [
                {
                    'pattern': r'protected\s+\$fillable\s*=\s*\[\s*\*',
                    'severity': 'HIGH',
                    'description': 'Mass assignment vulnerability - $fillable = [*]',
                    'recommendation': 'Explicitly whitelist fillable attributes',
                    'cwe': 'CWE-915',
                },
                {
                    'pattern': r'protected\s+\$guarded\s*=\s*\[\s*\]',
                    'severity': 'HIGH',
                    'description': 'Mass assignment - empty $guarded array',
                    'recommendation': 'Use $fillable to whitelist or $guarded to blacklist fields',
                    'cwe': 'CWE-915',
                },
            ],
            'csrf': [
                {
                    'pattern': r'VerifyCsrfToken.*?except.*?\[',
                    'severity': 'MEDIUM',
                    'description': 'CSRF protection exempted for routes',
                    'recommendation': 'Minimize CSRF exemptions, use API tokens instead',
                    'cwe': 'CWE-352',
                },
            ],
            'insecure_deserialization': [
                {
                    'pattern': r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                    'severity': 'CRITICAL',
                    'description': 'Unsafe unserialize with user input',
                    'recommendation': 'Use JSON instead: json_decode($input, true)',
                    'cwe': 'CWE-502',
                },
            ],
            'command_injection': [
                {
                    'pattern': r'exec\s*\([^)]*\$_(GET|POST|REQUEST)',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via exec with user input',
                    'recommendation': 'Validate input strictly or use Laravel Process facade',
                    'cwe': 'CWE-78',
                },
            ],
            'file_upload': [
                {
                    'pattern': r'->storeAs\([^)]*\$request->',
                    'severity': 'MEDIUM',
                    'description': 'File upload without validation',
                    'recommendation': 'Validate file type and size before storing',
                    'cwe': 'CWE-434',
                },
            ],
        }

        self.safe_patterns = {
            'eloquent_orm': [
                r'->where\(',
                r'->find\(',
                r'->get\(',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check Laravel code for security issues"""
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
                            'framework': 'Laravel',
                        }
                        findings.append(finding)

        # Check for missing .env.example
        if file_path.endswith('.env') and '.example' not in file_path:
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'LOW',
                'category': 'configuration',
                'description': 'Production .env file in repository',
                'recommendation': 'Add .env to .gitignore, use .env.example as template',
                'cwe': 'CWE-540',
                'code_snippet': 'Environment file',
                'framework': 'Laravel',
            })

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
