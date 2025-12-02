"""
Express.js Framework Security Rules
Context-aware security detection for Express applications
"""
import re
from typing import List, Dict, Any


class ExpressSecurityRules:
    """Express.js-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize Express security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'\.query\s*\(\s*[`"\'].*?\$\{.*?req\.',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via template literals with request data',
                    'recommendation': 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.query\s*\([^)]*\+\s*req\.',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via string concatenation',
                    'recommendation': 'Use parameterized queries instead of concatenation',
                    'cwe': 'CWE-89',
                },
            ],
            'nosql_injection': [
                {
                    'pattern': r'\.find\s*\(\s*req\.(body|query|params)',
                    'severity': 'HIGH',
                    'description': 'NoSQL injection - direct use of request in MongoDB query',
                    'recommendation': 'Validate and sanitize input before querying',
                    'cwe': 'CWE-943',
                },
                {
                    'pattern': r'\$where.*?req\.(body|query|params)',
                    'severity': 'CRITICAL',
                    'description': 'NoSQL injection via $where operator',
                    'recommendation': 'Never use $where with user input. Use query operators instead.',
                    'cwe': 'CWE-943',
                },
            ],
            'xss': [
                {
                    'pattern': r'res\.send\s*\(\s*req\.(query|params|body)',
                    'severity': 'HIGH',
                    'description': 'XSS - sending user input directly in response',
                    'recommendation': 'Sanitize output: res.send(escapeHtml(req.query.data))',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'res\.write\s*\(\s*req\.',
                    'severity': 'HIGH',
                    'description': 'XSS - writing user input directly to response',
                    'recommendation': 'Use template engines with auto-escaping or sanitize manually',
                    'cwe': 'CWE-79',
                },
            ],
            'command_injection': [
                {
                    'pattern': r'exec\s*\([^)]*req\.(query|body|params)',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via child_process.exec',
                    'recommendation': 'Use execFile() with array arguments or validate input strictly',
                    'cwe': 'CWE-78',
                },
                {
                    'pattern': r'spawn\s*\(\s*req\.',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via spawn with user input',
                    'recommendation': 'Validate command and use array arguments',
                    'cwe': 'CWE-78',
                },
            ],
            'cors': [
                {
                    'pattern': r'cors\s*\(\s*\{\s*origin\s*:\s*["\']?\*',
                    'severity': 'MEDIUM',
                    'description': 'Overly permissive CORS policy (origin: *)',
                    'recommendation': 'Specify allowed origins explicitly',
                    'cwe': 'CWE-346',
                },
            ],
            'middleware_order': [
                {
                    'pattern': r'app\.use\(.*?helmet\(\).*?\n.*?app\.use\(.*?cors',
                    'severity': 'LOW',
                    'description': 'Security middleware (helmet) should be first',
                    'recommendation': 'Place app.use(helmet()) before other middleware',
                    'cwe': 'CWE-16',
                },
            ],
            'session_security': [
                {
                    'pattern': r'session\s*\(\s*\{[^}]*secret\s*:\s*["\'][^"\']{1,10}["\']',
                    'severity': 'HIGH',
                    'description': 'Weak session secret (too short)',
                    'recommendation': 'Use strong, random session secret (32+ characters)',
                    'cwe': 'CWE-521',
                },
                {
                    'pattern': r'session\s*\(\s*\{[^}]*secure\s*:\s*false',
                    'severity': 'MEDIUM',
                    'description': 'Session cookie not marked as secure',
                    'recommendation': 'Set secure: true for HTTPS-only cookies',
                    'cwe': 'CWE-614',
                },
            ],
            'prototype_pollution': [
                {
                    'pattern': r'Object\.assign\s*\([^)]*req\.(body|query)',
                    'severity': 'HIGH',
                    'description': 'Prototype pollution via Object.assign',
                    'recommendation': 'Validate object keys before merging',
                    'cwe': 'CWE-1321',
                },
                {
                    'pattern': r'\.\.\.req\.(body|query)',
                    'severity': 'MEDIUM',
                    'description': 'Potential prototype pollution via spread operator',
                    'recommendation': 'Sanitize request data before spreading',
                    'cwe': 'CWE-1321',
                },
            ],
        }

        self.safe_patterns = {
            'parameterized_queries': [
                r'\.query\s*\([^)]*,\s*\[',  # Parameterized SQL
            ],
            'security_headers': [
                r'helmet\(\)',
                r'csp\(',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check Express code for security issues"""
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
                            'framework': 'Express.js',
                        }
                        findings.append(finding)

        # Check for missing security middleware
        findings.extend(self._check_missing_security(code, file_path))

        return findings

    def _check_missing_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for missing security configurations"""
        findings = []

        # Check for helmet
        if 'express()' in code and 'helmet' not in code:
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'MEDIUM',
                'category': 'missing_security',
                'description': 'Missing helmet middleware for security headers',
                'recommendation': 'Add: const helmet = require("helmet"); app.use(helmet());',
                'cwe': 'CWE-16',
                'code_snippet': 'Missing helmet middleware',
                'framework': 'Express.js',
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
