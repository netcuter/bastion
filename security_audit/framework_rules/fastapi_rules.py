"""
FastAPI Framework Security Rules
Modern async Python web framework
Context-aware security detection for FastAPI applications
"""
import re
from typing import List, Dict, Any


class FastAPISecurityRules:
    """FastAPI-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize FastAPI security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'session\.execute\s*\([^)]*f"',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via f-string in SQLAlchemy execute',
                    'recommendation': 'Use parameterized queries: session.execute(text("SELECT * WHERE id = :id"), {"id": user_id})',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'session\.execute\s*\([^)]*\+',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via string concatenation',
                    'recommendation': 'Use ORM or parameterized queries with text() and bound parameters',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.query\s*\([^)]*f"',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in query with f-string',
                    'recommendation': 'Use SQLAlchemy ORM methods: session.query(User).filter(User.id == user_id)',
                    'cwe': 'CWE-89',
                },
            ],
            'nosql_injection': [
                {
                    'pattern': r'collection\.find\s*\(\s*\{[^}]*request\.',
                    'severity': 'HIGH',
                    'description': 'NoSQL injection - MongoDB find with request data',
                    'recommendation': 'Validate and sanitize all request parameters before database queries',
                    'cwe': 'CWE-943',
                },
                {
                    'pattern': r'collection\.find_one\s*\(\s*\{.*?\$where',
                    'severity': 'CRITICAL',
                    'description': 'NoSQL injection via $where operator',
                    'recommendation': 'Never use $where with user input. Use standard query operators.',
                    'cwe': 'CWE-943',
                },
            ],
            'missing_auth': [
                {
                    'pattern': r'@app\.(get|post|put|delete|patch)\([^)]*\)(?!\s*@|\s*async\s+def\s+\w+\([^)]*[Dd]epends)',
                    'severity': 'MEDIUM',
                    'description': 'FastAPI route without authentication dependency',
                    'recommendation': 'Add authentication: @app.get(..., dependencies=[Depends(get_current_user)])',
                    'cwe': 'CWE-862',
                },
            ],
            'mass_assignment': [
                {
                    'pattern': r'\.update\s*\([^)]*\*\*request\.(body|json)',
                    'severity': 'HIGH',
                    'description': 'Mass assignment vulnerability - unpacking request data directly',
                    'recommendation': 'Use Pydantic models to whitelist allowed fields',
                    'cwe': 'CWE-915',
                },
            ],
            'cors': [
                {
                    'pattern': r'CORSMiddleware.*?allow_origins\s*=\s*\[\s*["\']?\*',
                    'severity': 'MEDIUM',
                    'description': 'Overly permissive CORS - allows all origins',
                    'recommendation': 'Specify explicit allowed origins instead of wildcard',
                    'cwe': 'CWE-346',
                },
            ],
            'insecure_deserialization': [
                {
                    'pattern': r'pickle\.loads?\s*\([^)]*request\.',
                    'severity': 'CRITICAL',
                    'description': 'Insecure deserialization - pickle from request',
                    'recommendation': 'Use JSON instead of pickle for user data. Never unpickle untrusted data.',
                    'cwe': 'CWE-502',
                },
            ],
            'path_traversal': [
                {
                    'pattern': r'FileResponse\s*\([^)]*request\.(query|path)_params',
                    'severity': 'HIGH',
                    'description': 'Path traversal in FileResponse',
                    'recommendation': 'Validate file paths with Path.resolve() and check if within allowed directory',
                    'cwe': 'CWE-22',
                },
            ],
        }

        self.safe_patterns = {
            'orm_safe': [
                r'session\.query\(',
                r'\.filter\(',
                r'\.filter_by\(',
                r'select\(',  # SQLAlchemy 2.0
            ],
            'pydantic_validation': [
                r'class\s+\w+\(BaseModel\):',
                r': Annotated\[',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check FastAPI code for security issues"""
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
                            'framework': 'FastAPI',
                        }
                        findings.append(finding)

        # Check for missing features
        findings.extend(self._check_missing_security(code, file_path))

        return findings

    def _check_missing_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for missing security configurations"""
        findings = []

        # Check if FastAPI app but no CORS middleware
        if 'FastAPI(' in code and 'CORSMiddleware' not in code:
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'LOW',
                'category': 'missing_security',
                'description': 'FastAPI app without CORS middleware',
                'recommendation': 'Add CORSMiddleware if app will be accessed from browsers',
                'cwe': 'CWE-346',
                'code_snippet': 'Missing CORS configuration',
                'framework': 'FastAPI',
            })

        # Check for HTTPSRedirectMiddleware in production
        if 'FastAPI(' in code and 'HTTPSRedirectMiddleware' not in code and 'production' in code.lower():
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'MEDIUM',
                'category': 'missing_security',
                'description': 'Production app without HTTPS redirect',
                'recommendation': 'Add HTTPSRedirectMiddleware for production deployment',
                'cwe': 'CWE-319',
                'code_snippet': 'Missing HTTPS redirect',
                'framework': 'FastAPI',
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
