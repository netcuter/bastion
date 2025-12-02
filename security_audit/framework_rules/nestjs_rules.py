"""
NestJS Framework Security Rules
Enterprise Node.js framework with TypeScript
Context-aware security detection for NestJS applications
"""
import re
from typing import List, Dict, Any


class NestJSSecurityRules:
    """NestJS-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize NestJS security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'\.query\s*\(\s*`.*?\$\{',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via template literal in TypeORM query',
                    'recommendation': 'Use parameterized queries: repository.query("SELECT * WHERE id = $1", [userId])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.query\s*\([^)]*\+',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via string concatenation',
                    'recommendation': 'Use TypeORM query builder or parameterized queries',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'createQueryBuilder.*?\.where\s*\(\s*`.*?\$\{',
                    'severity': 'HIGH',
                    'description': 'SQL injection in QueryBuilder where clause',
                    'recommendation': 'Use parameterized where: .where("user.id = :id", { id: userId })',
                    'cwe': 'CWE-89',
                },
            ],
            'nosql_injection': [
                {
                    'pattern': r'\.find\s*\(\s*\{[^}]*\.\.\.[^}]*req\.(body|query|params)',
                    'severity': 'HIGH',
                    'description': 'NoSQL injection via spread operator with request data',
                    'recommendation': 'Validate request data with class-validator DTOs',
                    'cwe': 'CWE-943',
                },
                {
                    'pattern': r'\$where.*?req\.(body|query|params)',
                    'severity': 'CRITICAL',
                    'description': 'MongoDB $where operator with user input',
                    'recommendation': 'Never use $where with user input. Use query operators instead.',
                    'cwe': 'CWE-943',
                },
            ],
            'missing_auth': [
                {
                    'pattern': r'@(Get|Post|Put|Delete|Patch)\s*\([^)]*\)(?!\s*@UseGuards)',
                    'severity': 'MEDIUM',
                    'description': 'NestJS route without authentication guard',
                    'recommendation': 'Add @UseGuards(AuthGuard) or @UseGuards(JwtAuthGuard) to protect endpoint',
                    'cwe': 'CWE-862',
                },
                {
                    'pattern': r'@(Get|Post|Put|Delete|Patch)\s*\([^)]*\)(?!\s*@Public)',
                    'severity': 'LOW',
                    'description': 'Endpoint without explicit public marker',
                    'recommendation': 'Mark public endpoints with @Public() decorator for clarity',
                    'cwe': 'CWE-285',
                },
            ],
            'validation': [
                {
                    'pattern': r'@Body\(\).*?:?\s*(?!.*Dto)\w+',
                    'severity': 'MEDIUM',
                    'description': 'Request body without DTO validation',
                    'recommendation': 'Use DTOs with class-validator: @Body() createDto: CreateUserDto',
                    'cwe': 'CWE-20',
                },
            ],
            'xss': [
                {
                    'pattern': r'@Res.*?\.send\s*\([^)]*req\.(body|query|params)',
                    'severity': 'HIGH',
                    'description': 'XSS - sending user input directly in response',
                    'recommendation': 'Sanitize output or use NestJS serialization',
                    'cwe': 'CWE-79',
                },
            ],
            'cors': [
                {
                    'pattern': r'enableCors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*',
                    'severity': 'MEDIUM',
                    'description': 'Overly permissive CORS configuration',
                    'recommendation': 'Specify allowed origins explicitly',
                    'cwe': 'CWE-346',
                },
            ],
            'prototype_pollution': [
                {
                    'pattern': r'Object\.assign\s*\([^)]*req\.(body|query)',
                    'severity': 'HIGH',
                    'description': 'Prototype pollution via Object.assign',
                    'recommendation': 'Use DTOs with class-transformer to safely map data',
                    'cwe': 'CWE-1321',
                },
                {
                    'pattern': r'\.\.\.(req\.(body|query|params))',
                    'severity': 'MEDIUM',
                    'description': 'Potential prototype pollution via spread operator',
                    'recommendation': 'Validate object keys before spreading',
                    'cwe': 'CWE-1321',
                },
            ],
            'jwt_security': [
                {
                    'pattern': r'sign\s*\([^)]*\{[^}]*expiresIn\s*:\s*["\']?(\d+y|999)',
                    'severity': 'MEDIUM',
                    'description': 'JWT with excessive expiration time',
                    'recommendation': 'Use short-lived tokens (15m-1h) with refresh tokens',
                    'cwe': 'CWE-613',
                },
                {
                    'pattern': r'JwtModule\.register\s*\(\s*\{[^}]*secret\s*:\s*["\'][^"\']{1,10}["\']',
                    'severity': 'HIGH',
                    'description': 'Weak JWT secret (too short)',
                    'recommendation': 'Use strong random secret (32+ characters) from environment',
                    'cwe': 'CWE-321',
                },
            ],
        }

        self.safe_patterns = {
            'typeorm_safe': [
                r'\.findOne\(',
                r'\.find\(',
                r'\.createQueryBuilder\(',
                r'\.where\([^)]*,\s*\{',  # Parameterized
            ],
            'validation': [
                r'@IsString\(',
                r'@IsNumber\(',
                r'@IsEmail\(',
                r'class-validator',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check NestJS code for security issues"""
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
                            'framework': 'NestJS',
                        }
                        findings.append(finding)

        # Check for missing features
        findings.extend(self._check_missing_security(code, file_path))

        return findings

    def _check_missing_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for missing security configurations"""
        findings = []

        # Check for global validation pipe
        if '@Module' in code and 'ValidationPipe' not in code and '@Body()' in code:
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'MEDIUM',
                'category': 'missing_validation',
                'description': 'Missing global ValidationPipe',
                'recommendation': 'Add app.useGlobalPipes(new ValidationPipe()) in main.ts',
                'cwe': 'CWE-20',
                'code_snippet': 'Missing ValidationPipe',
                'framework': 'NestJS',
            })

        # Check for helmet middleware
        if 'NestFactory.create' in code and 'helmet' not in code.lower():
            findings.append({
                'file_path': file_path,
                'line_number': 1,
                'severity': 'MEDIUM',
                'category': 'missing_security',
                'description': 'Missing helmet middleware for security headers',
                'recommendation': 'Add app.use(helmet()) in main.ts',
                'cwe': 'CWE-16',
                'code_snippet': 'Missing helmet',
                'framework': 'NestJS',
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
