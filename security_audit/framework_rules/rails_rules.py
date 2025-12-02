"""
Ruby on Rails Framework Security Rules
Full-stack Ruby web framework
Context-aware security detection for Rails applications
"""
import re
from typing import List, Dict, Any


class RailsSecurityRules:
    """Ruby on Rails-specific security rules"""

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Initialize Rails security patterns"""
        self.unsafe_patterns = {
            'sql_injection': [
                {
                    'pattern': r'\.where\s*\(["\'].*?#\{',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection via string interpolation in where clause',
                    'recommendation': 'Use parameterized where: .where("name = ?", user_name) or .where(name: user_name)',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.find_by_sql\s*\(["\'].*?#\{',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in find_by_sql with string interpolation',
                    'recommendation': 'Use parameterized queries: .find_by_sql(["SELECT * WHERE id = ?", user_id])',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'ActiveRecord::Base\.connection\.execute\s*\([^)]*#\{',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection in raw SQL execution',
                    'recommendation': 'Use ActiveRecord query methods or sanitize_sql',
                    'cwe': 'CWE-89',
                },
                {
                    'pattern': r'\.order\s*\(["\'].*?#\{',
                    'severity': 'HIGH',
                    'description': 'SQL injection in order clause',
                    'recommendation': 'Whitelist column names or use symbols: .order(:created_at)',
                    'cwe': 'CWE-89',
                },
            ],
            'xss': [
                {
                    'pattern': r'\.html_safe\b',
                    'severity': 'HIGH',
                    'description': 'html_safe bypasses Rails XSS protection',
                    'recommendation': 'Avoid html_safe with user input. Use sanitize() helper instead.',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'\braw\s*\(',
                    'severity': 'HIGH',
                    'description': 'raw() helper bypasses HTML escaping',
                    'recommendation': 'Remove raw() or use sanitize() for user-generated content',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'<%=\s*(?!h\s).*?params\[',
                    'severity': 'HIGH',
                    'description': 'Unescaped ERB output with params',
                    'recommendation': 'Use <%=h or <%= sanitize() for params',
                    'cwe': 'CWE-79',
                },
                {
                    'pattern': r'content_tag.*?params\[.*?\].*?escape\s*=>\s*false',
                    'severity': 'HIGH',
                    'description': 'content_tag with escaping disabled',
                    'recommendation': 'Remove escape: false or sanitize content',
                    'cwe': 'CWE-79',
                },
            ],
            'command_injection': [
                {
                    'pattern': r'\bsystem\s*\([^)]*params\[',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via system() with params',
                    'recommendation': 'Never use params in shell commands. Use Shellwords.escape or array form.',
                    'cwe': 'CWE-78',
                },
                {
                    'pattern': r'`.*?#\{.*?params',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via backtick execution',
                    'recommendation': 'Use Open3.capture3 with array arguments',
                    'cwe': 'CWE-78',
                },
                {
                    'pattern': r'\bexec\s*\([^)]*params',
                    'severity': 'CRITICAL',
                    'description': 'Command injection via exec',
                    'recommendation': 'Use spawn with array arguments instead of exec',
                    'cwe': 'CWE-78',
                },
                {
                    'pattern': r'%x\{.*?params',
                    'severity': 'CRITICAL',
                    'description': '%x command execution with params',
                    'recommendation': 'Use Open3 with array arguments',
                    'cwe': 'CWE-78',
                },
            ],
            'mass_assignment': [
                {
                    'pattern': r'\.new\s*\(params\[',
                    'severity': 'HIGH',
                    'description': 'Mass assignment vulnerability',
                    'recommendation': 'Use strong parameters to whitelist allowed attributes',
                    'cwe': 'CWE-915',
                },
                {
                    'pattern': r'\.create\s*\(params\[',
                    'severity': 'HIGH',
                    'description': 'Mass assignment in create',
                    'recommendation': 'Use strong parameters: params.require(:user).permit(:name, :email)',
                    'cwe': 'CWE-915',
                },
                {
                    'pattern': r'\.update\s*\(params\[',
                    'severity': 'HIGH',
                    'description': 'Mass assignment in update',
                    'recommendation': 'Use strong parameters to whitelist updatable fields',
                    'cwe': 'CWE-915',
                },
                {
                    'pattern': r'\.update_attributes\s*\(params\[',
                    'severity': 'HIGH',
                    'description': 'Mass assignment in update_attributes',
                    'recommendation': 'Use update with strong parameters',
                    'cwe': 'CWE-915',
                },
            ],
            'deserialization': [
                {
                    'pattern': r'YAML\.load\s*\(',
                    'severity': 'CRITICAL',
                    'description': 'Unsafe YAML deserialization (use YAML.safe_load)',
                    'recommendation': 'Use YAML.safe_load with permitted_classes whitelist',
                    'cwe': 'CWE-502',
                },
                {
                    'pattern': r'Marshal\.load\s*\(',
                    'severity': 'CRITICAL',
                    'description': 'Unsafe Marshal deserialization',
                    'recommendation': 'Avoid Marshal.load with untrusted data. Use JSON instead.',
                    'cwe': 'CWE-502',
                },
            ],
            'csrf': [
                {
                    'pattern': r'protect_from_forgery.*?:null_session',
                    'severity': 'MEDIUM',
                    'description': 'Weak CSRF protection (null_session)',
                    'recommendation': 'Use :exception or :reset_session for better CSRF protection',
                    'cwe': 'CWE-352',
                },
                {
                    'pattern': r'skip_before_action\s+:verify_authenticity_token',
                    'severity': 'HIGH',
                    'description': 'CSRF protection disabled',
                    'recommendation': 'Remove skip_before_action or use only for API endpoints',
                    'cwe': 'CWE-352',
                },
            ],
            'file_upload': [
                {
                    'pattern': r'params\[:file\]\.original_filename',
                    'severity': 'MEDIUM',
                    'description': 'Using original filename without sanitization',
                    'recommendation': 'Sanitize filename and validate file type',
                    'cwe': 'CWE-434',
                },
            ],
            'redirect': [
                {
                    'pattern': r'redirect_to\s+params\[',
                    'severity': 'MEDIUM',
                    'description': 'Open redirect via params',
                    'recommendation': 'Whitelist allowed redirect URLs or use only_path: true',
                    'cwe': 'CWE-601',
                },
            ],
        }

        self.safe_patterns = {
            'activerecord_safe': [
                r'\.where\([^)]*:\w+\s*=>',  # Hash conditions
                r'\.where\(\w+:',  # Symbol keys
                r'\.find\(',
                r'\.find_by\(',
            ],
            'strong_parameters': [
                r'\.require\(',
                r'\.permit\(',
            ],
        }

    def check_code(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check Rails code for security issues"""
        findings = []
        lines = code.splitlines()

        for category, patterns in self.unsafe_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']

                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if it's a false positive (has safe pattern)
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
                                'framework': 'Ruby on Rails',
                            }
                            findings.append(finding)

        # Check for missing features
        findings.extend(self._check_missing_security(code, file_path))

        return findings

    def _is_false_positive(self, line: str, all_lines: List[str], line_num: int) -> bool:
        """Check if detection is likely a false positive"""
        # Check context for safe patterns
        context_start = max(0, line_num - 3)
        context_end = min(len(all_lines), line_num + 3)
        context = ' '.join(all_lines[context_start:context_end])

        # Check for strong parameters
        if re.search(r'\.permit\(', context):
            return True

        # Check for safe ActiveRecord methods
        for safe_pattern in self.safe_patterns['activerecord_safe']:
            if re.search(safe_pattern, context):
                return True

        return False

    def _check_missing_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for missing security configurations"""
        findings = []

        # Check for secret key in config files
        if 'config/' in file_path and 'secret_key_base' in code:
            if re.search(r'secret_key_base\s*=\s*["\'][^"\']+["\']', code):
                findings.append({
                    'file_path': file_path,
                    'line_number': 1,
                    'severity': 'CRITICAL',
                    'category': 'hardcoded_secret',
                    'description': 'Hardcoded secret_key_base',
                    'recommendation': 'Use ENV["SECRET_KEY_BASE"] or Rails credentials',
                    'cwe': 'CWE-798',
                    'code_snippet': 'Hardcoded secret_key_base',
                    'framework': 'Ruby on Rails',
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
