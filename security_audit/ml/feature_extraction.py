"""
Feature Extraction for ML-based FP Classification
Ekstrahuje features z findings dla Random Forest model

Features:
1. Code characteristics (complexity, length)
2. Context analysis (function names, imports)
3. Pattern matching (sanitization, validation)
4. File characteristics (path, type)
5. Vulnerability type features
"""
import re
from typing import Dict, List, Any


class FeatureExtractor:
    """
    Ekstrakt features z vulnerability findings dla ML classification
    """

    def __init__(self):
        self.feature_names = self._init_feature_names()

    def _init_feature_names(self) -> List[str]:
        """Return list of feature names (for model interpretation)"""
        return [
            # File characteristics
            'has_empty_code',
            'code_length',
            'is_config_file',
            'is_about_page',
            'path_depth',

            # Code complexity
            'cyclomatic_complexity',
            'nesting_depth',
            'num_lines',

            # Sanitization indicators
            'has_sanitization',
            'has_escape_function',
            'has_validation',

            # Safe patterns
            'has_safe_variable_names',
            'uses_parameterized_query',
            'uses_orm_methods',
            'shell_false',

            # Framework patterns
            'has_framework_safe_methods',

            # Comment indicators
            'has_todo_comment',
            'has_example_comment',

            # Vulnerability type indicators (one-hot encoding)
            'is_sql_injection',
            'is_xss',
            'is_command_injection',
            'is_path_traversal',
            'is_hardcoded_secret',
            'is_csrf',
            'is_missing_headers',
            'is_weak_crypto',
            'is_insecure_http',

            # Severity (ordinal encoding)
            'severity_critical',
            'severity_high',
            'severity_medium',
            'severity_low',

            # Code pattern indicators
            'has_string_concat',
            'has_f_string',
            'has_format',
            'has_innerHTML',
            'has_exec',
            'has_os_system',
        ]

    def extract(self, finding: Dict[str, Any]) -> List[float]:
        """
        Extract feature vector from finding

        Returns:
            List of feature values (floats)
        """
        features = []

        # Get finding data
        code = finding.get('code_snippet', '').strip()
        file_path = finding.get('file_path', '').lower()
        title = finding.get('title', '').lower()
        severity = finding.get('severity', '').upper()

        # === FILE CHARACTERISTICS ===

        # Empty code
        features.append(1.0 if len(code) < 10 else 0.0)

        # Code length (normalized)
        features.append(min(len(code) / 1000.0, 1.0))

        # Config file
        features.append(1.0 if any(p in file_path for p in ['settings.py', 'config.py', '.env']) else 0.0)

        # About/credits page
        features.append(1.0 if any(p in file_path for p in ['about', 'credits', 'readme']) else 0.0)

        # Path depth
        path_depth = file_path.count('/')
        features.append(min(path_depth / 10.0, 1.0))

        # === CODE COMPLEXITY ===

        # Cyclomatic complexity (count branches)
        branches = len(re.findall(r'\b(if|elif|else|for|while|try|except|catch)\b', code))
        features.append(min(branches / 10.0, 1.0))

        # Nesting depth (approx - count indentation levels)
        lines = code.split('\n')
        max_indent = 0
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                max_indent = max(max_indent, indent)
        features.append(min(max_indent / 20.0, 1.0))

        # Number of lines
        num_lines = len([l for l in lines if l.strip()])
        features.append(min(num_lines / 50.0, 1.0))

        # === SANITIZATION INDICATORS ===

        # Has sanitization
        sanitization_patterns = ['sanitize', 'clean', 'validate', 'filter']
        features.append(1.0 if any(p in code.lower() for p in sanitization_patterns) else 0.0)

        # Has escape function
        escape_patterns = ['escape(', 'htmlspecialchars', 'DOMPurify', 'Markup.escape']
        features.append(1.0 if any(p in code for p in escape_patterns) else 0.0)

        # Has validation
        validation_patterns = ['if.*valid', 'check.*input', 'verify.*']
        features.append(1.0 if any(re.search(p, code, re.I) for p in validation_patterns) else 0.0)

        # === SAFE PATTERNS ===

        # Safe variable names
        safe_var_patterns = [r'\bsafe_', r'\bclean_', r'\bsanitized_', r'\bvalidated_']
        features.append(1.0 if any(re.search(p, code, re.I) for p in safe_var_patterns) else 0.0)

        # Parameterized query
        param_patterns = [r'\.execute\([^\)]*,\s*\[', r'\.execute\([^\)]*,\s*\(', 'prepare\\(']
        features.append(1.0 if any(re.search(p, code) for p in param_patterns) else 0.0)

        # ORM methods
        orm_patterns = [r'\.filter\(', r'\.get\(', r'\.all\(', r'Q\(']
        features.append(1.0 if any(re.search(p, code) for p in orm_patterns) else 0.0)

        # shell=False
        features.append(1.0 if 'shell=false' in code.lower() or 'shell = false' in code.lower() else 0.0)

        # === FRAMEWORK PATTERNS ===

        framework_safe = [
            r'render_template\(',  # Flask auto-escapes
            r'\.objects\.',        # Django ORM
            r'shlex\.quote',       # Safe shell escaping
        ]
        features.append(1.0 if any(re.search(p, code, re.I) for p in framework_safe) else 0.0)

        # === COMMENT INDICATORS ===

        # TODO comment
        features.append(1.0 if re.search(r'#\s*TODO', code, re.I) else 0.0)

        # Example comment
        example_patterns = ['# Example', '// Example', '"""Example', '/*Example']
        features.append(1.0 if any(p in code for p in example_patterns) else 0.0)

        # === VULNERABILITY TYPE (one-hot) ===

        features.append(1.0 if 'sql injection' in title else 0.0)
        features.append(1.0 if 'xss' in title or 'cross-site scripting' in title else 0.0)
        features.append(1.0 if 'command injection' in title or 'code injection' in title else 0.0)
        features.append(1.0 if 'path traversal' in title else 0.0)
        features.append(1.0 if 'hardcoded' in title or 'credential' in title else 0.0)
        features.append(1.0 if 'csrf' in title else 0.0)
        features.append(1.0 if 'missing security headers' in title or 'missing.*header' in title else 0.0)
        features.append(1.0 if 'weak crypto' in title or 'weak encryption' in title else 0.0)
        features.append(1.0 if 'insecure http' in title or 'http://' in title else 0.0)

        # === SEVERITY (one-hot) ===

        features.append(1.0 if severity == 'CRITICAL' else 0.0)
        features.append(1.0 if severity == 'HIGH' else 0.0)
        features.append(1.0 if severity == 'MEDIUM' else 0.0)
        features.append(1.0 if severity == 'LOW' else 0.0)

        # === CODE PATTERN INDICATORS ===

        # String concatenation
        features.append(1.0 if ' + ' in code else 0.0)

        # f-string
        features.append(1.0 if "f'" in code or 'f"' in code else 0.0)

        # .format()
        features.append(1.0 if '.format(' in code else 0.0)

        # innerHTML
        features.append(1.0 if 'innerhtml' in code.lower() or 'dangerouslysetinnerhtml' in code.lower() else 0.0)

        # exec(
        features.append(1.0 if 'exec(' in code.lower() or 'eval(' in code.lower() else 0.0)

        # os.system
        features.append(1.0 if 'os.system' in code.lower() or 'subprocess.' in code.lower() else 0.0)

        return features

    def extract_batch(self, findings: List[Dict[str, Any]]) -> List[List[float]]:
        """
        Extract features from multiple findings

        Returns:
            List of feature vectors
        """
        return [self.extract(f) for f in findings]

    def get_feature_names(self) -> List[str]:
        """Return feature names for model interpretation"""
        return self.feature_names

    def print_feature_stats(self, feature_matrix: List[List[float]]):
        """Print statistics about extracted features"""
        import statistics

        print("\n" + "="*70)
        print("FEATURE EXTRACTION STATISTICS")
        print("="*70)

        for i, name in enumerate(self.feature_names):
            values = [row[i] for row in feature_matrix]
            mean_val = statistics.mean(values)
            nonzero = sum(1 for v in values if v > 0)
            pct_nonzero = nonzero / len(values) * 100

            print(f"{name:40s} Mean: {mean_val:.3f}, NonZero: {pct_nonzero:.1f}%")

        print("="*70 + "\n")


def test_feature_extraction():
    """Test feature extraction on sample finding"""
    extractor = FeatureExtractor()

    # Test finding
    test_finding = {
        'title': 'SQL Injection',
        'severity': 'CRITICAL',
        'file_path': '/home/user/project/app/views.py',
        'code_snippet': '''
        search_term = request.GET['search']
        query = f"SELECT * FROM users WHERE name = '{search_term}'"
        cursor.execute(query)
        ''',
        'description': 'SQL injection vulnerability'
    }

    features = extractor.extract(test_finding)

    print("Test Feature Extraction:")
    print("="*70)
    print(f"Finding: {test_finding['title']}")
    print(f"Features extracted: {len(features)}")
    print(f"Expected features: {len(extractor.feature_names)}")
    print()
    print("Feature values:")
    for name, value in zip(extractor.feature_names, features):
        if value > 0:
            print(f"  {name:40s} = {value:.2f}")
    print("="*70)


if __name__ == '__main__':
    test_feature_extraction()
