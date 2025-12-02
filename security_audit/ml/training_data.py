"""
Training Data Generator for False Positive Classifier
Examples of TRUE POSITIVES (real vulnerabilities) vs FALSE POSITIVES (safe code)

This data helps the classifier learn to distinguish between:
- Real vulnerabilities that need fixing
- False alarms from test files, examples, or safe patterns
"""
from typing import List, Dict, Any


class TrainingDataGenerator:
    """
    Generates training examples for ML classifier
    Labels: 0 = Real Vulnerability, 1 = False Positive
    """

    @staticmethod
    def get_training_data() -> List[Dict[str, Any]]:
        """
        Get labeled training examples

        Returns list of dictionaries with:
        - code: Code snippet
        - label: 0 (real vuln) or 1 (false positive)
        - type: Vulnerability type
        - reason: Why it's labeled this way
        """
        return [
            # ========== SQL INJECTION - REAL VULNERABILITIES ==========
            {
                'code': 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                'label': 0,  # Real vulnerability
                'type': 'sql_injection',
                'reason': 'f-string in SQL with user input - clear SQL injection'
            },
            {
                'code': 'query = "SELECT * FROM " + table + " WHERE id=" + str(id)',
                'label': 0,
                'type': 'sql_injection',
                'reason': 'String concatenation in SQL query'
            },
            {
                'code': 'User.objects.raw(f"SELECT * FROM users WHERE name=\'{name}\'")',
                'label': 0,
                'type': 'sql_injection',
                'reason': 'Django raw() with f-string interpolation'
            },

            # ========== SQL INJECTION - FALSE POSITIVES ==========
            {
                'code': 'User.objects.filter(id=user_id)',
                'label': 1,  # False positive - safe
                'type': 'sql_injection',
                'reason': 'Django ORM filter() is safe - uses parameterization'
            },
            {
                'code': 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
                'label': 1,
                'type': 'sql_injection',
                'reason': 'Parameterized query - safe from SQL injection'
            },
            {
                'code': '# Example: cursor.execute(f"SELECT * FROM {table}")',
                'label': 1,
                'type': 'sql_injection',
                'reason': 'Comment/example code - not actual execution'
            },
            {
                'code': 'test_query = f"SELECT * FROM users WHERE id={test_id}"  # test file',
                'label': 1,
                'type': 'sql_injection',
                'reason': 'Test code - intentional vulnerability for testing'
            },

            # ========== XSS - REAL VULNERABILITIES ==========
            {
                'code': 'element.innerHTML = user_input',
                'label': 0,
                'type': 'xss',
                'reason': 'Direct assignment to innerHTML with user input'
            },
            {
                'code': 'return mark_safe(request.GET["html"])',
                'label': 0,
                'type': 'xss',
                'reason': 'mark_safe() with user input bypasses escaping'
            },
            {
                'code': '<div dangerouslySetInnerHTML={{__html: userContent}} />',
                'label': 0,
                'type': 'xss',
                'reason': 'React dangerouslySetInnerHTML with user content'
            },

            # ========== XSS - FALSE POSITIVES ==========
            {
                'code': 'element.innerHTML = DOMPurify.sanitize(user_input)',
                'label': 1,
                'type': 'xss',
                'reason': 'DOMPurify sanitization prevents XSS'
            },
            {
                'code': 'return escape(user_data)',
                'label': 1,
                'type': 'xss',
                'reason': 'Explicit escaping function used'
            },
            {
                'code': '<div>{userInput}</div>  # React auto-escapes',
                'label': 1,
                'type': 'xss',
                'reason': 'React JSX automatically escapes - safe'
            },
            {
                'code': '"""Example: innerHTML = untrusted_data  # DON\'T DO THIS"""',
                'label': 1,
                'type': 'xss',
                'reason': 'Documentation example showing what NOT to do'
            },

            # ========== COMMAND INJECTION - REAL VULNERABILITIES ==========
            {
                'code': 'os.system(f"ls {directory}")',
                'label': 0,
                'type': 'command_injection',
                'reason': 'os.system() with f-string - command injection'
            },
            {
                'code': 'subprocess.run(cmd, shell=True)',
                'label': 0,
                'type': 'command_injection',
                'reason': 'shell=True allows command injection'
            },
            {
                'code': 'exec("import " + module_name)',
                'label': 0,
                'type': 'code_injection',
                'reason': 'Dynamic exec() with user input'
            },

            # ========== COMMAND INJECTION - FALSE POSITIVES ==========
            {
                'code': 'subprocess.run(["ls", directory], shell=False)',
                'label': 1,
                'type': 'command_injection',
                'reason': 'Array arguments with shell=False is safe'
            },
            {
                'code': 'cmd = shlex.quote(user_input); os.system(f"ls {cmd}")',
                'label': 1,
                'type': 'command_injection',
                'reason': 'shlex.quote() properly escapes shell arguments'
            },
            {
                'code': 'def test_command_injection():\n    os.system("rm -rf /")',
                'label': 1,
                'type': 'command_injection',
                'reason': 'Test function - intentional for security testing'
            },

            # ========== PATH TRAVERSAL - REAL VULNERABILITIES ==========
            {
                'code': 'open(request.GET["file"])',
                'label': 0,
                'type': 'path_traversal',
                'reason': 'Direct user input in file path'
            },
            {
                'code': 'file_path = "/uploads/" + filename',
                'label': 0,
                'type': 'path_traversal',
                'reason': 'Concatenation allows ../.. traversal'
            },

            # ========== PATH TRAVERSAL - FALSE POSITIVES ==========
            {
                'code': 'safe_filename = os.path.basename(user_file); open(safe_filename)',
                'label': 1,
                'type': 'path_traversal',
                'reason': 'basename() removes directory traversal'
            },
            {
                'code': 'from werkzeug.utils import secure_filename; open(secure_filename(name))',
                'label': 1,
                'type': 'path_traversal',
                'reason': 'secure_filename() validates and sanitizes'
            },

            # ========== HARDCODED SECRETS - REAL VULNERABILITIES ==========
            {
                'code': 'API_KEY = "sk_live_abc123xyz789"',
                'label': 0,
                'type': 'hardcoded_secret',
                'reason': 'Hardcoded API key in source code'
            },
            {
                'code': 'password = "admin123"',
                'label': 0,
                'type': 'hardcoded_secret',
                'reason': 'Hardcoded password'
            },

            # ========== HARDCODED SECRETS - FALSE POSITIVES ==========
            {
                'code': 'API_KEY = os.environ.get("API_KEY")',
                'label': 1,
                'type': 'hardcoded_secret',
                'reason': 'Reading from environment - correct practice'
            },
            {
                'code': '# Example API_KEY = "your-key-here"  # Replace with your key',
                'label': 1,
                'type': 'hardcoded_secret',
                'reason': 'Comment/documentation placeholder'
            },
            {
                'code': 'DEFAULT_PASSWORD = "changeme"  # Must be changed on first login',
                'label': 1,
                'type': 'hardcoded_secret',
                'reason': 'Documented default requiring change - acceptable pattern'
            },
        ]

    @staticmethod
    def get_statistics() -> Dict[str, Any]:
        """Get training data statistics"""
        data = TrainingDataGenerator.get_training_data()

        real_vulns = [d for d in data if d['label'] == 0]
        false_positives = [d for d in data if d['label'] == 1]

        by_type = {}
        for item in data:
            vuln_type = item['type']
            if vuln_type not in by_type:
                by_type[vuln_type] = {'real': 0, 'fp': 0}

            if item['label'] == 0:
                by_type[vuln_type]['real'] += 1
            else:
                by_type[vuln_type]['fp'] += 1

        return {
            'total_examples': len(data),
            'real_vulnerabilities': len(real_vulns),
            'false_positives': len(false_positives),
            'balance_ratio': round(len(real_vulns) / len(false_positives), 2),
            'by_type': by_type
        }

    @staticmethod
    def export_to_json(filepath: str):
        """Export training data to JSON file"""
        import json

        data = TrainingDataGenerator.get_training_data()

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Exported {len(data)} training examples to {filepath}")
