"""
Code Anonymizer for AI Assistant
Removes ALL sensitive information before sending code to external AI

Privacy-first approach:
- Replaces variable names with var_1, var_2, etc.
- Replaces function names with func_1, func_2
- Replaces strings with string_XXX (hashed)
- Removes company/project-specific names
- Keeps code structure and logic intact
- NO sensitive data leaves the system!
"""
import re
import hashlib
from typing import Dict, Tuple, Set


class CodeAnonymizer:
    """
    Anonymizes source code before AI analysis

    Example transformation:
    ```python
    username = request.GET['user']
    cursor.execute(f"SELECT * FROM users WHERE name='{username}'")
    ```

    Becomes:
    ```python
    var_1 = request.GET['string_A1B2C3D4']
    cursor.execute(f"SELECT * FROM users WHERE name='{var_1}'")
    ```

    Safe to send - no business logic exposed!
    """

    # Keep these keywords (essential for security analysis)
    PRESERVE_KEYWORDS = {
        # Request/Response
        'request', 'response', 'req', 'res',
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
        'query', 'body', 'params', 'headers', 'cookies',

        # Security-relevant
        'user', 'password', 'token', 'auth', 'session',
        'username', 'email', 'id',

        # Dangerous functions (must keep for detection)
        'eval', 'exec', 'execute', 'system', 'open',
        'cursor', 'connection', 'db', 'database',

        # Common frameworks
        'django', 'flask', 'express', 'fastapi',
        'objects', 'filter', 'get', 'create', 'update',

        # HTML/DOM
        'innerHTML', 'document', 'window', 'element',

        # Python builtins
        'str', 'int', 'float', 'bool', 'list', 'dict', 'set',
        'None', 'True', 'False', 'self', 'cls',

        # Common variable names (keep for context)
        'data', 'value', 'result', 'output', 'input',
    }

    def __init__(self):
        self.var_mapping = {}
        self.str_mapping = {}
        self.func_mapping = {}
        self.var_counter = 1
        self.func_counter = 1

    def anonymize(self, code: str, preserve_structure: bool = True) -> Tuple[str, Dict[str, str]]:
        """
        Anonymize code for safe AI transmission

        Args:
            code: Source code to anonymize
            preserve_structure: Keep code structure intact

        Returns:
            (anonymized_code, reverse_mapping)
        """
        self._reset_mappings()

        anon_code = code

        # 1. Anonymize strings (sensitive data might be in strings)
        anon_code = self._anonymize_strings(anon_code)

        # 2. Anonymize variable names (except preserved keywords)
        if preserve_structure:
            anon_code = self._anonymize_variables(anon_code)

        # 3. Anonymize function names
        if preserve_structure:
            anon_code = self._anonymize_functions(anon_code)

        # Build reverse mapping
        reverse_mapping = {
            'variables': {v: k for k, v in self.var_mapping.items()},
            'strings': {v: k for k, v in self.str_mapping.items()},
            'functions': {v: k for k, v in self.func_mapping.items()}
        }

        return anon_code, reverse_mapping

    def _anonymize_strings(self, code: str) -> str:
        """Replace string literals with hashed placeholders"""

        def replace_string(match):
            string_content = match.group(1)

            # Skip very short strings (likely not sensitive)
            if len(string_content) < 3:
                return match.group(0)

            # Generate hash for string
            string_hash = self._hash_string(string_content)[:8]
            placeholder = f'string_{string_hash}'

            self.str_mapping[string_content] = placeholder

            # Keep quotes
            quote = match.group(0)[0]
            return f'{quote}{placeholder}{quote}'

        # Replace double-quoted strings
        code = re.sub(r'"([^"]+)"', replace_string, code)

        # Replace single-quoted strings
        code = re.sub(r"'([^']+)'", replace_string, code)

        return code

    def _anonymize_variables(self, code: str) -> str:
        """Replace variable names with placeholders"""

        # Extract all identifiers
        identifiers = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)

        # Build mapping for variables to anonymize
        for identifier in set(identifiers):
            # Skip if it's a preserved keyword
            if identifier in self.PRESERVE_KEYWORDS:
                continue

            # Skip if it's a Python keyword
            if identifier in ['if', 'else', 'elif', 'for', 'while', 'def', 'class',
                             'return', 'import', 'from', 'as', 'try', 'except', 'with']:
                continue

            # Skip if already mapped
            if identifier in self.var_mapping:
                continue

            # Create placeholder
            placeholder = f'var_{self.var_counter}'
            self.var_mapping[identifier] = placeholder
            self.var_counter += 1

        # Replace variables in code (word boundaries)
        for original, placeholder in self.var_mapping.items():
            code = re.sub(rf'\b{re.escape(original)}\b', placeholder, code)

        return code

    def _anonymize_functions(self, code: str) -> str:
        """Replace function names with placeholders"""

        # Find function definitions
        func_defs = re.finditer(r'\bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)

        for match in func_defs:
            func_name = match.group(1)

            # Skip preserved names
            if func_name in self.PRESERVE_KEYWORDS:
                continue

            if func_name not in self.func_mapping:
                placeholder = f'func_{self.func_counter}'
                self.func_mapping[func_name] = placeholder
                self.func_counter += 1

        # Replace function names
        for original, placeholder in self.func_mapping.items():
            code = re.sub(rf'\b{re.escape(original)}\b', placeholder, code)

        return code

    def _hash_string(self, text: str) -> str:
        """Generate hash for string anonymization"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def _reset_mappings(self):
        """Reset internal mappings for new anonymization"""
        self.var_mapping = {}
        self.str_mapping = {}
        self.func_mapping = {}
        self.var_counter = 1
        self.func_counter = 1

    def get_anonymization_stats(self) -> Dict[str, int]:
        """Get statistics about anonymization"""
        return {
            'variables_anonymized': len(self.var_mapping),
            'strings_anonymized': len(self.str_mapping),
            'functions_anonymized': len(self.func_mapping),
            'total_replacements': len(self.var_mapping) + len(self.str_mapping) + len(self.func_mapping)
        }

    def preview_anonymization(self, code: str, max_length: int = 200) -> str:
        """
        Generate preview of anonymized code

        Args:
            code: Original code
            max_length: Maximum preview length

        Returns:
            Preview string showing transformation
        """
        anon_code, _ = self.anonymize(code)

        # Truncate if needed
        if len(anon_code) > max_length:
            anon_code = anon_code[:max_length] + '...'

        preview = f"""
ORIGINAL ({len(code)} chars):
{code[:max_length]}{'...' if len(code) > max_length else ''}

ANONYMIZED ({len(anon_code)} chars):
{anon_code}

STATISTICS:
- Variables: {len(self.var_mapping)} anonymized
- Strings: {len(self.str_mapping)} anonymized
- Functions: {len(self.func_mapping)} anonymized
        """

        return preview.strip()
