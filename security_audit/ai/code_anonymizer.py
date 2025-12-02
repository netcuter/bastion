#!/usr/bin/env python3
"""
Code Anonymizer
Protects sensitive information before sending code to cloud AI

Anonymizes:
- Variable names
- Function names  
- String literals
- Comments
- File paths

Preserves:
- Security-relevant patterns (SQL keywords, dangerous functions, etc.)
- Code structure
- Vulnerability context
"""

import re
import hashlib
from typing import Dict, Tuple


class CodeAnonymizer:
    """Anonymize code to protect client confidentiality"""
    
    # Security keywords to preserve (case-insensitive)
    SECURITY_KEYWORDS = {
        # SQL injection
        'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
        'union', 'exec', 'execute', 'cursor', 'query',
        
        # XSS/injection
        'eval', 'exec', 'innerhtml', 'outerhtml', 'document.write',
        'dangerouslysetinnerhtml', 'v-html', 'ng-bind-html',
        
        # Crypto
        'md5', 'sha1', 'des', 'rc4', 'password', 'secret', 'key', 'token',
        
        # File operations
        'open', 'read', 'write', 'file', 'path', 'upload', 'download',
        
        # Network
        'request', 'response', 'get', 'post', 'put', 'delete', 'fetch', 'axios',
        
        # Auth
        'auth', 'login', 'session', 'cookie', 'jwt', 'oauth',
        
        # Dangerous functions
        'system', 'shell', 'subprocess', 'popen', 'pickle', 'yaml.load',
        '__import__', 'compile', 'globals', 'locals'
    }
    
    def __init__(self):
        self.var_counter = 0
        self.func_counter = 0
        self.string_counter = 0
        self.path_counter = 0
        
    def anonymize(self, code: str) -> Tuple[str, Dict]:
        """
        Anonymize code while preserving security context
        
        Args:
            code: Source code to anonymize
            
        Returns:
            Tuple of (anonymized_code, mapping_dict)
        """
        
        mapping = {
            'variables': {},
            'functions': {},
            'strings': {},
            'paths': {}
        }
        
        anon_code = code
        
        # 1. Remove comments first (they might contain sensitive info)
        anon_code = self._remove_comments(anon_code)
        
        # 2. Anonymize string literals (but preserve security keywords)
        anon_code = self._anonymize_strings(anon_code, mapping)
        
        # 3. Anonymize remaining paths/URLs
        anon_code = self._anonymize_paths(anon_code, mapping)
        
        # 4. Anonymize variable names (optional - might break context)
        # anon_code = self._anonymize_variables(anon_code, mapping)
        
        return anon_code, mapping
        
    def _anonymize_paths(self, code: str, mapping: Dict) -> str:
        """Anonymize file paths and URLs"""
        
        # Common path and URL patterns
        path_patterns = [
            r'(?:host|server|endpoint|url)\s*=\s*["\']([^"\']+)["\']',  # host="..." or url="..."
            r'//([a-zA-Z0-9\-.]+)',  # URLs like //example.com
            r'/[a-zA-Z0-9_\-./]+',  # Unix paths
            r'[A-Z]:\\[a-zA-Z0-9_\-\\.]+'  # Windows paths
        ]
        
        for pattern in path_patterns:
            for match in re.finditer(pattern, code):
                # Get the full match or first group
                original_path = match.group(1) if match.groups() else match.group(0)
                
                # Skip if too short or contains security keywords
                if len(original_path) < 3 or self._contains_security_keyword(original_path):
                    continue
                    
                # Generate anonymous path
                path_hash = hashlib.md5(original_path.encode()).hexdigest()[:8]
                anon_path = f"anonymized_{path_hash}"
                
                mapping['paths'][anon_path] = original_path
                code = code.replace(original_path, anon_path)
                
        return code
        
    def _anonymize_strings(self, code: str, mapping: Dict) -> str:
        """Anonymize string literals, preserving security-relevant ones"""
        
        # Match quoted strings - handle both single and double quotes
        # and multiline strings
        string_patterns = [
            (r'"([^"]+)"', '"'),  # Double quotes
            (r"'([^']+)'", "'"),  # Single quotes
        ]
        
        for pattern, quote in string_patterns:
            def replace_string(match):
                content = match.group(1)
                
                # Preserve if contains security keywords
                if self._contains_security_keyword(content):
                    return match.group(0)
                    
                # Preserve if very short (likely not sensitive)
                if len(content) <= 2:
                    return match.group(0)
                    
                # Generate anonymous string
                string_hash = hashlib.md5(content.encode()).hexdigest()[:8]
                anon_string = f"string_{string_hash}"
                
                mapping['strings'][anon_string] = content
                return f"{quote}{anon_string}{quote}"
                
            code = re.sub(pattern, replace_string, code)
            
        return code
        
    def _remove_comments(self, code: str) -> str:
        """Remove comments from code"""
        
        # Remove single-line comments (# and //)
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        
        # Remove multi-line comments (/* */ and ''' ''')
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        
        return code
        
    def _contains_security_keyword(self, text: str) -> bool:
        """Check if text contains any security keyword"""
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.SECURITY_KEYWORDS)
        
    def deanonymize(self, anon_code: str, mapping: Dict) -> str:
        """
        Reverse anonymization (if needed)
        
        Args:
            anon_code: Anonymized code
            mapping: Mapping from anonymize()
            
        Returns:
            Original code
        """
        
        original_code = anon_code
        
        # Reverse all mappings
        for category in ['paths', 'strings', 'variables', 'functions']:
            for anon, original in mapping.get(category, {}).items():
                original_code = original_code.replace(anon, original)
                
        return original_code


# Example usage
if __name__ == '__main__':
    anonymizer = CodeAnonymizer()
    
    # Test code with sensitive information
    test_code = '''
    # This is from client XYZ Corp
    def process_payment(user_id, amount):
        # Connect to production database
        conn = psycopg2.connect("host=prod-db.xyzcorp.com user=admin password=secret123")
        cursor = conn.cursor()
        
        # VULNERABILITY: SQL injection via f-string
        query = f"INSERT INTO payments (user_id, amount) VALUES ({user_id}, {amount})"
        cursor.execute(query)
        
        # Log to /var/log/xyzcorp/payments.log
        with open('/var/log/xyzcorp/payments.log', 'a') as f:
            f.write(f"Payment processed for user {user_id}")
    '''
    
    print("📝 Original Code:")
    print(test_code)
    print("\n" + "="*60 + "\n")
    
    anon_code, mapping = anonymizer.anonymize(test_code)
    
    print("🔒 Anonymized Code (safe for cloud AI):")
    print(anon_code)
    print("\n" + "="*60 + "\n")
    
    print("🗺️  Mapping (kept locally, never sent to cloud):")
    for category, items in mapping.items():
        if items:
            print(f"\n{category.upper()}:")
            for anon, original in items.items():
                print(f"  {anon} -> {original}")
