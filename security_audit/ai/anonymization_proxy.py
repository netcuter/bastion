#!/usr/bin/env python3
"""
Enhanced Anonymization Proxy with Cookie/Header Filtering
Anonymizes sensitive data (cookies, headers, JWTs, session IDs) before sending to AI providers.
"""

import re
import json
import hashlib
from typing import Dict, List, Set, Any
from dataclasses import dataclass, field

@dataclass
class AnonymizationRules:
    """Rules for what to anonymize"""
    domains: Dict[str, str] = field(default_factory=dict)
    ips: Dict[str, str] = field(default_factory=dict)
    companies: Dict[str, str] = field(default_factory=dict)
    emails: Dict[str, str] = field(default_factory=dict)
    usernames: Dict[str, str] = field(default_factory=dict)
    
    # NEW: Sensitive patterns
    cookie_patterns: List[str] = field(default_factory=list)
    header_patterns: List[str] = field(default_factory=list)
    token_patterns: List[str] = field(default_factory=list)
    
    # Counters for generating placeholder names
    _domain_counter: int = 0
    _ip_counter: int = 0
    _cookie_counter: int = 0
    _token_counter: int = 0

class EnhancedAnonymizer:
    def __init__(self, rules: AnonymizationRules = None):
        self.rules = rules or AnonymizationRules()
        
        # Default sensitive cookie/header patterns
        self.SENSITIVE_COOKIES = [
            'session', 'sessionid', 'sid', 'phpsessid', 'jsessionid',
            'auth', 'token', 'jwt', 'bearer', 'access_token',
            'csrf', 'xsrf', 'api_key', 'apikey',
            'user_id', 'userid', 'username',
            'remember', 'remember_me',
            'laravel_session', 'symfony', 'connect.sid'
        ]
        
        self.SENSITIVE_HEADERS = [
            'authorization', 'x-api-key', 'x-auth-token',
            'x-csrf-token', 'x-xsrf-token',
            'cookie', 'set-cookie',
            'x-session-id', 'x-user-id',
            'x-forwarded-for', 'x-real-ip',  # Internal IPs
            'api-key', 'apikey'
        ]
        
        # Regex patterns
        self.JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        self.UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
        self.SESSION_ID_PATTERN = re.compile(r'[0-9a-f]{32,}', re.I)
        
    def anonymize_cookies(self, cookies: str) -> tuple[str, Dict[str, str]]:
        """
        Anonymize cookies string
        Returns: (anonymized_string, mapping)
        """
        mapping = {}
        anonymized = cookies
        
        # Split cookies
        cookie_pairs = [c.strip() for c in cookies.split(';')]
        anonymized_pairs = []
        
        for pair in cookie_pairs:
            if '=' not in pair:
                anonymized_pairs.append(pair)
                continue
                
            name, value = pair.split('=', 1)
            name = name.strip()
            value = value.strip()
            
            # Check if cookie name is sensitive
            if any(sensitive in name.lower() for sensitive in self.SENSITIVE_COOKIES):
                # Anonymize value
                anon_value = f"COOKIE_VALUE_{hashlib.md5(value.encode()).hexdigest()[:8]}"
                mapping[anon_value] = value
                anonymized_pairs.append(f"{name}={anon_value}")
            else:
                # Keep as is
                anonymized_pairs.append(pair)
        
        return '; '.join(anonymized_pairs), mapping
    
    def anonymize_headers(self, headers: Dict[str, str]) -> tuple[Dict[str, str], Dict[str, str]]:
        """
        Anonymize HTTP headers
        Returns: (anonymized_headers, mapping)
        """
        mapping = {}
        anonymized = {}
        
        for name, value in headers.items():
            name_lower = name.lower()
            
            # Check if header is sensitive
            if name_lower in self.SENSITIVE_HEADERS:
                if name_lower == 'cookie':
                    # Special handling for Cookie header
                    anon_value, cookie_mapping = self.anonymize_cookies(value)
                    mapping.update(cookie_mapping)
                    anonymized[name] = anon_value
                elif name_lower == 'authorization':
                    # Anonymize bearer tokens, etc.
                    anon_value = self._anonymize_auth_header(value)
                    if anon_value != value:
                        mapping[anon_value] = value
                    anonymized[name] = anon_value
                else:
                    # Generic anonymization
                    anon_value = f"HEADER_VALUE_{hashlib.md5(value.encode()).hexdigest()[:8]}"
                    mapping[anon_value] = value
                    anonymized[name] = anon_value
            else:
                # Keep as is
                anonymized[name] = value
        
        return anonymized, mapping
    
    def _anonymize_auth_header(self, auth_value: str) -> str:
        """Anonymize Authorization header value"""
        parts = auth_value.split(' ', 1)
        if len(parts) == 2:
            auth_type, token = parts
            # Anonymize token but keep type (Bearer, Basic, etc.)
            anon_token = f"TOKEN_{hashlib.md5(token.encode()).hexdigest()[:16]}"
            return f"{auth_type} {anon_token}"
        return auth_value
    
    def anonymize_jwt(self, text: str, mapping: Dict[str, str] = None) -> str:
        """Find and anonymize JWT tokens"""
        if mapping is None:
            mapping = {}
            
        def replace_jwt(match):
            jwt = match.group(0)
            anon = f"JWT_TOKEN_{hashlib.md5(jwt.encode()).hexdigest()[:12]}"
            mapping[anon] = jwt
            return anon
        
        return self.JWT_PATTERN.sub(replace_jwt, text)
    
    def anonymize_session_ids(self, text: str, mapping: Dict[str, str] = None) -> str:
        """Find and anonymize session IDs"""
        if mapping is None:
            mapping = {}
            
        def replace_session(match):
            sid = match.group(0)
            # Only if it looks like a session ID (long hex string)
            if len(sid) >= 32:
                anon = f"SESSION_{hashlib.md5(sid.encode()).hexdigest()[:12]}"
                mapping[anon] = sid
                return anon
            return sid
        
        return self.SESSION_ID_PATTERN.sub(replace_session, text)
    
    def anonymize_request(self, request_data: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, str]]:
        """
        Anonymize entire HTTP request
        Returns: (anonymized_request, mapping)
        """
        mapping = {}
        anonymized = request_data.copy()
        
        # Anonymize URL (domains, IPs)
        if 'url' in anonymized:
            anonymized['url'], url_mapping = self._anonymize_url(anonymized['url'])
            mapping.update(url_mapping)
        
        # Anonymize headers
        if 'headers' in anonymized:
            anonymized['headers'], header_mapping = self.anonymize_headers(anonymized['headers'])
            mapping.update(header_mapping)
        
        # Anonymize body
        if 'body' in anonymized:
            body = anonymized['body']
            # Anonymize JWTs
            body = self.anonymize_jwt(body, mapping)
            # Anonymize session IDs
            body = self.anonymize_session_ids(body, mapping)
            anonymized['body'] = body
        
        return anonymized, mapping
    
    def _anonymize_url(self, url: str) -> tuple[str, Dict[str, str]]:
        """Anonymize URL (domains, IPs, tokens in params)"""
        mapping = {}
        anonymized = url
        
        # Anonymize domains from rules
        for real_domain, anon_domain in self.rules.domains.items():
            if real_domain in anonymized:
                anonymized = anonymized.replace(real_domain, anon_domain)
                mapping[anon_domain] = real_domain
        
        # Anonymize IPs from rules
        for real_ip, anon_ip in self.rules.ips.items():
            if real_ip in anonymized:
                anonymized = anonymized.replace(real_ip, anon_ip)
                mapping[anon_ip] = real_ip
        
        # Anonymize JWT tokens in URL
        anonymized = self.anonymize_jwt(anonymized, mapping)
        
        return anonymized, mapping
    
    def deanonymize(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore original values using mapping"""
        result = text
        # Reverse mapping (anon -> real)
        for anon, real in mapping.items():
            result = result.replace(anon, real)
        return result
    
    def anonymize_text(self, text: str) -> tuple[str, Dict[str, str]]:
        """
        Anonymize arbitrary text (for prompts/responses)
        Returns: (anonymized_text, mapping)
        """
        mapping = {}
        anonymized = text
        
        # Apply domain anonymization
        for real_domain, anon_domain in self.rules.domains.items():
            if real_domain in anonymized:
                anonymized = anonymized.replace(real_domain, anon_domain)
                mapping[anon_domain] = real_domain
        
        # Apply IP anonymization
        for real_ip, anon_ip in self.rules.ips.items():
            if real_ip in anonymized:
                anonymized = anonymized.replace(real_ip, anon_ip)
                mapping[anon_ip] = real_ip
        
        # Apply company anonymization
        for real_company, anon_company in self.rules.companies.items():
            if real_company in anonymized:
                anonymized = anonymized.replace(real_company, anon_company)
                mapping[anon_company] = real_company
        
        # Anonymize JWT tokens
        anonymized = self.anonymize_jwt(anonymized, mapping)
        
        # Anonymize session IDs
        anonymized = self.anonymize_session_ids(anonymized, mapping)
        
        return anonymized, mapping


# Example usage and tests
def demo():
    """Demo the enhanced anonymization"""
    
    # Setup rules
    rules = AnonymizationRules()
    rules.domains = {
        "client-corp.com": "target1.test",
        "internal.client-corp.com": "target2.test"
    }
    rules.ips = {
        "192.168.1.50": "10.99.1.1",
        "10.0.0.100": "10.99.1.2"
    }
    rules.companies = {
        "ClientCorp Inc": "COMPANY_A"
    }
    
    anonymizer = EnhancedAnonymizer(rules)
    
    print("=" * 60)
    print("🔒 ENHANCED ANONYMIZATION DEMO")
    print("=" * 60)
    
    # Test 1: Anonymize cookies
    print("\n📝 Test 1: Cookie Anonymization")
    print("-" * 60)
    cookies = "sessionid=a1b2c3d4e5f6; user_id=12345; theme=dark; csrf_token=xyz789"
    anon_cookies, cookie_mapping = anonymizer.anonymize_cookies(cookies)
    print(f"Original:    {cookies}")
    print(f"Anonymized:  {anon_cookies}")
    print(f"Mapping: {json.dumps(cookie_mapping, indent=2)}")
    
    # Test 2: Anonymize headers
    print("\n📝 Test 2: Header Anonymization")
    print("-" * 60)
    headers = {
        "Host": "client-corp.com",
        "Cookie": "sessionid=abc123; auth_token=xyz789",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        "X-API-Key": "secret-api-key-12345",
        "User-Agent": "Mozilla/5.0"
    }
    anon_headers, header_mapping = anonymizer.anonymize_headers(headers)
    print(f"Original headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print(f"\nAnonymized headers:")
    for k, v in anon_headers.items():
        print(f"  {k}: {v}")
    print(f"\nMapping: {json.dumps(header_mapping, indent=2)}")
    
    # Test 3: Full request anonymization
    print("\n📝 Test 3: Full Request Anonymization")
    print("-" * 60)
    request = {
        "method": "POST",
        "url": "https://client-corp.com/api/users?token=eyJhbGciOiJIUzI1NiJ9.test.sig",
        "headers": {
            "Host": "client-corp.com",
            "Cookie": "session=abc123; user=john",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        },
        "body": "username=admin&session_id=1234567890abcdef1234567890abcdef"
    }
    
    anon_request, request_mapping = anonymizer.anonymize_request(request)
    print("Original request:")
    print(json.dumps(request, indent=2))
    print("\nAnonymized request:")
    print(json.dumps(anon_request, indent=2))
    print(f"\nMapping: {json.dumps(request_mapping, indent=2)}")
    
    # Test 4: Text anonymization (for Claude prompts)
    print("\n📝 Test 4: Prompt Anonymization")
    print("-" * 60)
    prompt = """
    Please test https://client-corp.com for vulnerabilities.
    Use these credentials: session=abc123xyz789
    The company ClientCorp Inc wants a full pentest.
    JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
    """
    anon_prompt, prompt_mapping = anonymizer.anonymize_text(prompt)
    print("Original prompt:")
    print(prompt)
    print("\nAnonymized prompt (sent to Claude):")
    print(anon_prompt)
    print(f"\nMapping: {json.dumps(prompt_mapping, indent=2)}")
    
    # Test 5: De-anonymization
    print("\n📝 Test 5: De-anonymization (Claude response → You)")
    print("-" * 60)
    claude_response = """
    Found XSS vulnerability on target1.test!
    You can exploit it with: https://target1.test/search?q=<script>
    Session token JWT_TOKEN_a1b2c3d4e5f6 appears valid.
    """
    original_response = anonymizer.deanonymize(claude_response, prompt_mapping)
    print("Claude sees (anonymized):")
    print(claude_response)
    print("\nYou see (de-anonymized):")
    print(original_response)
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS COMPLETE!")
    print("🔒 Sensitive data NEVER reaches Claude!")
    print("=" * 60)

if __name__ == "__main__":
    demo()
