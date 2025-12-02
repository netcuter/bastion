#!/usr/bin/env python3
"""
Local AI Integration
Supports LM Studio, Ollama, and other local AI servers

100% local - no data leaves your machine
"""

import json
from typing import Dict, Optional


class LocalAIAssistant:
    """
    Local AI assistant for security analysis
    Works with LM Studio, Ollama, or any OpenAI-compatible local server
    """
    
    def __init__(self, server_url: str = 'http://localhost:1234', model: str = 'auto'):
        """
        Initialize local AI assistant
        
        Args:
            server_url: URL of local AI server (LM Studio default: http://localhost:1234)
            model: Model name or 'auto' to use server's loaded model
        """
        self.server_url = server_url.rstrip('/')
        self.model = model
        self.calls_made = 0
        
        # Try to import requests
        try:
            import requests
            self.requests = requests
        except ImportError:
            raise ImportError("Please install requests: pip install requests")
            
    def verify_finding(self, finding: Dict) -> bool:
        """
        Verify if a security finding is a real vulnerability
        
        Args:
            finding: Dict with 'type', 'code', 'description', etc.
            
        Returns:
            True if real vulnerability, False if false positive
        """
        
        prompt = self._build_verification_prompt(finding)
        
        try:
            response = self._call_local_ai(prompt)
            
            # Parse response
            answer = response.lower()
            is_real = 'true' in answer or 'real' in answer or 'vulnerable' in answer
            
            self.calls_made += 1
            return is_real
            
        except Exception as e:
            print(f"⚠️  Local AI verification failed: {e}")
            # On error, assume it's real (better safe than sorry)
            return True
            
    def _build_verification_prompt(self, finding: Dict) -> str:
        """Build prompt for vulnerability verification"""
        
        return f"""You are a security expert analyzing potential vulnerabilities.

Finding Type: {finding['type']}
Severity: {finding['severity']}
Code:
```
{finding['code']}
```

Description: {finding['description']}

Question: Is this a real security vulnerability or a false positive?

Consider:
1. Is the code actually exploitable?
2. Are there any protective measures in place?
3. Is the context appropriate for this pattern?

Answer with: TRUE (real vulnerability) or FALSE (false positive)
Then explain your reasoning in 1-2 sentences.

Format:
VERDICT: [TRUE/FALSE]
REASON: [your explanation]
"""

    def _call_local_ai(self, prompt: str, max_tokens: int = 500) -> str:
        """
        Call local AI server
        
        Args:
            prompt: The prompt to send
            max_tokens: Max tokens in response
            
        Returns:
            AI response text
        """
        
        url = f"{self.server_url}/v1/chat/completions"
        
        # Get model name if auto
        model = self.model
        if model == 'auto':
            model = self._get_loaded_model()
        
        data = {
            'model': model,
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are a security expert specializing in vulnerability analysis.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': max_tokens,
            'temperature': 0.1  # Low temperature for consistent analysis
        }
        
        try:
            response = self.requests.post(url, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            return result['choices'][0]['message']['content']
            
        except Exception as e:
            raise Exception(f"Local AI call failed: {e}")
            
    def _get_loaded_model(self) -> str:
        """Get the currently loaded model from local server"""
        
        try:
            url = f"{self.server_url}/v1/models"
            response = self.requests.get(url, timeout=10)
            response.raise_for_status()
            
            models = response.json()
            if models.get('data'):
                return models['data'][0]['id']
            else:
                return 'local-model'
                
        except Exception:
            # Fallback if models endpoint doesn't work
            return 'local-model'
            
    def test_connection(self) -> bool:
        """Test if local AI server is accessible"""
        
        try:
            url = f"{self.server_url}/v1/models"
            response = self.requests.get(url, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
            
    def get_stats(self) -> Dict:
        """Get usage statistics"""
        
        return {
            'calls_made': self.calls_made,
            'server_url': self.server_url,
            'model': self.model,
            'total_cost': 0.0  # Local AI is free!
        }


# Example usage
if __name__ == '__main__':
    import sys
    
    # Default to LM Studio URL
    server_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:1234'
    
    assistant = LocalAIAssistant(server_url=server_url)
    
    # Test connection
    if assistant.test_connection():
        print(f"✅ Connected to local AI: {server_url}")
    else:
        print(f"❌ Cannot connect to local AI: {server_url}")
        print(f"   Make sure LM Studio or Ollama is running")
        exit(1)
        
    # Test vulnerability verification
    test_finding = {
        'type': 'SQL Injection',
        'severity': 'HIGH',
        'code': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'description': 'F-string formatting in SQL query'
    }
    
    print("\n🔍 Testing vulnerability verification...")
    is_real = assistant.verify_finding(test_finding)
    stats = assistant.get_stats()
    
    print(f"\nVerdict: {'REAL VULNERABILITY' if is_real else 'FALSE POSITIVE'}")
    print(f"Calls made: {stats['calls_made']}")
    print(f"Cost: $0.00 (100% local)")
