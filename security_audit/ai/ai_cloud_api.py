#!/usr/bin/env python3
"""
Cloud AI API Integration
Supports any OpenAI-compatible API endpoint

CONFIGURATION:
- For OpenAI: Set API_BASE to https://api.openai.com
- For Anthropic: Set API_BASE to https://api.anthropic.com  
- For others: Check provider documentation

No vendor lock-in - works with multiple providers.
"""

import os
import json
from typing import Dict, List, Optional


class CloudAIAssistant:
    """
    Generic cloud AI assistant for security analysis
    Compatible with OpenAI-compatible APIs
    """
    
    # Pricing per 1M tokens (configurable)
    PRICING = {
        'fast': {
            'input': 0.25,   # $0.25 per 1M input tokens
            'output': 1.25   # $1.25 per 1M output tokens
        },
        'smart': {
            'input': 3.0,    # $3.00 per 1M input tokens  
            'output': 15.0   # $15.00 per 1M output tokens
        }
    }
    
    def __init__(self, api_key: str, api_base: str = None, model: str = 'fast'):
        """
        Initialize AI assistant
        
        Args:
            api_key: API key for authentication
            api_base: Base URL for API (optional)
            model: Model tier - 'fast' or 'smart'
        """
        self.api_key = api_key
        self.api_base = api_base
        self.model_tier = model
        
        self.input_tokens = 0
        self.output_tokens = 0
        
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
            response = self._call_api(prompt)
            
            # Parse response
            answer = response.lower()
            is_real = 'true' in answer or 'real' in answer or 'vulnerable' in answer
            
            return is_real
            
        except Exception as e:
            print(f"⚠️  AI verification failed: {e}")
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

    def _call_api(self, prompt: str, max_tokens: int = 500) -> str:
        """
        Call the AI API
        
        Args:
            prompt: The prompt to send
            max_tokens: Max tokens in response
            
        Returns:
            AI response text
        """
        
        # Build request based on API type
        if self.api_base and 'api.anthropic.com' in self.api_base:
            # Anthropic-compatible API
            return self._call_messages_api(prompt, max_tokens)
        else:
            # OpenAI-compatible API
            return self._call_openai_compatible_api(prompt, max_tokens)
            
    def _call_messages_api(self, prompt: str, max_tokens: int) -> str:
        """Call messages-style API (Anthropic-compatible)"""
        
        url = f"{self.api_base}/v1/messages"
        
        # Map model tier to actual model names
        # These are example mappings - adjust for your API provider
        model_map = {
            'fast': 'claude-haiku-3-5-20241022',      # Fast, economical model
            'smart': 'claude-sonnet-4-20250514'       # High-accuracy model
        }
        
        headers = {
            'anthropic-version': '2023-06-01',
            'x-api-key': self.api_key,
            'content-type': 'application/json'
        }
        
        data = {
            'model': model_map.get(self.model_tier, model_map['fast']),
            'max_tokens': max_tokens,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ]
        }
        
        response = self.requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        # Track tokens
        self.input_tokens += result.get('usage', {}).get('input_tokens', 0)
        self.output_tokens += result.get('usage', {}).get('output_tokens', 0)
        
        return result['content'][0]['text']
        
    def _call_openai_compatible_api(self, prompt: str, max_tokens: int) -> str:
        """Call OpenAI-compatible API (OpenAI, LM Studio, Ollama, etc.)"""
        
        url = f"{self.api_base}/v1/chat/completions"
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': self.model_tier,
            'max_tokens': max_tokens,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ]
        }
        
        response = self.requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        # Track tokens if available
        usage = result.get('usage', {})
        self.input_tokens += usage.get('prompt_tokens', 0)
        self.output_tokens += usage.get('completion_tokens', 0)
        
        return result['choices'][0]['message']['content']
        
    def get_total_cost(self) -> float:
        """Calculate total cost based on token usage"""
        
        pricing = self.PRICING.get(self.model_tier, self.PRICING['fast'])
        
        input_cost = (self.input_tokens / 1_000_000) * pricing['input']
        output_cost = (self.output_tokens / 1_000_000) * pricing['output']
        
        return input_cost + output_cost
        
    def get_stats(self) -> Dict:
        """Get usage statistics"""
        
        return {
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'total_cost': self.get_total_cost(),
            'model_tier': self.model_tier
        }


# Example usage
if __name__ == '__main__':
    # Test with environment variables
    api_key = os.getenv('AI_API_KEY')
    api_base = os.getenv('AI_API_BASE', 'https://api.openai.com')  # or your provider's endpoint
    
    if not api_key:
        print("Set AI_API_KEY environment variable")
        exit(1)
        
    assistant = CloudAIAssistant(api_key=api_key, api_base=api_base, model='fast')
    
    test_finding = {
        'type': 'SQL Injection',
        'severity': 'HIGH',
        'code': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'description': 'F-string formatting in SQL query'
    }
    
    is_real = assistant.verify_finding(test_finding)
    stats = assistant.get_stats()
    
    print(f"Verdict: {'REAL VULNERABILITY' if is_real else 'FALSE POSITIVE'}")
    print(f"Cost: ${stats['total_cost']:.4f}")
