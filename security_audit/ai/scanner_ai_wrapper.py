#!/usr/bin/env python3
"""
Security Scanner - AI Integration Wrapper
Version: 2.6.0

Supports:
- Cloud AI API (any OpenAI-compatible API)
- Local AI (LM Studio, Ollama, etc.)
- Traditional console mode (no AI)

All code is anonymized before sending to external APIs.
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Optional
from pathlib import Path


class SecurityScannerAI:
    """Main wrapper for AI-assisted security scanning"""
    
    def __init__(self, ai_mode: str = "none", ai_config: Optional[Dict] = None):
        """
        Initialize scanner with AI configuration
        
        Args:
            ai_mode: "cloud", "local", or "none"
            ai_config: Configuration dict with API keys, endpoints, etc.
        """
        self.ai_mode = ai_mode
        self.ai_config = ai_config or {}
        self.stats = {
            'total_findings': 0,
            'false_positives_filtered': 0,
            'api_calls': 0,
            'total_cost': 0.0
        }
        
    def scan(self, target_path: str, options: Optional[Dict] = None) -> Dict:
        """
        Run security scan with optional AI filtering
        
        Args:
            target_path: Path to scan
            options: Additional scan options
            
        Returns:
            Dict with findings and statistics
        """
        options = options or {}
        
        print(f"🔍 Starting security scan: {target_path}")
        print(f"🤖 AI Mode: {self.ai_mode}")
        
        # Step 1: Run security scan (mock for now)
        raw_findings = self._run_security_scan(target_path, options)
        print(f"📊 Raw findings: {len(raw_findings)}")
        
        # Step 2: Filter with AI if enabled
        if self.ai_mode != "none":
            filtered_findings = self._filter_with_ai(raw_findings)
            print(f"✅ After AI filtering: {len(filtered_findings)}")
        else:
            filtered_findings = raw_findings
            
        # Step 3: Generate report
        report = {
            'findings': filtered_findings,
            'statistics': {
                'total_raw': len(raw_findings),
                'total_filtered': len(filtered_findings),
                'false_positives_removed': len(raw_findings) - len(filtered_findings),
                'fp_reduction_rate': round((1 - len(filtered_findings)/len(raw_findings))*100, 2) if raw_findings else 0,
                'ai_calls': self.stats['api_calls'],
                'estimated_cost': round(self.stats['total_cost'], 4)
            }
        }
        
        return report
        
    def _run_security_scan(self, target_path: str, options: Dict) -> List[Dict]:
        """Run actual security scan - this is a mock implementation"""
        # TODO: Replace with real scanner integration
        # from security_audit.core.engine import SecurityEngine
        
        # Mock findings for demonstration
        mock_findings = [
            {
                'type': 'SQL Injection',
                'severity': 'HIGH',
                'file': 'app/database.py',
                'line': 42,
                'code': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                'description': 'Potential SQL injection via f-string formatting'
            },
            {
                'type': 'XSS',
                'severity': 'MEDIUM',
                'file': 'app/views.py',
                'line': 156,
                'code': 'return render_template("user.html", name=request.args.get("name"))',
                'description': 'User input rendered without escaping'
            },
            {
                'type': 'Hardcoded Secret',
                'severity': 'CRITICAL',
                'file': 'config/settings.py',
                'line': 12,
                'code': 'API_KEY = "sk-1234567890abcdef"',
                'description': 'Hardcoded API key in source code'
            },
            {
                'type': 'Weak Crypto',
                'severity': 'HIGH',
                'file': 'app/crypto.py',
                'line': 23,
                'code': 'hashlib.md5(password.encode()).hexdigest()',
                'description': 'MD5 used for password hashing'
            },
            {
                'type': 'Path Traversal',
                'severity': 'HIGH',
                'file': 'app/files.py',
                'line': 67,
                'code': 'open(os.path.join(UPLOAD_DIR, filename))',
                'description': 'User-controlled filename without validation'
            }
        ]
        
        return mock_findings
        
    def _filter_with_ai(self, findings: List[Dict]) -> List[Dict]:
        """Filter findings using AI to remove false positives"""
        
        if self.ai_mode == "cloud":
            return self._filter_with_cloud_api(findings)
        elif self.ai_mode == "local":
            return self._filter_with_local_ai(findings)
        else:
            return findings
            
    def _filter_with_cloud_api(self, findings: List[Dict]) -> List[Dict]:
        """Filter using cloud AI API with code anonymization"""
        try:
            from ai_cloud_api import CloudAIAssistant
            from code_anonymizer import CodeAnonymizer
            
            # Anonymize before sending to cloud
            anonymizer = CodeAnonymizer()
            
            assistant = CloudAIAssistant(
                api_key=self.ai_config.get('api_key'),
                api_base=self.ai_config.get('api_base', 'https://api.openai.com'),
                model=self.ai_config.get('model', 'fast')  # "fast" or "smart"
            )
            
            filtered = []
            for finding in findings:
                # Anonymize code before sending
                anon_code, mapping = anonymizer.anonymize(finding['code'])
                anon_finding = {**finding, 'code': anon_code}
                
                # Ask AI if it's a real vulnerability
                is_real = assistant.verify_finding(anon_finding)
                
                if is_real:
                    filtered.append(finding)
                else:
                    self.stats['false_positives_filtered'] += 1
                    
                self.stats['api_calls'] += 1
                
            self.stats['total_cost'] = assistant.get_total_cost()
            return filtered
            
        except ImportError as e:
            print(f"⚠️  Cloud AI not available: {e}")
            return findings
            
    def _filter_with_local_ai(self, findings: List[Dict]) -> List[Dict]:
        """Filter using local AI (LM Studio, Ollama, etc.)"""
        try:
            from ai_local import LocalAIAssistant
            
            assistant = LocalAIAssistant(
                server_url=self.ai_config.get('server_url', 'http://localhost:1234'),
                model=self.ai_config.get('model', 'auto')
            )
            
            filtered = []
            for finding in findings:
                is_real = assistant.verify_finding(finding)
                
                if is_real:
                    filtered.append(finding)
                else:
                    self.stats['false_positives_filtered'] += 1
                    
                self.stats['api_calls'] += 1
                
            return filtered
            
        except ImportError as e:
            print(f"⚠️  Local AI not available: {e}")
            return findings


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Security Scanner with AI-assisted false positive filtering'
    )
    
    parser.add_argument('command', choices=['scan'], help='Command to execute')
    parser.add_argument('--path', required=True, help='Path to scan')
    parser.add_argument('--ai-mode', choices=['cloud', 'local', 'none'], default='none',
                       help='AI assistance mode')
    parser.add_argument('--api-key', help='Cloud API key (for cloud mode)')
    parser.add_argument('--api-base', help='Cloud API base URL')
    parser.add_argument('--model', help='Model to use (fast/smart for cloud, auto for local)')
    parser.add_argument('--ai-server', help='Local AI server URL (for local mode)')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    # Build AI configuration
    ai_config = {}
    if args.ai_mode == 'cloud':
        if not args.api_key:
            print("❌ Error: --api-key required for cloud mode")
            sys.exit(1)
        ai_config['api_key'] = args.api_key
        if args.api_base:
            ai_config['api_base'] = args.api_base
        if args.model:
            ai_config['model'] = args.model
    elif args.ai_mode == 'local':
        if args.ai_server:
            ai_config['server_url'] = args.ai_server
        if args.model:
            ai_config['model'] = args.model
            
    # Run scanner
    scanner = SecurityScannerAI(ai_mode=args.ai_mode, ai_config=ai_config)
    results = scanner.scan(args.path)
    
    # Output results
    if args.json:
        output = json.dumps(results, indent=2)
    else:
        output = f"""
🔒 Security Scan Results
{'='*60}

📊 Statistics:
  • Raw findings: {results['statistics']['total_raw']}
  • After filtering: {results['statistics']['total_filtered']}
  • False positives removed: {results['statistics']['false_positives_removed']}
  • FP reduction rate: {results['statistics']['fp_reduction_rate']}%
  • AI calls made: {results['statistics']['ai_calls']}
  • Estimated cost: ${results['statistics']['estimated_cost']}

🔍 Findings ({len(results['findings'])} total):
"""
        for i, finding in enumerate(results['findings'], 1):
            output += f"""
  {i}. [{finding['severity']}] {finding['type']}
     File: {finding['file']}:{finding['line']}
     Code: {finding['code'][:80]}...
     Description: {finding['description']}
"""
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"✅ Results saved to: {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
