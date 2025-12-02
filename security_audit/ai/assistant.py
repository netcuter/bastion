"""
AI Assistant for Enhanced Vulnerability Analysis
Uses LOCAL LM Studio server (100% offline by default)

Features:
- 100% LOCAL - LM Studio server (localhost OR remote in LAN)
- Auto-detects model from LM Studio /v1/models endpoint
- Adjusts prompts for model type (DeepHat, Qwen Coder, generic)
- User consent optional (can auto-approve with --ai-always-consent)
- Code anonymization before analysis
- Works offline without internet
"""
import json
import requests
from typing import Dict, List, Any, Optional, Tuple

from .anonymizer import CodeAnonymizer


class AIAssistant:
    """
    LOCAL AI-powered vulnerability analysis using LM Studio

    Privacy & Security:
    1. 100% LOCAL - no external APIs
    2. Works with localhost OR remote LM Studio server in LAN
    3. Auto-detects model from server
    4. Optional code anonymization
    5. Optional user consent system

    Server configuration:
    - http://localhost:1234 (default - local LM Studio)
    - http://192.168.1.100:1234 (remote server in LAN)
    - http://10.0.0.50:8080 (custom port)

    Supported models:
    - DeepHat (security specialist) - uses CWE/MITRE prompts
    - Qwen2.5-Coder (code specialist) - uses code-focused prompts
    - Any other model - uses generic security prompts
    """

    def __init__(self, server_url: str = "http://localhost:1234",
                 enabled: bool = False, always_consent: bool = False):
        """
        Initialize AI Assistant with LM Studio

        Args:
            server_url: LM Studio server URL (default: http://localhost:1234)
            enabled: Enable AI assistant
            always_consent: Auto-approve all AI requests (skip prompts)
        """
        self.enabled = enabled
        self.server_url = server_url.rstrip('/') + '/v1'
        self.always_consent = always_consent
        self.never_consent = False
        self.anonymizer = CodeAnonymizer()

        # Model info (auto-detected)
        self.model = None
        self.model_info = {}
        self.model_type = 'generic'  # 'deephat', 'qwen-coder', or 'generic'

        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'consents_given': 0,
            'consents_denied': 0,
            'vulnerabilities_confirmed': 0,
            'false_positives_caught': 0,
        }

        # Initialize connection to LM Studio
        if self.enabled:
            self._initialize_connection()

    def _initialize_connection(self) -> bool:
        """
        Connect to LM Studio and auto-detect model

        Returns:
            True if successfully connected
        """
        try:
            # 1. Check if LM Studio server is reachable
            response = requests.get(
                f"{self.server_url}/models",
                timeout=5
            )

            if response.status_code != 200:
                print(f"\n⚠️  LM Studio server not responding: {self.server_url}")
                print("   Make sure LM Studio is running with a loaded model")
                self.enabled = False
                return False

            # 2. Get available models
            models_data = response.json()

            if not models_data.get('data'):
                print(f"\n⚠️  No models loaded in LM Studio: {self.server_url}")
                print("   Please load a model in LM Studio first")
                self.enabled = False
                return False

            # 3. Auto-select first loaded model
            first_model = models_data['data'][0]
            self.model = first_model.get('id', 'local-model')
            self.model_info = first_model

            # 4. Detect model type for optimized prompts
            model_name = self.model.lower()
            if 'deephat' in model_name:
                self.model_type = 'deephat'
            elif 'qwen' in model_name and 'coder' in model_name:
                self.model_type = 'qwen-coder'
            else:
                self.model_type = 'generic'

            # 5. Display connection info
            print(f"\n✅ LM Studio connected!")
            print(f"   Server: {self.server_url}")
            print(f"   Model: {self.model}")

            if self.model_type == 'deephat':
                print(f"   🎩 Security specialist detected! (DeepHat)")
                print(f"      → Using CWE/MITRE-focused prompts")
            elif self.model_type == 'qwen-coder':
                print(f"   💻 Code specialist detected! (Qwen Coder)")
                print(f"      → Using code-focused security prompts")
            else:
                print(f"   🤖 Generic model detected")
                print(f"      → Using standard security prompts")

            if self.always_consent:
                print(f"   ⚡ Auto-consent enabled (no prompts)")

            print()

            return True

        except requests.exceptions.ConnectionError:
            print(f"\n❌ Cannot connect to LM Studio: {self.server_url}")
            print("   Make sure LM Studio server is running!")
            print("   Check: Server → Enable CORS → Start server")
            self.enabled = False
            return False

        except Exception as e:
            print(f"\n⚠️  LM Studio initialization error: {e}")
            self.enabled = False
            return False

    def analyze_finding(self, finding: Dict[str, Any],
                       ask_permission: bool = True) -> Optional[Dict[str, Any]]:
        """
        Analyze vulnerability finding with local AI

        Args:
            finding: Vulnerability finding dictionary
            ask_permission: Whether to ask for user consent

        Returns:
            AI analysis result or None if disabled/denied
        """

        # Check if AI is enabled
        if not self.enabled or self.never_consent:
            return None

        # Ask for permission (unless always_consent is True)
        if ask_permission and not self.always_consent:
            consent = self._ask_user_consent(finding)

            if consent == 'never':
                self.never_consent = True
                return None
            elif consent == 'always':
                self.always_consent = True
                # Continue to analysis
            elif consent == 'no':
                self.stats['consents_denied'] += 1
                return None
            elif consent != 'yes':
                return None

        self.stats['consents_given'] += 1

        # Anonymize code
        code = finding.get('code_snippet', '')
        if not code:
            return None

        anon_code, mapping = self.anonymizer.anonymize(code)

        # Build AI prompt (optimized for model type)
        system_prompt, user_prompt = self._build_analysis_prompt(finding, anon_code)

        # Call LM Studio API
        result = self._call_lmstudio_api(system_prompt, user_prompt)

        # Update statistics
        self.stats['total_analyzed'] += 1
        if result and result.get('is_real_vulnerability'):
            self.stats['vulnerabilities_confirmed'] += 1
        else:
            self.stats['false_positives_caught'] += 1

        return result

    def _ask_user_consent(self, finding: Dict[str, Any]) -> str:
        """
        Ask user for permission to analyze with AI

        Returns: 'yes', 'no', 'always', or 'never'
        """
        print("\n" + "="*70)
        print("🤖 LOCAL AI ASSISTANT - Prosi o Pozwolenie")
        print("="*70)
        print(f"\nPodatność do analizy:")
        print(f"  Typ: {finding.get('title', 'Unknown')}")
        print(f"  Severity: {finding.get('severity', 'Unknown')}")
        print(f"  Plik: {finding.get('file_path', 'Unknown')}")
        print(f"  Linia: {finding.get('line_number', '?')}")

        print(f"\n🖥️  Model LLM: {self.model}")
        print(f"   Server: {self.server_url}")
        print(f"   Typ: {self.model_type.upper()}")

        print("\n⚠️  Kod będzie wysłany do LOKALNEGO serwera LM Studio")
        print("   (100% offline, bez internetu)")

        print("\nOpcje:")
        print("  [y]      Tak, wyślij TEN finding do analizy")
        print("  [N]      Nie, pomiń (domyślnie)")
        print("  [always] Tak, automatycznie dla CAŁEGO projektu")
        print("  [never]  Nigdy nie pytaj w tej sesji (wyłącz AI)")

        try:
            choice = input("\nTwój wybór [y/N/always/never]: ").strip().lower()

            if choice == 'y' or choice == 'yes':
                return 'yes'
            elif choice == 'always':
                print("\n✅ AI Assistant włączony automatycznie dla całego projektu!\n")
                return 'always'
            elif choice == 'never':
                print("\n❌ AI Assistant wyłączony dla tej sesji.\n")
                return 'never'
            else:
                return 'no'
        except (KeyboardInterrupt, EOFError):
            print("\n\n❌ Przerwano. AI wyłączony.\n")
            return 'never'

    def _build_analysis_prompt(self, finding: Dict[str, Any],
                              anon_code: str) -> Tuple[str, str]:
        """
        Build AI analysis prompt optimized for model type

        Returns:
            (system_prompt, user_prompt)
        """

        # System prompt varies by model type
        if self.model_type == 'deephat':
            # DeepHat: security specialist with CWE/MITRE knowledge
            system_prompt = """You are DeepHat, a cybersecurity expert AI specialized in vulnerability analysis.
You have deep knowledge of OWASP Top 10, CWE Top 25, and MITRE ATT&CK framework.
Analyze code for security vulnerabilities with precision.
ALWAYS respond with VALID JSON only, no markdown, no explanations outside JSON."""

            user_prompt = f"""Analyze this potential {finding.get('title', 'vulnerability')}.

CODE (line {finding.get('line_number', '?')}):
```
{anon_code}
```

SUSPECTED VULNERABILITY:
- Type: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- CWE: {finding.get('cwe_id', 'Unknown')}
- Description: {finding.get('description', 'No description')}

ASSESSMENT CRITERIA:
1. Is this a REAL vulnerability or FALSE POSITIVE?
2. Can you trace user input → sink?
3. Is there sanitization/validation present?
4. Is this a framework-safe pattern?
5. What's the exploitability level?

Respond with VALID JSON:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "technical explanation of your assessment",
  "cwe_id": "CWE-XXX",
  "exploitability": "low/medium/high/critical",
  "attack_scenario": "brief description how this could be exploited",
  "recommendation": "specific fix recommendation"
}}"""

        elif self.model_type == 'qwen-coder':
            # Qwen Coder: code-focused security analysis
            system_prompt = """You are a code security expert specializing in vulnerability detection.
Analyze code for security issues using static analysis principles.
ALWAYS respond with VALID JSON only."""

            user_prompt = f"""Is this {finding.get('title', 'vulnerability')} REAL or FALSE POSITIVE?

CODE:
```
{anon_code}
```

FINDING:
- Type: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}

ANALYZE:
1. Real vulnerability or false positive?
2. Data flow: user input → dangerous operation?
3. Sanitization/validation present?
4. Safe framework pattern?

JSON response:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "technical explanation",
  "recommendation": "fix suggestion"
}}"""

        else:
            # Generic model: simple security prompt
            system_prompt = """You are a security code auditor.
Analyze code for vulnerabilities.
Respond ONLY with valid JSON."""

            user_prompt = f"""Is this {finding.get('title', 'issue')} a real vulnerability?

Code:
```
{anon_code}
```

Severity: {finding.get('severity', 'Unknown')}

JSON response:
{{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}}"""

        return system_prompt, user_prompt

    def _call_lmstudio_api(self, system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
        """
        Call LM Studio API (OpenAI-compatible)

        Args:
            system_prompt: System message
            user_prompt: User message

        Returns:
            Parsed JSON response or None
        """
        try:
            response = requests.post(
                f"{self.server_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.2,  # Low temperature for consistent security analysis
                    "max_tokens": 500,
                },
                timeout=30
            )

            if response.status_code != 200:
                print(f"⚠️  LM Studio API error: {response.status_code}")
                return None

            result = response.json()
            ai_response = result['choices'][0]['message']['content']

            # Parse JSON (handle markdown code blocks if model adds them)
            ai_response = ai_response.strip()
            if ai_response.startswith('```'):
                # Remove markdown code fences
                lines = ai_response.split('\n')
                ai_response = '\n'.join(lines[1:-1]) if len(lines) > 2 else ai_response
                if ai_response.startswith('json'):
                    ai_response = ai_response[4:].strip()

            # Parse JSON
            analysis = json.loads(ai_response.strip())

            return analysis

        except json.JSONDecodeError as e:
            print(f"⚠️  AI response not valid JSON: {e}")
            print(f"   Response was: {ai_response[:200]}")
            return None

        except requests.exceptions.Timeout:
            print(f"⚠️  LM Studio request timeout (>30s)")
            return None

        except Exception as e:
            print(f"⚠️  AI analysis error: {e}")
            return None

    def enhance_findings(self, findings: List[Dict[str, Any]],
                        max_analyze: int = None) -> Tuple[List[Dict], List[Dict]]:
        """
        Enhance findings with AI analysis

        Args:
            findings: List of vulnerability findings
            max_analyze: Maximum findings to analyze (None = all)

        Returns:
            (confirmed_vulnerabilities, likely_false_positives)
        """
        if not self.enabled:
            return findings, []

        confirmed = []
        false_positives = []

        count = 0
        total = len(findings)

        print(f"\n🤖 Analyzing {total} findings with LOCAL AI...")
        print(f"   Model: {self.model} ({self.model_type})")
        print(f"   Server: {self.server_url}\n")

        for i, finding in enumerate(findings, 1):
            # Limit if specified
            if max_analyze and count >= max_analyze:
                confirmed.append(finding)
                continue

            # Progress indicator
            if not self.always_consent:
                print(f"[{i}/{total}] Analyzing: {finding.get('title', 'Unknown')}")

            # Analyze with AI
            ai_result = self.analyze_finding(finding, ask_permission=True)

            if ai_result:
                finding['ai_analysis'] = ai_result
                finding['ai_model'] = self.model
                finding['ai_confidence'] = ai_result.get('confidence', 0.5)
                count += 1

                if ai_result.get('is_real_vulnerability', True):
                    confirmed.append(finding)
                    if self.always_consent:
                        print(f"   ✅ [{i}/{total}] REAL: {finding.get('title')} (confidence: {ai_result.get('confidence', 0):.1%})")
                else:
                    false_positives.append(finding)
                    if self.always_consent:
                        print(f"   ❌ [{i}/{total}] FALSE POSITIVE: {finding.get('title')} (confidence: {ai_result.get('confidence', 0):.1%})")
            else:
                # No AI analysis - keep original
                confirmed.append(finding)

        print(f"\n📊 AI Analysis Complete:")
        print(f"   ✅ Analyzed: {count}/{total}")
        print(f"   ✅ Real vulnerabilities: {len(confirmed)}")
        print(f"   ❌ False positives: {len(false_positives)}")

        return confirmed, false_positives

    def get_statistics(self) -> Dict[str, Any]:
        """Get AI assistant statistics"""
        return {
            **self.stats,
            'always_consent_enabled': self.always_consent,
            'never_consent_enabled': self.never_consent,
            'server_url': self.server_url,
            'model': self.model,
            'model_type': self.model_type,
            'connected': self.enabled,
        }

    def print_statistics(self):
        """Print AI assistant statistics"""
        stats = self.get_statistics()

        print("\n" + "="*70)
        print("🤖 LOCAL AI ASSISTANT - Statystyki Sesji")
        print("="*70)
        print(f"Server: {stats['server_url']}")
        print(f"Model: {stats['model']} ({stats['model_type']})")
        print(f"Connected: {'✅ Yes' if stats['connected'] else '❌ No'}")
        print(f"\nTotal analyzed: {stats['total_analyzed']}")
        print(f"Consents given: {stats['consents_given']}")
        print(f"Consents denied: {stats['consents_denied']}")
        print(f"Vulnerabilities confirmed: {stats['vulnerabilities_confirmed']}")
        print(f"False positives caught: {stats['false_positives_caught']}")
        print(f"Always consent: {'✅ Enabled' if stats['always_consent_enabled'] else '❌ Disabled'}")
        print("="*70 + "\n")
