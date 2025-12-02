"""
Adversarial Vulnerability Validation
Advanced validation system using adversarial analysis to reduce false positives

Features:
- Adversarial validation loops (counter-arguments)
- Independent "negative" prompts to refute findings
- Confidence scoring
- False positive classification
- Multi-perspective analysis
"""
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class ValidationConfidence(Enum):
    """Validation confidence levels"""
    CONFIRMED = "confirmed"  # Validated as real vulnerability
    LIKELY = "likely"  # High confidence, but not 100%
    POSSIBLE = "possible"  # Could be real, needs manual review
    UNLIKELY = "unlikely"  # Probably false positive
    FALSE_POSITIVE = "false_positive"  # Confirmed false positive


class ValidationMethod(Enum):
    """Validation methods"""
    ADVERSARIAL_PROMPT = "adversarial_prompt"  # AI-based adversarial analysis
    STATIC_RULES = "static_rules"  # Rule-based validation
    DYNAMIC_TEST = "dynamic_test"  # Runtime testing
    CONTEXT_ANALYSIS = "context_analysis"  # Code context analysis
    EXPLOIT_POC = "exploit_poc"  # Proof of concept exploitation


@dataclass
class ValidationResult:
    """Validation result for a finding"""
    finding_id: str = ""
    original_severity: str = ""
    validated: bool = False
    confidence: ValidationConfidence = ValidationConfidence.POSSIBLE
    validation_methods: List[str] = None
    supporting_evidence: List[str] = None
    refuting_evidence: List[str] = None
    final_verdict: str = ""
    false_positive_reason: str = ""
    recommendation: str = ""

    def __post_init__(self):
        if self.validation_methods is None:
            self.validation_methods = []
        if self.supporting_evidence is None:
            self.supporting_evidence = []
        if self.refuting_evidence is None:
            self.refuting_evidence = []


class AdversarialValidator:
    """
    Adversarial validation system

    Uses adversarial analysis to challenge and validate findings
    Reduces false positives through multi-perspective analysis
    """

    def __init__(self):
        self.validation_results: List[ValidationResult] = []
        self.false_positive_patterns: Dict[str, List[str]] = self._load_fp_patterns()

    def validate_finding(self, finding: Dict[str, Any],
                        code_context: Optional[str] = None) -> ValidationResult:
        """
        Validate a security finding using multiple methods

        Args:
            finding: Security finding to validate
            code_context: Surrounding code context

        Returns:
            Validation result with confidence score
        """
        result = ValidationResult(
            finding_id=finding.get('id', ''),
            original_severity=finding.get('severity', 'MEDIUM')
        )

        # Method 1: Static rule-based validation
        static_validation = self._static_rule_validation(finding, code_context)
        if static_validation['is_fp']:
            result.refuting_evidence.append(static_validation['reason'])
            result.confidence = ValidationConfidence.FALSE_POSITIVE
            result.false_positive_reason = static_validation['reason']
        else:
            result.supporting_evidence.append("Passed static rule validation")

        # Method 2: Context analysis
        context_validation = self._context_analysis(finding, code_context)
        if context_validation['has_sanitization']:
            result.refuting_evidence.append("Input is sanitized before use")
            result.confidence = ValidationConfidence.UNLIKELY
        elif context_validation['has_validation']:
            result.refuting_evidence.append("Input validation detected")
            result.confidence = ValidationConfidence.UNLIKELY
        else:
            result.supporting_evidence.append("No sanitization detected")

        # Method 3: Adversarial prompt analysis
        adversarial_validation = self._adversarial_prompt_analysis(finding, code_context)
        if adversarial_validation['refuted']:
            result.refuting_evidence.extend(adversarial_validation['arguments'])
            if result.confidence == ValidationConfidence.POSSIBLE:
                result.confidence = ValidationConfidence.UNLIKELY
        else:
            result.supporting_evidence.extend(adversarial_validation['arguments'])

        # Method 4: Pattern matching for known FPs
        fp_pattern_match = self._check_fp_patterns(finding)
        if fp_pattern_match:
            result.refuting_evidence.append(f"Matches known FP pattern: {fp_pattern_match}")
            result.confidence = ValidationConfidence.FALSE_POSITIVE
            result.false_positive_reason = fp_pattern_match

        # Calculate final verdict
        result.validated = self._calculate_final_verdict(result)
        result.final_verdict = self._generate_verdict_text(result)
        result.recommendation = self._generate_recommendation(result)

        self.validation_results.append(result)
        return result

    def validate_batch(self, findings: List[Dict[str, Any]],
                      code_contexts: Optional[Dict[str, str]] = None) -> List[ValidationResult]:
        """
        Validate multiple findings in batch

        Args:
            findings: List of security findings
            code_contexts: Dict mapping finding IDs to code contexts

        Returns:
            List of validation results
        """
        results = []

        for finding in findings:
            finding_id = finding.get('id', '')
            context = code_contexts.get(finding_id) if code_contexts else None
            result = self.validate_finding(finding, context)
            results.append(result)

        return results

    def filter_validated_findings(self, findings: List[Dict[str, Any]],
                                  min_confidence: ValidationConfidence = ValidationConfidence.LIKELY) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter findings based on validation confidence

        Args:
            findings: Original findings
            min_confidence: Minimum confidence threshold

        Returns:
            Tuple of (validated_findings, rejected_findings)
        """
        confidence_order = {
            ValidationConfidence.CONFIRMED: 5,
            ValidationConfidence.LIKELY: 4,
            ValidationConfidence.POSSIBLE: 3,
            ValidationConfidence.UNLIKELY: 2,
            ValidationConfidence.FALSE_POSITIVE: 1
        }

        min_score = confidence_order[min_confidence]

        validated = []
        rejected = []

        for finding, result in zip(findings, self.validation_results):
            if confidence_order[result.confidence] >= min_score:
                validated.append(finding)
            else:
                rejected.append(finding)

        return validated, rejected

    def _static_rule_validation(self, finding: Dict[str, Any],
                                code_context: Optional[str]) -> Dict[str, Any]:
        """
        Static rule-based validation

        Checks for common false positive patterns
        """
        vuln_type = finding.get('type', '').lower()
        file_path = finding.get('file', '')
        code_snippet = finding.get('code', '')

        # Check for test files
        if any(indicator in file_path.lower() for indicator in ['test_', '_test.', '/tests/', '/test/']):
            return {
                'is_fp': True,
                'reason': 'Finding in test file - typically not exploitable in production'
            }

        # Check for commented code
        if code_snippet.strip().startswith(('#', '//', '/*', '*')):
            return {
                'is_fp': True,
                'reason': 'Vulnerable code is commented out'
            }

        # Check for example/demo code
        if any(indicator in file_path.lower() for indicator in ['example', 'demo', 'sample', 'tutorial']):
            return {
                'is_fp': True,
                'reason': 'Finding in example/demo code'
            }

        # SQL Injection specific checks
        if 'sql' in vuln_type:
            # Check for ORM usage (typically safe)
            if any(orm in code_snippet.lower() for orm in ['.filter(', '.get(', '.all()', '.first()']):
                return {
                    'is_fp': True,
                    'reason': 'Using ORM methods which are protected from SQL injection'
                }

            # Check for parameterized queries
            if '?' in code_snippet or ':' in code_snippet and 'execute' in code_snippet:
                return {
                    'is_fp': True,
                    'reason': 'Using parameterized query (placeholders detected)'
                }

        # XSS specific checks
        if 'xss' in vuln_type:
            # Check for auto-escaping templates
            if any(template in code_snippet for template in ['{{', '}}', '{%', '%}']):
                if 'safe' not in code_snippet and 'autoescape' not in code_snippet:
                    return {
                        'is_fp': True,
                        'reason': 'Template engine with auto-escaping enabled'
                    }

        # Command Injection specific checks
        if 'command' in vuln_type:
            # Check for safe subprocess usage
            if 'subprocess.run' in code_snippet and 'shell=False' in code_snippet:
                return {
                    'is_fp': True,
                    'reason': 'Using subprocess with shell=False (safe)'
                }

        return {'is_fp': False, 'reason': ''}

    def _context_analysis(self, finding: Dict[str, Any],
                         code_context: Optional[str]) -> Dict[str, Any]:
        """
        Analyze code context for sanitization and validation

        Looks for:
        - Input sanitization functions
        - Input validation checks
        - Security controls
        """
        if not code_context:
            return {'has_sanitization': False, 'has_validation': False}

        # Sanitization patterns
        sanitization_patterns = [
            r'escape\w*\(',
            r'sanitize\w*\(',
            r'clean\w*\(',
            r'filter\w*\(',
            r'strip\w*\(',
            r'htmlspecialchars\(',
            r'htmlentities\(',
            r'mysqli_real_escape_string\(',
            r'PDO::quote\(',
            r're\.sub\(',
            r'bleach\.',
        ]

        has_sanitization = any(re.search(pattern, code_context) for pattern in sanitization_patterns)

        # Validation patterns
        validation_patterns = [
            r'if\s+.*\s+(not|!)\s+',
            r'isinstance\(',
            r'type\(',
            r'validate\w*\(',
            r'is_valid\w*\(',
            r'check\w*\(',
            r'assert\w*\(',
            r'raise\s+\w*Error',
            r'throw\s+new\s+Error',
        ]

        has_validation = any(re.search(pattern, code_context) for pattern in validation_patterns)

        return {
            'has_sanitization': has_sanitization,
            'has_validation': has_validation
        }

    def _adversarial_prompt_analysis(self, finding: Dict[str, Any],
                                    code_context: Optional[str]) -> Dict[str, Any]:
        """
        Use adversarial prompts to challenge the finding

        Simulates a "defense attorney" arguing against the vulnerability
        """
        vuln_type = finding.get('type', '')
        code_snippet = finding.get('code', '')

        # Generate adversarial arguments
        refuting_arguments = []
        supporting_arguments = []

        # Adversarial prompt: "This is not a vulnerability because..."
        adversarial_checks = {
            'SQL Injection': [
                'Could be using parameterized queries in parent function',
                'May have input validation in middleware',
                'Database user might have restricted permissions',
                'Could be internal query not exposed to users'
            ],
            'XSS': [
                'Output might be in non-HTML context',
                'Browser may have built-in XSS protection',
                'Content Security Policy might block execution',
                'Data might be numeric (not string)'
            ],
            'Command Injection': [
                'Could be running with restricted shell',
                'Input might be validated by regex',
                'May be running in sandboxed environment',
                'Command might not include user input'
            ],
            'Path Traversal': [
                'May have path normalization',
                'Could be using chroot jail',
                'Permissions might restrict access',
                'Path might be validated'
            ]
        }

        # Check if any adversarial arguments apply
        for vuln_category, arguments in adversarial_checks.items():
            if vuln_category.lower() in vuln_type.lower():
                # Simulate adversarial analysis
                if code_context:
                    # More sophisticated analysis with context
                    if 'validate' in code_context or 'check' in code_context:
                        refuting_arguments.append("Code context shows validation logic")
                    else:
                        supporting_arguments.append("No validation found in context")
                else:
                    # Without context, use generic arguments
                    refuting_arguments.extend(arguments[:2])

        # Determine if refuted
        refuted = len(refuting_arguments) > len(supporting_arguments)

        return {
            'refuted': refuted,
            'arguments': refuting_arguments if refuted else supporting_arguments
        }

    def _check_fp_patterns(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Check against known false positive patterns

        Returns reason if matches FP pattern, None otherwise
        """
        vuln_type = finding.get('type', '').lower()
        code_snippet = finding.get('code', '')
        file_path = finding.get('file', '')

        if vuln_type in self.false_positive_patterns:
            for pattern in self.false_positive_patterns[vuln_type]:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    return f"Matches FP pattern: {pattern}"

        return None

    def _calculate_final_verdict(self, result: ValidationResult) -> bool:
        """
        Calculate final verdict based on evidence

        Returns True if vulnerability is validated, False if false positive
        """
        confidence_scores = {
            ValidationConfidence.CONFIRMED: 1.0,
            ValidationConfidence.LIKELY: 0.8,
            ValidationConfidence.POSSIBLE: 0.5,
            ValidationConfidence.UNLIKELY: 0.3,
            ValidationConfidence.FALSE_POSITIVE: 0.0
        }

        score = confidence_scores.get(result.confidence, 0.5)

        # Adjust score based on evidence
        supporting_weight = len(result.supporting_evidence) * 0.1
        refuting_weight = len(result.refuting_evidence) * 0.15

        final_score = score + supporting_weight - refuting_weight
        final_score = max(0.0, min(1.0, final_score))

        # Update confidence based on final score
        if final_score >= 0.9:
            result.confidence = ValidationConfidence.CONFIRMED
        elif final_score >= 0.7:
            result.confidence = ValidationConfidence.LIKELY
        elif final_score >= 0.5:
            result.confidence = ValidationConfidence.POSSIBLE
        elif final_score >= 0.3:
            result.confidence = ValidationConfidence.UNLIKELY
        else:
            result.confidence = ValidationConfidence.FALSE_POSITIVE

        return final_score >= 0.5

    def _generate_verdict_text(self, result: ValidationResult) -> str:
        """Generate human-readable verdict"""
        confidence_texts = {
            ValidationConfidence.CONFIRMED: "This is a CONFIRMED vulnerability - high confidence",
            ValidationConfidence.LIKELY: "This is LIKELY a real vulnerability - requires validation",
            ValidationConfidence.POSSIBLE: "This is POSSIBLY a vulnerability - manual review recommended",
            ValidationConfidence.UNLIKELY: "This is UNLIKELY to be a vulnerability - probable false positive",
            ValidationConfidence.FALSE_POSITIVE: "This is a FALSE POSITIVE - not a real vulnerability"
        }

        verdict = confidence_texts.get(result.confidence, "Unknown")

        if result.supporting_evidence:
            verdict += f"\n\nSupporting evidence:\n- " + "\n- ".join(result.supporting_evidence)

        if result.refuting_evidence:
            verdict += f"\n\nRefuting evidence:\n- " + "\n- ".join(result.refuting_evidence)

        return verdict

    def _generate_recommendation(self, result: ValidationResult) -> str:
        """Generate actionable recommendation"""
        if result.confidence == ValidationConfidence.CONFIRMED:
            return f"FIX IMMEDIATELY - Confirmed {result.original_severity} severity vulnerability"
        elif result.confidence == ValidationConfidence.LIKELY:
            return "REVIEW AND FIX - High probability of real vulnerability"
        elif result.confidence == ValidationConfidence.POSSIBLE:
            return "MANUAL REVIEW REQUIRED - Uncertain if this is a real vulnerability"
        elif result.confidence == ValidationConfidence.UNLIKELY:
            return "LOW PRIORITY - Likely false positive, but review if time permits"
        else:
            return "IGNORE - Confirmed false positive, can be safely dismissed"

    def _load_fp_patterns(self) -> Dict[str, List[str]]:
        """
        Load known false positive patterns

        Returns dict of vulnerability type -> list of FP regex patterns
        """
        return {
            'sql injection': [
                r'\.filter\(',  # ORM filter
                r'\.get\(',  # ORM get
                r'\.exclude\(',  # ORM exclude
                r'SELECT \* FROM \w+ WHERE id = \?',  # Parameterized
            ],
            'xss': [
                r'\{\{\s*\w+\s*\}\}',  # Template with auto-escape
                r'textContent\s*=',  # Safe DOM assignment
                r'innerText\s*=',  # Safe DOM assignment
            ],
            'command injection': [
                r'subprocess\.run\([^)]*shell=False',  # Safe subprocess
                r'subprocess\.check_output\([^)]*shell=False',
            ],
            'path traversal': [
                r'os\.path\.basename\(',  # Only filename
                r'Path\([^)]*\)\.name',  # Only filename
                r'secure_filename\(',  # Flask secure_filename
            ]
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate validation report"""
        total = len(self.validation_results)
        confirmed = sum(1 for r in self.validation_results if r.confidence == ValidationConfidence.CONFIRMED)
        likely = sum(1 for r in self.validation_results if r.confidence == ValidationConfidence.LIKELY)
        possible = sum(1 for r in self.validation_results if r.confidence == ValidationConfidence.POSSIBLE)
        unlikely = sum(1 for r in self.validation_results if r.confidence == ValidationConfidence.UNLIKELY)
        false_positives = sum(1 for r in self.validation_results if r.confidence == ValidationConfidence.FALSE_POSITIVE)

        return {
            'summary': {
                'total_validated': total,
                'confirmed': confirmed,
                'likely': likely,
                'possible': possible,
                'unlikely': unlikely,
                'false_positives': false_positives,
                'fp_rate': (false_positives / total * 100) if total > 0 else 0
            },
            'results': [asdict(r) for r in self.validation_results]
        }


class ValidationOrchestrator:
    """
    Orchestrator for adversarial validation workflows

    Manages validation pipelines and reporting
    """

    def __init__(self):
        self.validator = AdversarialValidator()

    def validate_scan_results(self, findings: List[Dict[str, Any]],
                             code_base_path: str = "") -> Dict[str, Any]:
        """
        Validate all findings from security scan

        Args:
            findings: List of security findings
            code_base_path: Path to code base for context extraction

        Returns:
            Validation report with filtered findings
        """
        # TODO: Extract code context for each finding
        code_contexts = {}

        # Validate all findings
        validation_results = self.validator.validate_batch(findings, code_contexts)

        # Filter findings by confidence
        validated, rejected = self.validator.filter_validated_findings(
            findings,
            min_confidence=ValidationConfidence.LIKELY
        )

        # Generate report
        report = self.validator.generate_report()
        report['validated_findings'] = validated
        report['rejected_findings'] = rejected

        return report

    def continuous_validation(self, findings_stream):
        """
        Continuous validation for streaming findings

        Validates findings as they are discovered
        """
        for finding in findings_stream:
            result = self.validator.validate_finding(finding)
            if result.validated:
                yield finding
