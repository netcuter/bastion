"""
AI-Powered Security Testing Module (AdvancedSecurity-inspired)
Advanced security testing capabilities using AI and automation

Features:
- Threat Intelligence & Risk Modeling (P.A.S.T.A methodology)
- Mobile Testing Engine (AI-Monkey Tester for Android/iOS)
- Tooling Layer (fuzzers, crawlers, instrumentation)
- Adversarial Vulnerability Validation (false positive reduction)
- Evidence Capture System (HTTP, logs, screenshots, traces)
- Business Context Risk Assessment (contextual risk evaluation)
- AI Assistant (code analysis with LM Studio)
- Code Anonymization (privacy-preserving analysis)
"""

from .anonymizer import CodeAnonymizer
from .assistant import AIAssistant
from .threat_intelligence import ThreatIntelligence, PASTAThreatModeling
from .mobile_testing import AIMonkeyTester, MobileTestingOrchestrator, MobilePlatform
from .tooling_layer import IntelligentWebCrawler, AdvancedFuzzer, TaintAnalysisEngine, ToolingOrchestrator
from .adversarial_validation import AdversarialValidator, ValidationOrchestrator, ValidationConfidence
from .evidence_capture import EvidenceCollector, EvidenceReproducibility, EvidenceType
from .business_risk import BusinessRiskAnalyzer, IndustryType, ComplianceFramework, AssetCriticality

__all__ = [
    # Original AI modules
    'CodeAnonymizer',
    'AIAssistant',

    # Threat Intelligence & Risk Modeling
    'ThreatIntelligence',
    'PASTAThreatModeling',

    # Mobile Testing
    'AIMonkeyTester',
    'MobileTestingOrchestrator',
    'MobilePlatform',

    # Tooling Layer
    'IntelligentWebCrawler',
    'AdvancedFuzzer',
    'TaintAnalysisEngine',
    'ToolingOrchestrator',

    # Adversarial Validation
    'AdversarialValidator',
    'ValidationOrchestrator',
    'ValidationConfidence',

    # Evidence Capture
    'EvidenceCollector',
    'EvidenceReproducibility',
    'EvidenceType',

    # Business Risk Assessment
    'BusinessRiskAnalyzer',
    'IndustryType',
    'ComplianceFramework',
    'AssetCriticality',
]
