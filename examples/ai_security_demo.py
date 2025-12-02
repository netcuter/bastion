#!/usr/bin/env python3
"""
AdvancedSecurity-Inspired Features Demo
Demonstration of advanced AI-powered security testing capabilities
"""

import sys
sys.path.insert(0, '..')

from security_audit.ai import (
    ThreatIntelligence,
    PASTAThreatModeling,
    AIMonkeyTester,
    MobilePlatform,
    IntelligentWebCrawler,
    AdvancedFuzzer,
    AdversarialValidator,
    EvidenceCollector,
    BusinessRiskAnalyzer,
    IndustryType,
    ComplianceFramework,
    AssetCriticality,
)
from security_audit.ai.business_risk import BusinessAsset


def demo_threat_intelligence():
    """Demo: Threat Intelligence & P.A.S.T.A Methodology"""
    print("=" * 80)
    print("DEMO 1: Threat Intelligence & Risk Modeling (P.A.S.T.A)")
    print("=" * 80)

    # Initialize threat intelligence
    threat_intel = ThreatIntelligence()

    # Define business context
    business_context = {
        'application_name': 'E-Commerce Platform',
        'business_domain': 'ecommerce',
        'sensitive_data_types': ['PII', 'payment_cards', 'credentials'],
        'compliance_requirements': ['PCI-DSS', 'GDPR'],
        'user_roles': ['admin', 'customer', 'guest'],
        'critical_assets': ['customer_database', 'payment_gateway', 'order_system']
    }

    # Analyze project using P.A.S.T.A
    print("\n[*] Running P.A.S.T.A threat modeling...")
    report = threat_intel.analyze_project(
        project_path='.',
        business_context=business_context
    )

    print(f"\n[+] Threat Model Complete!")
    print(f"    - Total threats identified: {report['summary']['total_threats']}")
    print(f"    - Critical risks: {report['summary']['critical_risks']}")
    print(f"    - High risks: {report['summary']['high_risks']}")
    print(f"    - Languages detected: {', '.join(report['stages']['2_technical_scope']['languages'])}")
    print(f"    - Frameworks detected: {', '.join(report['stages']['2_technical_scope']['frameworks'])}")


def demo_mobile_testing():
    """Demo: Mobile Testing Engine"""
    print("\n" + "=" * 80)
    print("DEMO 2: Mobile Testing Engine (AI-Monkey Tester)")
    print("=" * 80)

    # Initialize mobile tester
    tester = AIMonkeyTester(platform=MobilePlatform.ANDROID)

    print("\n[*] Mobile Testing Capabilities:")
    print("    ✓ Android & iOS support")
    print("    ✓ SSL/TLS pinning bypass")
    print("    ✓ Traffic interception")
    print("    ✓ Multi-stack instrumentation (Java, Objective-C, Swift, Native, Flutter)")
    print("    ✓ Intelligent UI exploration")
    print("    ✓ Complex flow navigation (login, checkout, multi-step forms)")
    print("    ✓ CAPTCHA detection and handling")

    # Simulate APK analysis
    print("\n[*] Example: Analyzing Android APK...")
    print("    - Package name detection")
    print("    - Permission extraction")
    print("    - SSL pinning detection")
    print("    - Obfuscation detection")
    print("\n[+] Mobile testing capabilities ready!")


def demo_tooling_layer():
    """Demo: Advanced Tooling Layer"""
    print("\n" + "=" * 80)
    print("DEMO 3: Advanced Tooling Layer")
    print("=" * 80)

    print("\n[*] Web Crawler Capabilities:")
    print("    ✓ Intelligent URL discovery")
    print("    ✓ Form detection and analysis")
    print("    ✓ API endpoint enumeration")
    print("    ✓ JavaScript parsing")
    print("    ✓ Authentication handling")

    print("\n[*] Fuzzing Engine Strategies:")
    print("    ✓ Random fuzzing")
    print("    ✓ Mutation-based fuzzing")
    print("    ✓ Generation-based fuzzing (SQL Injection, XSS, Command Injection)")
    print("    ✓ Smart (AI-guided) fuzzing")
    print("    ✓ Protocol-aware fuzzing")

    print("\n[*] Taint Analysis:")
    print("    ✓ Source-to-sink tracking")
    print("    ✓ Multi-language support")
    print("    ✓ Data flow visualization")

    print("\n[+] Tooling layer ready for comprehensive security testing!")


def demo_adversarial_validation():
    """Demo: Adversarial Vulnerability Validation"""
    print("\n" + "=" * 80)
    print("DEMO 4: Adversarial Vulnerability Validation")
    print("=" * 80)

    # Initialize validator
    validator = AdversarialValidator()

    # Example vulnerability
    test_finding = {
        'id': 'vuln_001',
        'type': 'SQL Injection',
        'severity': 'HIGH',
        'file': 'app/views.py',
        'line': 42,
        'code': 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    }

    print("\n[*] Validating vulnerability using adversarial analysis...")
    print(f"    Original finding: {test_finding['type']} ({test_finding['severity']})")

    result = validator.validate_finding(test_finding)

    print(f"\n[+] Validation Complete!")
    print(f"    - Confidence: {result.confidence.value}")
    print(f"    - Validated: {result.validated}")
    print(f"    - Final verdict: {result.final_verdict[:100]}...")

    print("\n[*] Validation Methods Used:")
    print("    ✓ Static rule-based validation")
    print("    ✓ Context analysis")
    print("    ✓ Adversarial prompt analysis")
    print("    ✓ Known FP pattern matching")


def demo_evidence_capture():
    """Demo: Evidence Capture System"""
    print("\n" + "=" * 80)
    print("DEMO 5: Evidence Capture System")
    print("=" * 80)

    # Initialize evidence collector
    collector = EvidenceCollector(output_dir="./evidence_demo")

    print("\n[*] Evidence Capture Capabilities:")
    print("    ✓ HTTP request/response capture")
    print("    ✓ Screenshots and video recording")
    print("    ✓ Application logs collection")
    print("    ✓ UI interaction traces")
    print("    ✓ Instrumentation logs")
    print("    ✓ Exploitation proof-of-concept evidence")

    # Simulate evidence capture
    print("\n[*] Capturing HTTP evidence...")
    evidence_id = collector.capture_http_request_response(
        method="POST",
        url="https://example.com/api/login",
        request_headers={'Content-Type': 'application/json'},
        request_body='{"username": "admin", "password": "test"}',
        response_status=200,
        response_headers={'Content-Type': 'application/json'},
        response_body='{"token": "abc123"}',
        response_time=150.5,
        vulnerability_id="vuln_001"
    )

    print(f"[+] Evidence captured: {evidence_id}")
    print("\n[*] Evidence is automatically indexed and can be exported as bundle!")


def demo_business_risk():
    """Demo: Business Context Risk Assessment"""
    print("\n" + "=" * 80)
    print("DEMO 6: Business Context Risk Assessment")
    print("=" * 80)

    # Initialize business risk analyzer
    risk_analyzer = BusinessRiskAnalyzer(
        industry=IndustryType.FINANCE,
        compliance_frameworks=[
            ComplianceFramework.GDPR,
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.SOC2
        ]
    )

    # Register business assets
    customer_db = BusinessAsset(
        asset_id='asset_001',
        name='Customer Database',
        description='Main customer database with PII and payment info',
        criticality=AssetCriticality.CRITICAL,
        data_types=['PII', 'payment_cards', 'credentials'],
        user_base_size=500000,
        revenue_impact=10000000.0,  # $10M
        compliance_requirements=[
            ComplianceFramework.GDPR,
            ComplianceFramework.PCI_DSS
        ],
        geographic_scope=['EU', 'US']
    )

    risk_analyzer.register_business_asset(customer_db)

    # Assess vulnerability in business context
    test_vulnerability = {
        'id': 'vuln_001',
        'type': 'SQL Injection',
        'severity': 'CRITICAL'
    }

    print("\n[*] Assessing vulnerability in business context...")
    assessment = risk_analyzer.assess_vulnerability(
        test_vulnerability,
        affected_asset_ids=['asset_001']
    )

    print(f"\n[+] Business Risk Assessment Complete!")
    print(f"    - Technical severity: {assessment.risk_score.technical_severity}")
    print(f"    - Business impact: {assessment.risk_score.business_impact}")
    print(f"    - Overall risk score: {assessment.risk_score.overall_risk:.1f}/10")
    print(f"    - Financial impact: ${assessment.risk_score.financial_impact_min:,.0f} - "
          f"${assessment.risk_score.financial_impact_max:,.0f}")
    print(f"    - Compliance violations: {', '.join(assessment.risk_score.compliance_violations)}")
    print(f"    - Mitigation priority: {assessment.mitigation_priority}")
    print(f"    - Recommended timeline: {assessment.recommended_timeline}")

    # Generate executive summary
    print("\n[*] Executive Summary:")
    summary = risk_analyzer.generate_executive_summary()
    print(f"    - Total risks identified: {summary['executive_summary']['total_risks_identified']}")
    print(f"    - Critical risks: {summary['executive_summary']['risk_distribution']['critical']}")
    print(f"    - Financial exposure: {summary['executive_summary']['financial_exposure']['minimum']} - "
          f"{summary['executive_summary']['financial_exposure']['maximum']}")


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("  OSTORLAB-INSPIRED FEATURES DEMONSTRATION")
    print("  Advanced AI-Powered Security Testing")
    print("=" * 80)

    try:
        demo_threat_intelligence()
        demo_mobile_testing()
        demo_tooling_layer()
        demo_adversarial_validation()
        demo_evidence_capture()
        demo_business_risk()

        print("\n" + "=" * 80)
        print("  ALL DEMOS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\n[✓] AdvancedSecurity-inspired features are ready to use!")
        print("[✓] Check security_audit/ai/ for full implementation")
        print("\n")

    except Exception as e:
        print(f"\n[!] Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
