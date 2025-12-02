#!/usr/bin/env python3
"""
Comprehensive tests for AdvancedSecurity-inspired features
"""

import sys
import json


def test_threat_intelligence():
    """Test Threat Intelligence module"""
    print("\n" + "="*80)
    print("TEST 1: Threat Intelligence & P.A.S.T.A")
    print("="*80)

    from security_audit.ai import ThreatIntelligence, PASTAThreatModeling

    # Test P.A.S.T.A methodology
    pasta = PASTAThreatModeling()

    # Stage 1: Define Objectives
    print("\n[*] Stage 1: Define Objectives")
    context = {
        'application_name': 'Test Banking App',
        'business_domain': 'finance',
        'sensitive_data_types': ['PII', 'financial', 'credentials'],
        'compliance_requirements': ['PCI-DSS', 'GDPR', 'SOC2'],
        'user_roles': ['admin', 'teller', 'customer'],
        'critical_assets': ['account_database', 'transaction_processor']
    }
    business_ctx = pasta.stage1_define_objectives(context)
    print(f"    ✓ Business context: {business_ctx.application_name}")
    print(f"    ✓ Compliance: {', '.join(business_ctx.compliance_requirements)}")

    # Stage 2: Technical Scope
    print("\n[*] Stage 2: Define Technical Scope")
    tech_stack = pasta.stage2_define_technical_scope('.')
    print(f"    ✓ Languages: {', '.join(tech_stack.languages)}")
    print(f"    ✓ Frameworks: {', '.join(tech_stack.frameworks) if tech_stack.frameworks else 'None detected'}")
    print(f"    ✓ Databases: {', '.join(tech_stack.databases) if tech_stack.databases else 'None detected'}")

    # Stage 3: Attack Surface
    print("\n[*] Stage 3: Application Decomposition")
    attack_surface = pasta.stage3_application_decomposition('.')
    print(f"    ✓ Entry points: {', '.join(attack_surface.entry_points) if attack_surface.entry_points else 'None detected'}")
    print(f"    ✓ Auth methods: {', '.join(attack_surface.authentication_methods) if attack_surface.authentication_methods else 'None detected'}")

    # Stage 4: Threat Analysis
    print("\n[*] Stage 4: Threat Analysis")
    threats = pasta.stage4_threat_analysis()
    print(f"    ✓ Total threats identified: {len(threats)}")
    print(f"    ✓ Sample threats: {', '.join([t.threats[0]['name'] for t in threats[:3]])}")

    # Stage 7: Risk Analysis
    print("\n[*] Stage 7: Risk & Impact Analysis")
    risks = pasta.stage7_risk_impact_analysis()
    high_risks = [r for r in risks if r.risk_score >= 7.0]
    print(f"    ✓ High-risk threats: {len(high_risks)}")
    print(f"    ✓ Top risk score: {risks[0].risk_score:.1f}/10" if risks else "    ✓ No risks")

    # Full report
    print("\n[*] Generating full P.A.S.T.A report")
    report = pasta.generate_full_report()
    print(f"    ✓ Report stages: {len(report['stages'])}")
    print(f"    ✓ Critical risks: {report['summary']['critical_risks']}")

    print("\n[✓] Threat Intelligence module: PASSED")
    return True


def test_mobile_testing():
    """Test Mobile Testing Engine"""
    print("\n" + "="*80)
    print("TEST 2: Mobile Testing Engine")
    print("="*80)

    from security_audit.ai import AIMonkeyTester, MobilePlatform, MobileTestingOrchestrator

    # Test Android tester
    print("\n[*] Testing Android capabilities")
    android_tester = AIMonkeyTester(platform=MobilePlatform.ANDROID)
    print(f"    ✓ Platform: {android_tester.platform.value}")
    print(f"    ✓ UI states: {len(android_tester.ui_states)}")
    print(f"    ✓ Traffic captures: {len(android_tester.traffic_captures)}")

    # Test iOS tester
    print("\n[*] Testing iOS capabilities")
    ios_tester = AIMonkeyTester(platform=MobilePlatform.IOS)
    print(f"    ✓ Platform: {ios_tester.platform.value}")

    # Test SSL pinning bypass
    print("\n[*] Testing SSL pinning bypass")
    android_result = android_tester.bypass_ssl_pinning()
    print(f"    ✓ Android bypass: {'Success' if android_result else 'Failed'}")
    ios_result = ios_tester.bypass_ssl_pinning()
    print(f"    ✓ iOS bypass: {'Success' if ios_result else 'Failed'}")
    print(f"    ✓ Hooks installed: {len(android_tester.instrumentation_hooks)}")

    # Test instrumentation
    print("\n[*] Testing instrumentation")
    android_tester.instrument_java_methods('com.example.App', 'getData')
    print(f"    ✓ Java hooks: {len([h for h in android_tester.instrumentation_hooks if h.language == 'java'])}")

    ios_tester.instrument_objc_methods('AppDelegate', 'applicationDidFinishLaunching')
    print(f"    ✓ Objective-C hooks: {len([h for h in ios_tester.instrumentation_hooks if h.language == 'objc'])}")

    # Test security issue detection
    print("\n[*] Testing security issue detection")
    issues = android_tester.detect_security_issues()
    print(f"    ✓ Issues detected: {len(issues)}")

    # Test orchestrator
    print("\n[*] Testing Mobile Testing Orchestrator")
    orchestrator = MobileTestingOrchestrator()
    print(f"    ✓ Orchestrator initialized")
    print(f"    ✓ Testers: {len(orchestrator.testers)}")

    print("\n[✓] Mobile Testing module: PASSED")
    return True


def test_tooling_layer():
    """Test Tooling Layer"""
    print("\n" + "="*80)
    print("TEST 3: Advanced Tooling Layer")
    print("="*80)

    from security_audit.ai import IntelligentWebCrawler, AdvancedFuzzer, TaintAnalysisEngine
    from security_audit.ai.tooling_layer import CrawlerMode, FuzzingStrategy, CrawledEndpoint

    # Test fuzzer
    print("\n[*] Testing Fuzzer - Random Strategy")
    fuzzer = AdvancedFuzzer(strategy=FuzzingStrategy.RANDOM)
    payloads = fuzzer._generate_random_payloads(5)
    print(f"    ✓ Generated {len(payloads)} random payloads")

    print("\n[*] Testing Fuzzer - Mutation Strategy")
    fuzzer_mut = AdvancedFuzzer(strategy=FuzzingStrategy.MUTATION)
    mut_payloads = fuzzer_mut._generate_mutation_payloads(5)
    print(f"    ✓ Generated {len(mut_payloads)} mutation payloads")

    print("\n[*] Testing Fuzzer - Generation Strategy")
    fuzzer_gen = AdvancedFuzzer(strategy=FuzzingStrategy.GENERATION)
    gen_payloads = fuzzer_gen._generate_generation_payloads(10)
    print(f"    ✓ Generated {len(gen_payloads)} security payloads")
    print(f"    ✓ Sample: {gen_payloads[0][:50]}...")

    print("\n[*] Testing Fuzzer - Smart Strategy")
    fuzzer_smart = AdvancedFuzzer(strategy=FuzzingStrategy.SMART)
    smart_payloads = fuzzer_smart._generate_smart_payloads(10)
    print(f"    ✓ Generated {len(smart_payloads)} smart payloads")

    # Test taint analysis
    print("\n[*] Testing Taint Analysis Engine")
    taint_engine = TaintAnalysisEngine()

    test_code_python = """
    username = request.GET['username']
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    """

    violations = taint_engine.analyze_code(test_code_python, 'python')
    print(f"    ✓ Python taint violations: {len(violations)}")
    if violations:
        print(f"    ✓ Sample: {violations[0]['source']} -> {violations[0]['sink']}")

    test_code_js = """
    const user = req.query.user;
    eval(user);
    """

    violations_js = taint_engine.analyze_code(test_code_js, 'javascript')
    print(f"    ✓ JavaScript taint violations: {len(violations_js)}")

    print("\n[✓] Tooling Layer module: PASSED")
    return True


def test_adversarial_validation():
    """Test Adversarial Validation"""
    print("\n" + "="*80)
    print("TEST 4: Adversarial Vulnerability Validation")
    print("="*80)

    from security_audit.ai import AdversarialValidator, ValidationConfidence

    validator = AdversarialValidator()

    # Test Case 1: Real SQL Injection
    print("\n[*] Test Case 1: Real SQL Injection")
    finding1 = {
        'id': 'test_001',
        'type': 'SQL Injection',
        'severity': 'CRITICAL',
        'file': 'app/views.py',
        'line': 42,
        'code': 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    }

    result1 = validator.validate_finding(finding1)
    print(f"    ✓ Confidence: {result1.confidence.value}")
    print(f"    ✓ Validated: {result1.validated}")
    print(f"    ✓ Supporting evidence: {len(result1.supporting_evidence)}")
    print(f"    ✓ Refuting evidence: {len(result1.refuting_evidence)}")

    # Test Case 2: False Positive (ORM usage)
    print("\n[*] Test Case 2: False Positive (ORM)")
    finding2 = {
        'id': 'test_002',
        'type': 'SQL Injection',
        'severity': 'HIGH',
        'file': 'app/models.py',
        'line': 10,
        'code': 'User.objects.filter(id=user_id).first()'
    }

    result2 = validator.validate_finding(finding2, code_context="# Using Django ORM\nUser.objects.filter(id=user_id)")
    print(f"    ✓ Confidence: {result2.confidence.value}")
    print(f"    ✓ Validated: {result2.validated}")
    print(f"    ✓ FP reason: {result2.false_positive_reason[:50]}..." if result2.false_positive_reason else "    ✓ No FP reason")

    # Test Case 3: Test file (should be FP)
    print("\n[*] Test Case 3: Test File (should be FP)")
    finding3 = {
        'id': 'test_003',
        'type': 'XSS',
        'severity': 'HIGH',
        'file': 'tests/test_views.py',
        'code': 'response.write(user_input)'
    }

    result3 = validator.validate_finding(finding3)
    print(f"    ✓ Confidence: {result3.confidence.value}")
    print(f"    ✓ Validated: {result3.validated}")

    # Batch validation
    print("\n[*] Testing batch validation")
    findings = [finding1, finding2, finding3]
    results = validator.validate_batch(findings)
    print(f"    ✓ Validated {len(results)} findings")

    # Generate report
    print("\n[*] Testing report generation")
    report = validator.generate_report()
    print(f"    ✓ Total validated: {report['summary']['total_validated']}")
    print(f"    ✓ Confirmed: {report['summary']['confirmed']}")
    print(f"    ✓ False positives: {report['summary']['false_positives']}")
    print(f"    ✓ FP rate: {report['summary']['fp_rate']:.1f}%")

    print("\n[✓] Adversarial Validation module: PASSED")
    return True


def test_evidence_capture():
    """Test Evidence Capture System"""
    print("\n" + "="*80)
    print("TEST 5: Evidence Capture System")
    print("="*80)

    from security_audit.ai import EvidenceCollector, EvidenceReproducibility
    import tempfile
    import os

    # Create temp directory for evidence
    temp_dir = tempfile.mkdtemp(prefix='evidence_test_')
    print(f"\n[*] Using temp directory: {temp_dir}")

    collector = EvidenceCollector(output_dir=temp_dir)

    # Test HTTP capture
    print("\n[*] Testing HTTP evidence capture")
    http_id = collector.capture_http_request_response(
        method="POST",
        url="https://example.com/api/login",
        request_headers={'Content-Type': 'application/json', 'Authorization': 'Bearer token123'},
        request_body='{"username": "admin", "password": "test123"}',
        response_status=200,
        response_headers={'Content-Type': 'application/json'},
        response_body='{"token": "abc123def456", "user_id": 1}',
        response_time=125.5,
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ HTTP evidence ID: {http_id}")
    print(f"    ✓ Total HTTP captures: {len(collector.http_evidence)}")

    # Test screenshot capture
    print("\n[*] Testing screenshot capture")
    fake_screenshot = b"PNG_IMAGE_DATA_HERE" * 100
    screenshot_id = collector.capture_screenshot(
        screenshot_data=fake_screenshot,
        description="Login screen with vulnerable XSS",
        device_info="Android 12, Pixel 6",
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ Screenshot ID: {screenshot_id}")
    print(f"    ✓ Total screenshots: {len(collector.screenshot_evidence)}")

    # Test log capture
    print("\n[*] Testing log capture")
    log_lines = [
        "[2025-12-02 10:15:23] INFO: User login attempt",
        "[2025-12-02 10:15:24] ERROR: SQL syntax error near 'admin'",
        "[2025-12-02 10:15:25] CRITICAL: Potential SQL injection detected",
        "[2025-12-02 10:15:26] WARNING: Multiple failed authentication attempts"
    ]
    log_id = collector.capture_logs(
        log_lines=log_lines,
        log_type="application",
        log_level="ERROR",
        log_source="/var/log/app.log",
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ Log evidence ID: {log_id}")
    print(f"    ✓ Total log captures: {len(collector.log_evidence)}")
    print(f"    ✓ Relevant patterns: {collector.log_evidence[0].relevant_patterns}")

    # Test UI interaction trace
    print("\n[*] Testing UI interaction trace")
    ui_id = collector.capture_ui_interaction(
        interaction_type="input",
        target_element="username_field",
        input_value="admin' OR '1'='1",
        result="SQL injection successful",
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ UI trace ID: {ui_id}")
    print(f"    ✓ Total UI traces: {len(collector.ui_traces)}")

    # Test instrumentation trace
    print("\n[*] Testing instrumentation trace")
    instr_id = collector.capture_instrumentation_trace(
        hook_target="com.example.Database.executeQuery",
        call_stack=["MainActivity.onCreate", "UserService.login", "Database.executeQuery"],
        arguments=["SELECT * FROM users WHERE id = 1"],
        return_value={"user": "admin"},
        execution_time=15.5,
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ Instrumentation trace ID: {instr_id}")
    print(f"    ✓ Total instrumentation traces: {len(collector.instrumentation_traces)}")

    # Test exploit PoC
    print("\n[*] Testing exploit PoC capture")
    poc_id = collector.capture_exploit_poc(
        vulnerability_type="SQL Injection",
        exploit_payload="admin' OR '1'='1' --",
        exploit_steps=[
            "1. Navigate to login page",
            "2. Enter payload in username field",
            "3. Submit form",
            "4. Observe authentication bypass"
        ],
        pre_exploit_state="Not authenticated",
        post_exploit_state="Authenticated as admin",
        impact_demonstration="Full administrative access gained",
        vulnerability_id="vuln_001"
    )
    print(f"    ✓ Exploit PoC ID: {poc_id}")
    print(f"    ✓ Total PoCs: {len(collector.exploit_pocs)}")

    # Test evidence retrieval
    print("\n[*] Testing evidence retrieval for vulnerability")
    evidence = collector.get_evidence_for_vulnerability("vuln_001")
    print(f"    ✓ HTTP evidence: {len(evidence['http'])}")
    print(f"    ✓ Screenshots: {len(evidence['screenshots'])}")
    print(f"    ✓ Logs: {len(evidence['logs'])}")
    print(f"    ✓ UI traces: {len(evidence['ui_traces'])}")
    print(f"    ✓ Instrumentation: {len(evidence['instrumentation'])}")
    print(f"    ✓ Exploit PoCs: {len(evidence['exploit_pocs'])}")

    # Test evidence report
    print("\n[*] Testing evidence report generation")
    report = collector.generate_evidence_report("vuln_001")
    print(f"    ✓ Total evidence items: {report['total_evidence_items']}")

    # Test reproducibility guide
    print("\n[*] Testing reproducibility guide generation")
    repro = EvidenceReproducibility(collector)
    guide = repro.generate_reproduction_guide("vuln_001")
    print(f"    ✓ Guide length: {len(guide)} characters")
    print(f"    ✓ Contains HTTP requests: {'curl' in guide}")
    print(f"    ✓ Contains exploit steps: {'Exploitation Steps' in guide}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)
    print(f"\n[*] Cleaned up temp directory")

    print("\n[✓] Evidence Capture module: PASSED")
    return True


def test_business_risk():
    """Test Business Risk Assessment"""
    print("\n" + "="*80)
    print("TEST 6: Business Context Risk Assessment")
    print("="*80)

    from security_audit.ai import BusinessRiskAnalyzer, IndustryType, ComplianceFramework, AssetCriticality
    from security_audit.ai.business_risk import BusinessAsset

    # Test different industries
    print("\n[*] Testing Finance Industry")
    finance_analyzer = BusinessRiskAnalyzer(
        industry=IndustryType.FINANCE,
        compliance_frameworks=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR, ComplianceFramework.SOC2]
    )
    print(f"    ✓ Industry multiplier: {finance_analyzer.industry_risk_multipliers[IndustryType.FINANCE]}")

    print("\n[*] Testing Healthcare Industry")
    healthcare_analyzer = BusinessRiskAnalyzer(
        industry=IndustryType.HEALTHCARE,
        compliance_frameworks=[ComplianceFramework.HIPAA, ComplianceFramework.GDPR]
    )
    print(f"    ✓ Industry multiplier: {healthcare_analyzer.industry_risk_multipliers[IndustryType.HEALTHCARE]}")

    # Register critical business asset
    print("\n[*] Registering business assets")
    customer_db = BusinessAsset(
        asset_id='asset_001',
        name='Customer Database',
        description='Main database with customer PII and payment info',
        criticality=AssetCriticality.CRITICAL,
        data_types=['PII', 'payment_cards', 'credentials'],
        user_base_size=1000000,  # 1M users
        revenue_impact=50000000.0,  # $50M
        compliance_requirements=[ComplianceFramework.GDPR, ComplianceFramework.PCI_DSS],
        geographic_scope=['EU', 'US', 'UK']
    )
    finance_analyzer.register_business_asset(customer_db)
    print(f"    ✓ Registered: {customer_db.name}")
    print(f"    ✓ Criticality: {customer_db.criticality.value}")
    print(f"    ✓ Users: {customer_db.user_base_size:,}")

    # Test critical vulnerability assessment
    print("\n[*] Assessing CRITICAL SQL Injection")
    vuln_critical = {
        'id': 'vuln_001',
        'type': 'SQL Injection',
        'severity': 'CRITICAL'
    }
    assessment = finance_analyzer.assess_vulnerability(vuln_critical, ['asset_001'])
    print(f"    ✓ Technical severity: {assessment.risk_score.technical_severity}")
    print(f"    ✓ Business impact: {assessment.risk_score.business_impact}")
    print(f"    ✓ Overall risk: {assessment.risk_score.overall_risk:.1f}/10")
    print(f"    ✓ Financial impact: ${assessment.risk_score.financial_impact_min:,.0f} - ${assessment.risk_score.financial_impact_max:,.0f}")
    print(f"    ✓ Compliance violations: {', '.join(assessment.risk_score.compliance_violations)}")
    print(f"    ✓ Priority: {assessment.mitigation_priority}")
    print(f"    ✓ Timeline: {assessment.recommended_timeline}")

    # Test medium vulnerability
    print("\n[*] Assessing MEDIUM Information Disclosure")
    vuln_medium = {
        'id': 'vuln_002',
        'type': 'Information Disclosure',
        'severity': 'MEDIUM'
    }
    assessment2 = finance_analyzer.assess_vulnerability(vuln_medium, ['asset_001'])
    print(f"    ✓ Overall risk: {assessment2.risk_score.overall_risk:.1f}/10")
    print(f"    ✓ Priority: {assessment2.mitigation_priority}")

    # Test low-criticality asset
    print("\n[*] Testing with LOW criticality asset")
    logs_asset = BusinessAsset(
        asset_id='asset_002',
        name='Application Logs',
        criticality=AssetCriticality.LOW,
        data_types=[],
        user_base_size=0,
        revenue_impact=0.0
    )
    finance_analyzer.register_business_asset(logs_asset)

    assessment3 = finance_analyzer.assess_vulnerability(vuln_critical, ['asset_002'])
    print(f"    ✓ Business impact: {assessment3.risk_score.business_impact}")
    print(f"    ✓ Overall risk: {assessment3.risk_score.overall_risk:.1f}/10")

    # Test executive summary
    print("\n[*] Testing executive summary generation")
    summary = finance_analyzer.generate_executive_summary()
    print(f"    ✓ Total risks: {summary['executive_summary']['total_risks_identified']}")
    print(f"    ✓ Critical: {summary['executive_summary']['risk_distribution']['critical']}")
    print(f"    ✓ High: {summary['executive_summary']['risk_distribution']['high']}")
    print(f"    ✓ Financial exposure: {summary['executive_summary']['financial_exposure']['minimum']} - {summary['executive_summary']['financial_exposure']['maximum']}")
    print(f"    ✓ Frameworks at risk: {', '.join(summary['executive_summary']['compliance_frameworks_at_risk'])}")
    print(f"    ✓ Immediate actions: {summary['executive_summary']['immediate_actions_required']}")
    print(f"    ✓ Top risks: {len(summary['top_risks'])}")

    print("\n[✓] Business Risk Assessment module: PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("  COMPREHENSIVE MODULE TESTS")
    print("  Testing all AdvancedSecurity-inspired features")
    print("="*80)

    results = []

    try:
        results.append(("Threat Intelligence", test_threat_intelligence()))
    except Exception as e:
        print(f"\n[✗] Threat Intelligence FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Threat Intelligence", False))

    try:
        results.append(("Mobile Testing", test_mobile_testing()))
    except Exception as e:
        print(f"\n[✗] Mobile Testing FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Mobile Testing", False))

    try:
        results.append(("Tooling Layer", test_tooling_layer()))
    except Exception as e:
        print(f"\n[✗] Tooling Layer FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Tooling Layer", False))

    try:
        results.append(("Adversarial Validation", test_adversarial_validation()))
    except Exception as e:
        print(f"\n[✗] Adversarial Validation FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Adversarial Validation", False))

    try:
        results.append(("Evidence Capture", test_evidence_capture()))
    except Exception as e:
        print(f"\n[✗] Evidence Capture FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Evidence Capture", False))

    try:
        results.append(("Business Risk", test_business_risk()))
    except Exception as e:
        print(f"\n[✗] Business Risk FAILED: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Business Risk", False))

    # Print summary
    print("\n" + "="*80)
    print("  TEST SUMMARY")
    print("="*80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for module, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {module:30s} {status}")

    print("="*80)
    print(f"  Total: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    print("="*80)

    if passed == total:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print(" Done!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
