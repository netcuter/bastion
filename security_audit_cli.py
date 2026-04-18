#!/usr/bin/env python3
"""
Security Audit CLI
Command-line interface for the security audit system
"""
import argparse
import sys
from pathlib import Path

from security_audit._version import __version__
from security_audit.core import Config, AuditEngine
from security_audit.scanners import (
    WebVulnerabilityScanner,
    SecretsDetector,
    DependencyScanner,
    ASVSScanner,
    MultiLanguageScanner,
    AdvancedPatternsScanner,
    DataFlowScanner,
    MCPFileScanner,
)
from security_audit.reporters import (
    JSONReporter,
    HTMLReporter,
    SARIFReporter,
    ASVSReporter
)
from security_audit.asvs import ASVSLevel

# ML-based FP Classifier (trained Random Forest)
try:
    from security_audit.ml.ml_classifier import MLFPClassifier
    ML_CLASSIFIER_AVAILABLE = True
except ImportError:
    ML_CLASSIFIER_AVAILABLE = False


def main():
    parser = argparse.ArgumentParser(
        description='Security Audit System for Web Applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan current directory
  python3 security_audit_cli.py --path .

  # Scan with ML-based false positive reduction (58%% FP reduction!)
  python3 security_audit_cli.py --path . --ml-fp-reduction

  # Scan with HTML report
  python3 security_audit_cli.py --path /path/to/project --output html --report report.html

  # Scan with specific scanners
  python3 security_audit_cli.py --path . --scanners web,secrets

  # Scan with custom config
  python3 security_audit_cli.py --path . --config config.json

  # Fail on critical issues (useful for CI/CD)
  python3 security_audit_cli.py --path . --fail-on critical

  # Full scan with ML filtering and verbose output
  python3 security_audit_cli.py --path . --ml-fp-reduction --verbose
        '''
    )

    parser.add_argument(
        '--path',
        type=str,
        default='.',
        help='Path to project directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (JSON)'
    )

    parser.add_argument(
        '--output',
        type=str,
        choices=['json', 'html', 'sarif', 'asvs-json', 'asvs-html'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--asvs-level',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='ASVS verification level (1=Opportunistic, 2=Standard, 3=Advanced)'
    )

    parser.add_argument(
        '--report',
        type=str,
        help='Output report file path'
    )

    parser.add_argument(
        '--scanners',
        type=str,
        help='Comma-separated list of scanners to run (web,secrets,dependencies,asvs,multilang,advanced,dataflow)'
    )

    parser.add_argument(
        '--fail-on',
        type=str,
        choices=['critical', 'high', 'medium', 'low'],
        help='Exit with error code if findings of this severity or higher are found'
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--ml-fp-reduction',
        action='store_true',
        help='Enable ML-based false positive reduction (58%% FP reduction, 100%% local)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'Bastion Security Audit System v{__version__}'
    )

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Initialize audit engine
    engine = AuditEngine(config)

    # Register scanners
    scanners_to_run = []
    if args.scanners:
        scanner_names = [s.strip() for s in args.scanners.split(',')]
        scanners_to_run = scanner_names
    else:
        scanners_to_run = ['web', 'secrets', 'dependencies', 'asvs', 'multilang', 'advanced', 'dataflow', 'mcp']

    if 'web' in scanners_to_run:
        web_scanner = WebVulnerabilityScanner(config.get_scanner_config('web_vulnerabilities'))
        engine.register_scanner(web_scanner)
        if args.verbose:
            print(f"[+] Registered: {web_scanner.get_name()}")

    if 'secrets' in scanners_to_run:
        secrets_scanner = SecretsDetector(config.get_scanner_config('secrets_detector'))
        engine.register_scanner(secrets_scanner)
        if args.verbose:
            print(f"[+] Registered: {secrets_scanner.get_name()}")

    if 'dependencies' in scanners_to_run:
        dep_scanner = DependencyScanner(config.get_scanner_config('dependency_scanner'))
        engine.register_scanner(dep_scanner)
        if args.verbose:
            print(f"[+] Registered: {dep_scanner.get_name()}")

    if 'asvs' in scanners_to_run:
        asvs_config = config.get_scanner_config('asvs_scanner')
        asvs_config['asvs_level'] = args.asvs_level
        asvs_scanner = ASVSScanner(asvs_config)
        engine.register_scanner(asvs_scanner)
        if args.verbose:
            print(f"[+] Registered: {asvs_scanner.get_name()} (Level {args.asvs_level})")

    if 'multilang' in scanners_to_run:
        ml_scanner = MultiLanguageScanner(config.get_scanner_config('multilanguage_scanner'))
        engine.register_scanner(ml_scanner)
        if args.verbose:
            print(f"[+] Registered: {ml_scanner.get_name()}")

    if 'advanced' in scanners_to_run:
        advanced_scanner = AdvancedPatternsScanner(config.get_scanner_config('advanced_patterns'))
        engine.register_scanner(advanced_scanner)
        if args.verbose:
            print(f"[+] Registered: {advanced_scanner.get_name()}")

    if 'dataflow' in scanners_to_run:
        dataflow_scanner = DataFlowScanner(config.get_scanner_config('dataflow'))
        engine.register_scanner(dataflow_scanner)
        if args.verbose:
            print(f"[+] Registered: {dataflow_scanner.get_name()}")

    if 'mcp' in scanners_to_run:
        mcp_scanner = MCPFileScanner(config.get_scanner_config('mcp'))
        engine.register_scanner(mcp_scanner)
        if args.verbose:
            print(f"[+] Registered: {mcp_scanner.get_name()}")

    # Validate path
    project_path = Path(args.path).resolve()
    if not project_path.exists():
        print(f"[!] Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    # Run scan
    try:
        findings = engine.scan_directory(str(project_path))
        stats = engine.get_stats()

        # Apply ML-based FP reduction if requested
        if args.ml_fp_reduction:
            if not ML_CLASSIFIER_AVAILABLE:
                print("\n[!] Warning: ML classifier not available")
                print("[!] Install dependencies: pip install scikit-learn numpy joblib")
                print("[!] Continuing without FP reduction...")
            else:
                print(f"\n[🤖] Applying ML-based False Positive Reduction...")
                print(f"[📊] Before ML: {len(findings)} findings")

                try:
                    # Initialize ML classifier
                    ml_classifier = MLFPClassifier()

                    # Convert findings to dict format
                    findings_dicts = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

                    # Filter with ML
                    real_vulns, false_positives = ml_classifier.filter_findings(findings_dicts)

                    # Update findings (convert back if needed)
                    findings = real_vulns

                    # Print statistics
                    total = len(real_vulns) + len(false_positives)
                    fp_reduction = (len(false_positives) / total * 100) if total > 0 else 0

                    print(f"[✅] After ML:  {len(real_vulns)} findings")
                    print(f"[🎯] FP Reduction: {fp_reduction:.1f}% ({len(false_positives)} false positives filtered)")

                    if args.verbose:
                        print(f"\n[📋] ML Classification Details:")
                        print(f"    Real vulnerabilities: {len(real_vulns)}")
                        print(f"    False positives:      {len(false_positives)}")
                        print(f"    Total findings:       {total}")
                        print(f"    Model: Random Forest (trained on 9 apps, 5 languages)")

                except Exception as e:
                    print(f"[!] Error applying ML classifier: {e}")
                    if args.verbose:
                        import traceback
                        traceback.print_exc()
                    print(f"[!] Continuing with unfiltered results...")

        # Generate report
        report_content = generate_report(
            findings, stats, str(project_path), args.output
        )

        # Save or display report
        if args.report:
            save_report(report_content, args.report, args.output)
            print(f"\n[+] Report saved to: {args.report}")
        else:
            if args.output == 'html':
                # For HTML, save to default file
                default_file = 'security_report.html'
                save_report(report_content, default_file, args.output)
                print(f"\n[+] HTML report saved to: {default_file}")
            else:
                print("\n" + "="*80)
                print("SECURITY AUDIT REPORT")
                print("="*80)
                print(report_content)

        # Print summary
        print_summary(stats)

        # Check fail-on condition
        exit_code = check_fail_condition(stats, args.fail_on)
        sys.exit(exit_code)

    except Exception as e:
        print(f"\n[!] Error during scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def print_banner():
    """Print ASCII banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         Security Audit System for Web Applications           ║
║                         Version 3.0.0                         ║
║         🤖 AI-Powered Engine (AdvancedSecurity-Inspired) 🤖          ║
║   Data Flow • ML (58% FP ↓) • Threat Intel • Mobile Testing ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def generate_report(findings, stats, project_path, output_format):
    """Generate report in specified format"""
    if output_format == 'json':
        reporter = JSONReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'html':
        reporter = HTMLReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'sarif':
        reporter = SARIFReporter()
        return reporter.generate(findings, stats, project_path)
    elif output_format == 'asvs-json':
        reporter = ASVSReporter(ASVSLevel.LEVEL_1)
        return reporter.generate(findings, stats, project_path, 'json')
    elif output_format == 'asvs-html':
        reporter = ASVSReporter(ASVSLevel.LEVEL_1)
        return reporter.generate(findings, stats, project_path, 'html')
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def save_report(content, file_path, output_format):
    """Save report to file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def print_summary(stats):
    """Print scan summary"""
    print("\n" + "="*80)
    print("SCAN SUMMARY")
    print("="*80)
    print(f"Files scanned:     {stats['total_files_scanned']}")
    print(f"Lines scanned:     {stats['total_lines_scanned']}")
    print(f"Scan duration:     {stats['scan_duration']:.2f} seconds")
    print(f"\nFindings by severity:")
    print(f"  CRITICAL:        {stats['findings_by_severity']['CRITICAL']}")
    print(f"  HIGH:            {stats['findings_by_severity']['HIGH']}")
    print(f"  MEDIUM:          {stats['findings_by_severity']['MEDIUM']}")
    print(f"  LOW:             {stats['findings_by_severity']['LOW']}")
    print(f"  INFO:            {stats['findings_by_severity']['INFO']}")
    print("="*80)


def check_fail_condition(stats, fail_on):
    """Check if we should exit with error code based on findings"""
    if not fail_on:
        return 0

    severity_levels = {
        'critical': ['CRITICAL'],
        'high': ['CRITICAL', 'HIGH'],
        'medium': ['CRITICAL', 'HIGH', 'MEDIUM'],
        'low': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    }

    severities_to_check = severity_levels[fail_on]

    for severity in severities_to_check:
        if stats['findings_by_severity'][severity] > 0:
            print(f"\n[!] Exiting with error: Found {severity} severity issues")
            return 1

    return 0


if __name__ == '__main__':
    main()
