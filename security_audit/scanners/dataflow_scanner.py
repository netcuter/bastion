"""
Data Flow Scanner
Uses taint tracking and call graph analysis for interprocedural vulnerability detection
"""
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity
from ..core.taint_tracker import TaintTracker
from ..core.advanced_analyzer import AdvancedAnalyzer
from ..framework_rules import detect_framework, get_framework_rules


class DataFlowScanner(BaseScanner):
    """
    Advanced scanner using data flow analysis and taint tracking
    Detects vulnerabilities that span multiple functions and files
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.taint_tracker = TaintTracker()
        self.advanced_analyzer = AdvancedAnalyzer()

    def get_name(self) -> str:
        return "Data Flow Analysis Scanner"

    def get_description(self) -> str:
        return "Advanced scanner with taint tracking, call graph analysis, and framework-specific rules"

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """
        Perform data flow analysis on file

        Args:
            file_path: Path to file
            content: File content
            file_type: File extension

        Returns:
            List of findings from data flow analysis
        """
        findings = []

        # 1. Taint Tracking Analysis
        taint_findings = self._perform_taint_analysis(file_path, content, file_type)
        findings.extend(taint_findings)

        # 2. Framework-Specific Analysis
        framework_findings = self._perform_framework_analysis(file_path, content, file_type)
        findings.extend(framework_findings)

        # 3. Advanced Analysis (call graph, interprocedural)
        advanced_findings = self._perform_advanced_analysis(file_path, content, file_type)
        findings.extend(advanced_findings)

        return findings

    def _perform_taint_analysis(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Perform taint tracking analysis"""
        findings = []

        try:
            taint_flows = self.taint_tracker.track_taint_flow(content, file_type)

            for flow in taint_flows:
                # Only report unsanitized flows
                if not flow.sanitized:
                    severity = self._determine_severity(flow.vulnerability_type)

                    finding = Finding(
                        scanner=self.get_name(),
                        severity=severity,
                        title=f"Data Flow Vulnerability: {flow.vulnerability_type}",
                        description=f"Tainted data flows from {flow.source} (line {flow.source_line}) to {flow.sink} (line {flow.sink_line}) without sanitization",
                        file_path=file_path,
                        line_number=flow.sink_line,
                        code_snippet=self._format_taint_flow(flow),
                        recommendation=self._get_sanitization_recommendation(flow.vulnerability_type),
                        cwe_id=self._get_cwe_for_vuln_type(flow.vulnerability_type),
                        owasp_category="Data Flow Analysis"
                    )
                    findings.append(finding)

        except Exception as e:
            # Silently handle errors in taint analysis
            pass

        return findings

    def _perform_framework_analysis(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Perform framework-specific analysis"""
        findings = []

        try:
            # Detect frameworks
            frameworks = detect_framework(content, file_type)

            # Apply framework-specific rules
            for framework in frameworks:
                rules = get_framework_rules(framework)
                if rules:
                    framework_findings = rules.check_code(content, file_path)

                    # Convert to Finding objects
                    for fw_finding in framework_findings:
                        finding = Finding(
                            scanner=self.get_name(),
                            severity=self._string_to_severity(fw_finding.get('severity', 'MEDIUM')),
                            title=f"{fw_finding.get('framework', 'Framework')} - {fw_finding.get('category', 'Security Issue')}",
                            description=fw_finding.get('description', ''),
                            file_path=fw_finding.get('file_path', file_path),
                            line_number=fw_finding.get('line_number', 1),
                            code_snippet=fw_finding.get('code_snippet', ''),
                            recommendation=fw_finding.get('recommendation', ''),
                            cwe_id=fw_finding.get('cwe', ''),
                            owasp_category=f"{fw_finding.get('framework', 'Framework')} Security"
                        )
                        findings.append(finding)

        except Exception as e:
            # Silently handle framework analysis errors
            pass

        return findings

    def _perform_advanced_analysis(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Perform call graph and interprocedural analysis"""
        findings = []

        try:
            results = self.advanced_analyzer.analyze_single_file(file_path, content, file_type)

            # Process taint flows from advanced analyzer
            for taint_flow in results.get('taint_flows', []):
                if taint_flow.get('severity') != 'INFO':
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=self._string_to_severity(taint_flow.get('severity', 'MEDIUM')),
                        title=f"Interprocedural {taint_flow.get('vulnerability_type', 'Vulnerability')}",
                        description=f"Data flow from {taint_flow.get('source')} to {taint_flow.get('sink')}",
                        file_path=file_path,
                        line_number=taint_flow.get('sink_line', 1),
                        code_snippet=f"Flow: {taint_flow.get('source')} → {taint_flow.get('sink')}",
                        recommendation="Review data flow and add appropriate sanitization",
                        cwe_id=self._get_cwe_for_vuln_type(taint_flow.get('vulnerability_type', '')),
                        owasp_category="Interprocedural Analysis"
                    )
                    findings.append(finding)

        except Exception as e:
            # Silently handle advanced analysis errors
            pass

        return findings

    def _determine_severity(self, vuln_type: str) -> Severity:
        """Determine severity based on vulnerability type"""
        critical_types = ['sql_injection', 'command_injection', 'code_injection']
        high_types = ['xss', 'path_traversal', 'xxe']

        vuln_type_lower = vuln_type.lower()

        if any(ct in vuln_type_lower for ct in critical_types):
            return Severity.CRITICAL
        elif any(ht in vuln_type_lower for ht in high_types):
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _string_to_severity(self, severity_str: str) -> Severity:
        """Convert string to Severity enum"""
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO,
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)

    def _get_sanitization_recommendation(self, vuln_type: str) -> str:
        """Get sanitization recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or ORM methods. Never concatenate user input in SQL.',
            'command_injection': 'Avoid executing system commands with user input. Use subprocess with shell=False and array arguments.',
            'xss': 'Escape HTML output using framework auto-escaping or html.escape(). Use DOMPurify for rich content.',
            'path_traversal': 'Use os.path.basename() to extract filename. Validate against whitelist.',
            'xxe': 'Disable DTD processing. Use defusedxml library.',
        }
        return recommendations.get(vuln_type.lower(), 'Validate and sanitize all user input.')

    def _get_cwe_for_vuln_type(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'xss': 'CWE-79',
            'path_traversal': 'CWE-22',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918',
            'code_injection': 'CWE-94',
        }
        return cwe_map.get(vuln_type.lower(), 'CWE-74')

    def _format_taint_flow(self, flow) -> str:
        """Format taint flow for display"""
        lines = []
        lines.append(f"Variable: {flow.variable}")
        lines.append(f"")
        lines.append(f"Flow Path:")
        for step_line, step_desc in flow.path:
            lines.append(f"  Line {step_line}: {step_desc}")

        return "\n".join(lines)
