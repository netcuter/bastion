"""
SARIF (Static Analysis Results Interchange Format) reporter
For CI/CD integration with GitHub, GitLab, etc.
"""
import json
from typing import List, Dict, Any
from datetime import datetime

from ..core.scanner import Finding, Severity


class SARIFReporter:
    """Generate SARIF format security report"""

    def __init__(self):
        self.severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }

    def generate(self, findings: List[Finding], stats: Dict[str, Any],
                 project_path: str) -> str:
        """
        Generate SARIF report

        Args:
            findings: List of security findings
            stats: Scan statistics
            project_path: Path to scanned project

        Returns:
            SARIF JSON report as string
        """
        # Group findings by scanner
        findings_by_scanner = {}
        for finding in findings:
            scanner = finding.scanner
            if scanner not in findings_by_scanner:
                findings_by_scanner[scanner] = []
            findings_by_scanner[scanner].append(finding)

        # Create SARIF runs (one per scanner)
        runs = []
        for scanner_name, scanner_findings in findings_by_scanner.items():
            run = self._create_run(scanner_name, scanner_findings)
            runs.append(run)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs
        }

        return json.dumps(sarif, indent=2)

    def _create_run(self, scanner_name: str, findings: List[Finding]) -> Dict[str, Any]:
        """Create a SARIF run for a scanner"""
        # Create rules from unique finding types
        rules = self._create_rules(findings)

        # Create results from findings
        results = [self._create_result(finding) for finding in findings]

        run = {
            "tool": {
                "driver": {
                    "name": scanner_name,
                    "version": "1.0.0",
                    "informationUri": "https://github.com/security-audit-system",
                    "rules": rules
                }
            },
            "results": results
        }

        return run

    def _create_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create SARIF rules from findings"""
        rules_dict = {}

        for finding in findings:
            rule_id = self._get_rule_id(finding)
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "helpUri": self._get_help_uri(finding),
                    "properties": {
                        "security-severity": self._get_security_severity(finding.severity)
                    }
                }

                if finding.cwe_id:
                    rules_dict[rule_id]["properties"]["tags"] = [finding.cwe_id]

        return list(rules_dict.values())

    def _create_result(self, finding: Finding) -> Dict[str, Any]:
        """Create a SARIF result from a finding"""
        # Ensure line number is valid for SARIF (must be >= 1)
        line_number = finding.line_number if finding.line_number and finding.line_number >= 1 else 1
        
        result = {
            "ruleId": self._get_rule_id(finding),
            "level": self.severity_map[finding.severity],
            "message": {
                "text": f"{finding.description}\n\nRecommendation: {finding.recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        },
                        "region": {
                            "startLine": line_number,
                            "startColumn": 1
                        }
                    }
                }
            ]
        }

        if finding.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.code_snippet
            }

        return result

    def _get_rule_id(self, finding: Finding) -> str:
        """Generate rule ID from finding"""
        if finding.cwe_id:
            return finding.cwe_id
        # Create ID from title
        return finding.title.lower().replace(' ', '-').replace('(', '').replace(')', '')

    def _get_help_uri(self, finding: Finding) -> str:
        """Get help URI for the finding"""
        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace('CWE-', '')
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        return ""

    def _get_security_severity(self, severity: Severity) -> str:
        """Convert severity to SARIF security severity score"""
        severity_scores = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0"
        }
        return severity_scores.get(severity, "5.0")

    def save_to_file(self, report: str, file_path: str):
        """Save report to file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report)
