"""
JSON report generator
"""
import json
from typing import List, Dict, Any
from datetime import datetime

from ..core.scanner import Finding


class JSONReporter:
    """Generate JSON format security report"""

    def __init__(self):
        pass

    def generate(self, findings: List[Finding], stats: Dict[str, Any],
                 project_path: str) -> str:
        """
        Generate JSON report

        Args:
            findings: List of security findings
            stats: Scan statistics
            project_path: Path to scanned project

        Returns:
            JSON report as string
        """
        report = {
            "scan_info": {
                "scan_date": datetime.now().isoformat(),
                "project_path": project_path,
                "scanner_version": "1.0.0"
            },
            "summary": {
                "total_findings": len(findings),
                "critical": stats["findings_by_severity"]["CRITICAL"],
                "high": stats["findings_by_severity"]["HIGH"],
                "medium": stats["findings_by_severity"]["MEDIUM"],
                "low": stats["findings_by_severity"]["LOW"],
                "info": stats["findings_by_severity"]["INFO"]
            },
            "statistics": {
                "files_scanned": stats["total_files_scanned"],
                "lines_scanned": stats["total_lines_scanned"],
                "scan_duration_seconds": stats["scan_duration"]
            },
            "findings": [self._finding_to_dict(f) for f in findings]
        }

        return json.dumps(report, indent=2)

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "scanner": finding.scanner,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "recommendation": finding.recommendation,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category
        }

    def save_to_file(self, report: str, file_path: str):
        """Save report to file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report)
