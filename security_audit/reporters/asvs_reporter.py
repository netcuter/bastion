"""
ASVS Compliance Reporter
Generates detailed ASVS compliance reports
"""
import json
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict

from ..core.scanner import Finding
from ..asvs import ASVSLevel, ASVSCategory, ASVSRequirements


class ASVSReporter:
    """Generate ASVS compliance reports"""

    def __init__(self, asvs_level: ASVSLevel = ASVSLevel.LEVEL_1):
        self.asvs_level = asvs_level
        self.requirements = ASVSRequirements.get_requirements_by_level(asvs_level)

    def generate(self, findings: List[Finding], stats: Dict[str, Any],
                 project_path: str, output_format: str = 'json') -> str:
        """
        Generate ASVS compliance report

        Args:
            findings: List of security findings
            stats: Scan statistics
            project_path: Path to scanned project
            output_format: 'json' or 'html'

        Returns:
            ASVS report as string
        """
        compliance_data = self._analyze_compliance(findings)

        if output_format == 'json':
            return self._generate_json_report(compliance_data, stats, project_path)
        elif output_format == 'html':
            return self._generate_html_report(compliance_data, stats, project_path)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _analyze_compliance(self, findings: List[Finding]) -> Dict[str, Any]:
        """Analyze ASVS compliance from findings"""
        # Group findings by ASVS category
        findings_by_category = defaultdict(list)
        asvs_findings = []

        for finding in findings:
            if 'ASVS' in str(finding.owasp_category):
                asvs_findings.append(finding)
                # Extract category from owasp_category (e.g., "ASVS V2.1" -> V2)
                if finding.owasp_category:
                    category_match = finding.owasp_category.split()[1] if len(finding.owasp_category.split()) > 1 else None
                    if category_match:
                        category_code = category_match.split('.')[0]  # V2.1 -> V2
                        findings_by_category[category_code].append(finding)

        # Calculate compliance per category
        category_compliance = {}
        for category in ASVSCategory:
            category_code = category.value
            category_reqs = ASVSRequirements.get_requirements_by_category(category)
            category_reqs_for_level = [r for r in category_reqs if r.level.value <= self.asvs_level.value]

            total_reqs = len(category_reqs_for_level)
            failed_reqs = len(findings_by_category.get(category_code, []))
            passed_reqs = max(0, total_reqs - failed_reqs)

            if total_reqs > 0:
                compliance_pct = (passed_reqs / total_reqs) * 100
            else:
                compliance_pct = 100.0

            category_compliance[category_code] = {
                'name': category.name.replace('_', ' ').title(),
                'total_requirements': total_reqs,
                'passed': passed_reqs,
                'failed': failed_reqs,
                'compliance_percentage': round(compliance_pct, 2),
                'findings': findings_by_category.get(category_code, [])
            }

        # Overall compliance
        total_requirements = sum(c['total_requirements'] for c in category_compliance.values())
        total_passed = sum(c['passed'] for c in category_compliance.values())
        total_failed = sum(c['failed'] for c in category_compliance.values())

        overall_compliance = (total_passed / total_requirements * 100) if total_requirements > 0 else 100.0

        return {
            'asvs_level': self.asvs_level.value,
            'overall_compliance': round(overall_compliance, 2),
            'total_requirements': total_requirements,
            'total_passed': total_passed,
            'total_failed': total_failed,
            'category_compliance': category_compliance,
            'asvs_findings': asvs_findings
        }

    def _generate_json_report(self, compliance_data: Dict[str, Any],
                              stats: Dict[str, Any], project_path: str) -> str:
        """Generate JSON ASVS report"""
        report = {
            'scan_info': {
                'scan_date': datetime.now().isoformat(),
                'project_path': project_path,
                'asvs_version': '4.0',
                'asvs_level': compliance_data['asvs_level']
            },
            'compliance_summary': {
                'overall_compliance_percentage': compliance_data['overall_compliance'],
                'total_requirements': compliance_data['total_requirements'],
                'requirements_passed': compliance_data['total_passed'],
                'requirements_failed': compliance_data['total_failed'],
                'compliance_status': self._get_compliance_status(compliance_data['overall_compliance'])
            },
            'category_breakdown': {}
        }

        # Add category details
        for category_code, category_data in compliance_data['category_compliance'].items():
            report['category_breakdown'][category_code] = {
                'category_name': category_data['name'],
                'compliance_percentage': category_data['compliance_percentage'],
                'total_requirements': category_data['total_requirements'],
                'passed': category_data['passed'],
                'failed': category_data['failed'],
                'findings': [f.to_dict() for f in category_data['findings']]
            }

        return json.dumps(report, indent=2)

    def _generate_html_report(self, compliance_data: Dict[str, Any],
                              stats: Dict[str, Any], project_path: str) -> str:
        """Generate HTML ASVS compliance report"""
        compliance_status = self._get_compliance_status(compliance_data['overall_compliance'])
        status_color = self._get_status_color(compliance_data['overall_compliance'])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASVS Compliance Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}

        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .asvs-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }}

        .summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .compliance-meter {{
            width: 100%;
            height: 40px;
            background: #e0e0e0;
            border-radius: 20px;
            overflow: hidden;
            margin: 20px 0;
        }}

        .compliance-fill {{
            height: 100%;
            background: {status_color};
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
        }}

        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}

        .category {{
            background: white;
            margin-bottom: 20px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .category-header {{
            padding: 20px;
            background: #3498db;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .category-body {{
            padding: 20px;
        }}

        .compliance-bar {{
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }}

        .compliance-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #2ecc71);
        }}

        .requirement {{
            padding: 15px;
            border-left: 4px solid #e74c3c;
            background: #fff5f5;
            margin: 10px 0;
            border-radius: 4px;
        }}

        .requirement-passed {{
            border-left-color: #27ae60;
            background: #f0fff4;
        }}

        .status-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}

        .status-excellent {{ background: #27ae60; color: white; }}
        .status-good {{ background: #2ecc71; color: white; }}
        .status-fair {{ background: #f39c12; color: white; }}
        .status-poor {{ background: #e74c3c; color: white; }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>OWASP ASVS Compliance Report</h1>
            <p>Application Security Verification Standard</p>
            <span class="asvs-badge">ASVS Level {compliance_data['asvs_level']}</span>
            <span class="asvs-badge">Version 4.0</span>
            <p style="margin-top: 15px; opacity: 0.9;">
                <strong>Project:</strong> {project_path}<br>
                <strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </header>

        <div class="summary">
            <h2>Compliance Summary</h2>
            <div class="compliance-meter">
                <div class="compliance-fill" style="width: {compliance_data['overall_compliance']}%">
                    {compliance_data['overall_compliance']}%
                </div>
            </div>
            <div style="text-align: center; margin: 10px 0;">
                <span class="status-badge status-{self._get_status_class(compliance_data['overall_compliance'])}">
                    {compliance_status}
                </span>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{compliance_data['total_requirements']}</div>
                    <div class="stat-label">Total Requirements</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #27ae60;">{compliance_data['total_passed']}</div>
                    <div class="stat-label">Passed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #e74c3c;">{compliance_data['total_failed']}</div>
                    <div class="stat-label">Failed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{compliance_data['overall_compliance']}%</div>
                    <div class="stat-label">Compliance</div>
                </div>
            </div>
        </div>

        <h2 style="margin: 30px 0 20px 0;">Category Breakdown</h2>

        {self._generate_category_html(compliance_data['category_compliance'])}

        <footer>
            <p>Generated by Security Audit System - ASVS Compliance Module</p>
            <p style="font-size: 0.9em; margin-top: 10px;">
                Based on OWASP ASVS 4.0 - Application Security Verification Standard
            </p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _generate_category_html(self, category_compliance: Dict[str, Any]) -> str:
        """Generate HTML for category breakdown"""
        html_parts = []

        for category_code, data in sorted(category_compliance.items()):
            if data['total_requirements'] == 0:
                continue

            compliance_pct = data['compliance_percentage']
            status_class = self._get_status_class(compliance_pct)

            category_html = f"""
        <div class="category">
            <div class="category-header">
                <div>
                    <h3>{category_code}: {data['name']}</h3>
                    <p style="opacity: 0.9; margin-top: 5px;">
                        {data['passed']}/{data['total_requirements']} requirements passed
                    </p>
                </div>
                <div>
                    <span class="status-badge status-{status_class}">
                        {compliance_pct}%
                    </span>
                </div>
            </div>
            <div class="category-body">
                <div class="compliance-bar">
                    <div class="compliance-bar-fill" style="width: {compliance_pct}%"></div>
                </div>
                {self._generate_findings_html(data['findings'])}
            </div>
        </div>"""

            html_parts.append(category_html)

        return '\n'.join(html_parts)

    def _generate_findings_html(self, findings: List[Finding]) -> str:
        """Generate HTML for findings in a category"""
        if not findings:
            return '<p style="color: #27ae60; padding: 10px;">✓ No compliance issues found in this category</p>'

        findings_html = []
        for finding in findings[:5]:  # Show max 5 findings per category
            findings_html.append(f"""
                <div class="requirement">
                    <strong>{finding.title}</strong>
                    <p style="margin: 5px 0; color: #666;">{finding.description}</p>
                    <p style="margin-top: 5px; font-size: 0.9em;">
                        <strong>File:</strong> {finding.file_path}:{finding.line_number}<br>
                        <strong>Recommendation:</strong> {finding.recommendation}
                    </p>
                </div>
            """)

        if len(findings) > 5:
            findings_html.append(f'<p style="padding: 10px; color: #666;">... and {len(findings) - 5} more issue(s)</p>')

        return '\n'.join(findings_html)

    def _get_compliance_status(self, compliance_pct: float) -> str:
        """Get compliance status text"""
        if compliance_pct >= 90:
            return "Excellent Compliance"
        elif compliance_pct >= 75:
            return "Good Compliance"
        elif compliance_pct >= 50:
            return "Fair Compliance"
        else:
            return "Poor Compliance"

    def _get_status_class(self, compliance_pct: float) -> str:
        """Get CSS class for compliance status"""
        if compliance_pct >= 90:
            return "excellent"
        elif compliance_pct >= 75:
            return "good"
        elif compliance_pct >= 50:
            return "fair"
        else:
            return "poor"

    def _get_status_color(self, compliance_pct: float) -> str:
        """Get color for compliance meter"""
        if compliance_pct >= 90:
            return "#27ae60"
        elif compliance_pct >= 75:
            return "#2ecc71"
        elif compliance_pct >= 50:
            return "#f39c12"
        else:
            return "#e74c3c"

    def save_to_file(self, report: str, file_path: str):
        """Save report to file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report)
