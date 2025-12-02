"""
HTML report generator
"""
from typing import List, Dict, Any
from datetime import datetime

from ..core.scanner import Finding, Severity


class HTMLReporter:
    """Generate HTML format security report"""

    def __init__(self):
        pass

    def generate(self, findings: List[Finding], stats: Dict[str, Any],
                 project_path: str) -> str:
        """
        Generate HTML report

        Args:
            findings: List of security findings
            stats: Scan statistics
            project_path: Path to scanned project

        Returns:
            HTML report as string
        """
        # Group findings by severity
        findings_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }

        for finding in findings:
            findings_by_severity[finding.severity.value].append(finding)

        html = self._generate_html_template(
            project_path, stats, findings_by_severity
        )

        return html

    def _generate_html_template(self, project_path: str, stats: Dict[str, Any],
                                findings_by_severity: Dict[str, List[Finding]]) -> str:
        """Generate complete HTML document"""

        total_findings = sum(len(findings) for findings in findings_by_severity.values())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report</title>
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
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .scan-info {{
            opacity: 0.9;
            margin-top: 15px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}

        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}

        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}

        .severity-section {{
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .severity-header {{
            padding: 20px;
            color: white;
            font-size: 1.3em;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333 !important; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}

        .finding {{
            border-bottom: 1px solid #eee;
            padding: 20px;
        }}

        .finding:last-child {{
            border-bottom: none;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }}

        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
            flex: 1;
        }}

        .finding-meta {{
            display: flex;
            gap: 15px;
            font-size: 0.9em;
            color: #666;
            margin-bottom: 15px;
        }}

        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}

        .badge-cwe {{
            background: #e3f2fd;
            color: #1976d2;
        }}

        .badge-owasp {{
            background: #f3e5f5;
            color: #7b1fa2;
        }}

        .finding-description {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}

        .code-snippet {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-bottom: 15px;
            line-height: 1.5;
        }}

        .code-snippet .highlight {{
            background: #264f78;
            display: block;
        }}

        .recommendation {{
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            border-radius: 5px;
        }}

        .recommendation strong {{
            color: #0c5460;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }}

        .no-findings {{
            padding: 40px;
            text-align: center;
            color: #666;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Audit Report</h1>
            <div class="scan-info">
                <p><strong>Project:</strong> {project_path}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Files Scanned:</strong> {stats['total_files_scanned']} | <strong>Lines:</strong> {stats['total_lines_scanned']} | <strong>Duration:</strong> {stats['scan_duration']:.2f}s</p>
            </div>
        </header>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value" style="color: #dc3545;">{stats['findings_by_severity']['CRITICAL']}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value" style="color: #fd7e14;">{stats['findings_by_severity']['HIGH']}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value" style="color: #ffc107;">{stats['findings_by_severity']['MEDIUM']}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="value" style="color: #28a745;">{stats['findings_by_severity']['LOW']}</div>
            </div>
            <div class="summary-card">
                <h3>Info</h3>
                <div class="value" style="color: #17a2b8;">{stats['findings_by_severity']['INFO']}</div>
            </div>
        </div>

        {self._generate_findings_sections(findings_by_severity)}

        <footer>
            <p>Generated by Security Audit System v1.0</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _generate_findings_sections(self, findings_by_severity: Dict[str, List[Finding]]) -> str:
        """Generate HTML sections for each severity level"""
        sections = []

        severity_config = [
            ('CRITICAL', 'critical', 'Critical'),
            ('HIGH', 'high', 'High'),
            ('MEDIUM', 'medium', 'Medium'),
            ('LOW', 'low', 'Low'),
            ('INFO', 'info', 'Info')
        ]

        for severity_key, severity_class, severity_label in severity_config:
            findings = findings_by_severity[severity_key]
            if not findings:
                continue

            section = f"""
        <div class="severity-section">
            <div class="severity-header severity-{severity_class}">
                <span>{severity_label} Severity Issues</span>
                <span>{len(findings)} finding(s)</span>
            </div>
            {self._generate_findings_html(findings)}
        </div>"""

            sections.append(section)

        if not sections:
            return '<div class="severity-section"><div class="no-findings">No security issues found!</div></div>'

        return '\n'.join(sections)

    def _generate_findings_html(self, findings: List[Finding]) -> str:
        """Generate HTML for individual findings"""
        findings_html = []

        for finding in findings:
            badges = []
            if finding.cwe_id:
                badges.append(f'<span class="badge badge-cwe">{finding.cwe_id}</span>')
            if finding.owasp_category:
                badges.append(f'<span class="badge badge-owasp">{finding.owasp_category}</span>')

            badges_html = ' '.join(badges) if badges else ''

            finding_html = f"""
            <div class="finding">
                <div class="finding-header">
                    <div class="finding-title">{self._escape_html(finding.title)}</div>
                </div>
                <div class="finding-meta">
                    <div class="meta-item">
                        <strong>Scanner:</strong> {self._escape_html(finding.scanner)}
                    </div>
                    <div class="meta-item">
                        <strong>File:</strong> {self._escape_html(finding.file_path)}:{finding.line_number}
                    </div>
                    {f'<div class="meta-item">{badges_html}</div>' if badges_html else ''}
                </div>
                <div class="finding-description">
                    {self._escape_html(finding.description)}
                </div>
                {f'<pre class="code-snippet">{self._format_code_snippet(finding.code_snippet)}</pre>' if finding.code_snippet else ''}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {self._escape_html(finding.recommendation)}
                </div>
            </div>"""

            findings_html.append(finding_html)

        return '\n'.join(findings_html)

    def _format_code_snippet(self, snippet: str) -> str:
        """Format code snippet with highlighting"""
        lines = []
        for line in snippet.split('\n'):
            if line.strip().startswith('>>>'):
                lines.append(f'<span class="highlight">{self._escape_html(line)}</span>')
            else:
                lines.append(self._escape_html(line))
        return '\n'.join(lines)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ''
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

    def save_to_file(self, report: str, file_path: str):
        """Save report to file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report)
