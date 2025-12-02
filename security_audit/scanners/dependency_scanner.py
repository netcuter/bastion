"""
Dependency vulnerability scanner
Checks for known vulnerabilities in dependencies
"""
import re
import json
from typing import List, Dict, Any
from pathlib import Path

from ..core.scanner import BaseScanner, Finding, Severity


class DependencyScanner(BaseScanner):
    """Scanner for dependency vulnerabilities"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Dependency Scanner"

    def get_description(self) -> str:
        return "Scans dependencies for known vulnerabilities and outdated packages"

    def _init_patterns(self):
        """Initialize dependency file patterns"""
        self.dependency_files = {
            'package.json': self._scan_npm,
            'requirements.txt': self._scan_python,
            'Pipfile': self._scan_pipenv,
            'composer.json': self._scan_php,
            'Gemfile': self._scan_ruby,
            'pom.xml': self._scan_maven,
            'build.gradle': self._scan_gradle,
            'go.mod': self._scan_go,
        }

        # Known vulnerable package patterns (examples - should be updated regularly)
        self.known_vulnerabilities = {
            # Python
            'django<2.2.28': {
                'severity': Severity.CRITICAL,
                'description': 'Django versions before 2.2.28 have SQL injection vulnerability',
                'cve': 'CVE-2022-28346'
            },
            'flask<2.0.0': {
                'severity': Severity.MEDIUM,
                'description': 'Flask versions before 2.0.0 have security issues',
                'cve': 'Multiple CVEs'
            },
            'requests<2.31.0': {
                'severity': Severity.HIGH,
                'description': 'Requests library has security vulnerabilities in older versions',
                'cve': 'CVE-2023-32681'
            },

            # JavaScript
            'lodash<4.17.21': {
                'severity': Severity.HIGH,
                'description': 'Lodash has prototype pollution vulnerabilities',
                'cve': 'CVE-2020-28500'
            },
            'express<4.17.3': {
                'severity': Severity.MEDIUM,
                'description': 'Express.js has security issues in older versions',
                'cve': 'Multiple CVEs'
            },
            'axios<0.21.2': {
                'severity': Severity.HIGH,
                'description': 'Axios has SSRF vulnerability',
                'cve': 'CVE-2021-3749'
            },

            # PHP
            'symfony/http-kernel<4.4.50': {
                'severity': Severity.HIGH,
                'description': 'Symfony HTTP Kernel has cache poisoning vulnerability',
                'cve': 'CVE-2022-24894'
            },
        }

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan dependency file for vulnerabilities"""
        findings = []
        file_name = Path(file_path).name

        # Check if this is a dependency file we can scan
        if file_name in self.dependency_files:
            scan_func = self.dependency_files[file_name]
            findings.extend(scan_func(file_path, content))

        return findings

    def _scan_npm(self, file_path: str, content: str) -> List[Finding]:
        """Scan package.json for vulnerabilities"""
        findings = []

        try:
            data = json.loads(content)
            dependencies = {}
            dependencies.update(data.get('dependencies', {}))
            dependencies.update(data.get('devDependencies', {}))

            for package, version in dependencies.items():
                # Clean version string
                version = version.lstrip('^~>=<')

                # Check for specific vulnerabilities
                package_version = f"{package}<{version}"
                if package_version in self.known_vulnerabilities:
                    vuln = self.known_vulnerabilities[package_version]
                    findings.append(Finding(
                        scanner=self.get_name(),
                        severity=vuln['severity'],
                        title=f"Vulnerable NPM Package: {package}",
                        description=vuln['description'],
                        file_path=file_path,
                        line_number=0,
                        code_snippet=f"{package}: {version}",
                        recommendation=f"Update {package} to a secure version. Run: npm update {package}",
                        cwe_id="CWE-1035",
                        owasp_category="A06:2021 - Vulnerable and Outdated Components"
                    ))

                # Check for wildcard versions
                if version in ['*', 'latest']:
                    findings.append(Finding(
                        scanner=self.get_name(),
                        severity=Severity.MEDIUM,
                        title=f"Unpinned Dependency: {package}",
                        description=f"Package {package} uses wildcard version",
                        file_path=file_path,
                        line_number=0,
                        code_snippet=f"{package}: {version}",
                        recommendation="Pin dependencies to specific versions for reproducible builds",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021 - Vulnerable and Outdated Components"
                    ))

        except json.JSONDecodeError:
            findings.append(Finding(
                scanner=self.get_name(),
                severity=Severity.LOW,
                title="Invalid package.json",
                description="Could not parse package.json file",
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Fix JSON syntax errors",
                cwe_id="",
                owasp_category=""
            ))

        return findings

    def _scan_python(self, file_path: str, content: str) -> List[Finding]:
        """Scan requirements.txt for vulnerabilities"""
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse package and version
            match = re.match(r'([a-zA-Z0-9_-]+)(==|>=|<=|>|<|~=)(.+)', line)
            if match:
                package = match.group(1)
                operator = match.group(2)
                version = match.group(3)

                # Check for specific vulnerabilities
                package_version = f"{package}<{version}"
                if package_version in self.known_vulnerabilities:
                    vuln = self.known_vulnerabilities[package_version]
                    findings.append(Finding(
                        scanner=self.get_name(),
                        severity=vuln['severity'],
                        title=f"Vulnerable Python Package: {package}",
                        description=vuln['description'],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line,
                        recommendation=f"Update {package} to a secure version. Run: pip install --upgrade {package}",
                        cwe_id="CWE-1035",
                        owasp_category="A06:2021 - Vulnerable and Outdated Components"
                    ))

                # Warn about unpinned versions
                if operator in ['>=', '>']:
                    findings.append(Finding(
                        scanner=self.get_name(),
                        severity=Severity.LOW,
                        title=f"Unpinned Dependency: {package}",
                        description=f"Package {package} allows newer versions ({operator}{version})",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line,
                        recommendation="Consider pinning to specific version with == for reproducible builds",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021 - Vulnerable and Outdated Components"
                    ))

        return findings

    def _scan_pipenv(self, file_path: str, content: str) -> List[Finding]:
        """Scan Pipfile for vulnerabilities"""
        # Similar to package.json but for Python Pipenv
        return []

    def _scan_php(self, file_path: str, content: str) -> List[Finding]:
        """Scan composer.json for vulnerabilities"""
        findings = []

        try:
            data = json.loads(content)
            dependencies = {}
            dependencies.update(data.get('require', {}))
            dependencies.update(data.get('require-dev', {}))

            for package, version in dependencies.items():
                if package == 'php':  # Skip PHP version requirement
                    continue

                # Check for wildcard versions
                if '*' in version:
                    findings.append(Finding(
                        scanner=self.get_name(),
                        severity=Severity.MEDIUM,
                        title=f"Unpinned Dependency: {package}",
                        description=f"Package {package} uses wildcard version",
                        file_path=file_path,
                        line_number=0,
                        code_snippet=f"{package}: {version}",
                        recommendation="Pin dependencies to specific versions",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021 - Vulnerable and Outdated Components"
                    ))

        except json.JSONDecodeError:
            pass

        return findings

    def _scan_ruby(self, file_path: str, content: str) -> List[Finding]:
        """Scan Gemfile for vulnerabilities"""
        # Placeholder for Ruby Gemfile scanning
        return []

    def _scan_maven(self, file_path: str, content: str) -> List[Finding]:
        """Scan pom.xml for vulnerabilities"""
        # Placeholder for Maven POM scanning
        return []

    def _scan_gradle(self, file_path: str, content: str) -> List[Finding]:
        """Scan build.gradle for vulnerabilities"""
        # Placeholder for Gradle scanning
        return []

    def _scan_go(self, file_path: str, content: str) -> List[Finding]:
        """Scan go.mod for vulnerabilities"""
        # Placeholder for Go modules scanning
        return []
