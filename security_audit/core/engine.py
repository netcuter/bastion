"""
Main security audit engine
"""
import os
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import fnmatch

from .config import Config
from .scanner import BaseScanner, Finding, Severity


class AuditEngine:
    """Main security audit engine"""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.scanners: List[BaseScanner] = []
        self.all_findings: List[Finding] = []
        self.stats = {
            "total_files_scanned": 0,
            "total_lines_scanned": 0,
            "scan_duration": 0,
            "findings_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        }

    def register_scanner(self, scanner: BaseScanner):
        """Register a security scanner"""
        self.scanners.append(scanner)

    def scan_directory(self, directory_path: str) -> List[Finding]:
        """
        Scan entire directory for security issues

        Args:
            directory_path: Path to directory to scan

        Returns:
            List of all findings
        """
        start_time = datetime.now()
        self.all_findings = []
        directory = Path(directory_path)

        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")

        print(f"\n[*] Starting security audit of: {directory_path}")
        print(f"[*] Registered scanners: {len(self.scanners)}")

        # Walk through directory
        for file_path in self._get_files_to_scan(directory):
            self._scan_file(file_path)

        # Calculate statistics
        end_time = datetime.now()
        self.stats["scan_duration"] = (end_time - start_time).total_seconds()
        self._calculate_stats()

        print(f"\n[+] Scan completed in {self.stats['scan_duration']:.2f} seconds")
        print(f"[+] Files scanned: {self.stats['total_files_scanned']}")
        print(f"[+] Total findings: {len(self.all_findings)}")

        return self.all_findings

    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single file

        Args:
            file_path: Path to file to scan

        Returns:
            List of findings for this file
        """
        findings = self._scan_file(Path(file_path))
        self._calculate_stats()
        return findings

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Internal method to scan a file"""
        try:
            # Check file size
            if file_path.stat().st_size > self.config.get_max_file_size():
                return []

            # Read file content
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"[!] Error reading file {file_path}: {e}")
                return []

            # Determine file type
            file_type = file_path.suffix.lstrip('.')

            # Run all scanners
            file_findings = []
            for scanner in self.scanners:
                if scanner.is_enabled():
                    try:
                        findings = scanner.scan(str(file_path), content, file_type)
                        file_findings.extend(findings)
                    except Exception as e:
                        print(f"[!] Error in scanner {scanner.get_name()}: {e}")

            # Update stats
            self.stats["total_files_scanned"] += 1
            self.stats["total_lines_scanned"] += len(content.splitlines())
            self.all_findings.extend(file_findings)

            if file_findings:
                print(f"[!] Found {len(file_findings)} issue(s) in {file_path}")

            return file_findings

        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
            return []

    def _get_files_to_scan(self, directory: Path) -> List[Path]:
        """Get list of files to scan based on configuration"""
        files_to_scan = []
        excluded_dirs = self.config.get_excluded_dirs()
        excluded_files = self.config.get_excluded_files()
        included_extensions = self.config.get_included_extensions()

        for root, dirs, files in os.walk(directory):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in excluded_dirs]

            for file in files:
                file_path = Path(root) / file

                # Check if file should be excluded
                if any(fnmatch.fnmatch(file, pattern) for pattern in excluded_files):
                    continue

                # Check if file extension is included
                if file_path.suffix in included_extensions:
                    files_to_scan.append(file_path)

        return files_to_scan

    def _calculate_stats(self):
        """Calculate statistics from findings"""
        for finding in self.all_findings:
            self.stats["findings_by_severity"][finding.severity.value] += 1

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.all_findings if f.severity == severity]

    def get_findings_by_file(self, file_path: str) -> List[Finding]:
        """Get findings for specific file"""
        return [f for f in self.all_findings if f.file_path == file_path]

    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings"""
        return self.get_findings_by_severity(Severity.CRITICAL)

    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        return self.stats

    def generate_report(self) -> Dict[str, Any]:
        """Generate audit report"""
        return {
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.all_findings),
            "statistics": self.stats,
            "findings": [f.to_dict() for f in self.all_findings]
        }
