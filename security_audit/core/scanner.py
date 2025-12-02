"""
Base scanner interface for security audit system
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding"""
    scanner: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str
    cwe_id: str = None
    owasp_category: str = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category
        }


class BaseScanner(ABC):
    """Base class for all security scanners"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.findings: List[Finding] = []

    @abstractmethod
    def get_name(self) -> str:
        """Return scanner name"""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return scanner description"""
        pass

    @abstractmethod
    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """
        Scan file content for security issues

        Args:
            file_path: Path to the file being scanned
            content: File content
            file_type: File extension/type (py, js, php, etc.)

        Returns:
            List of findings
        """
        pass

    def add_finding(self, finding: Finding):
        """Add a finding to the scanner results"""
        self.findings.append(finding)

    def clear_findings(self):
        """Clear all findings"""
        self.findings = []

    def get_findings(self) -> List[Finding]:
        """Get all findings"""
        return self.findings

    def is_enabled(self) -> bool:
        """Check if scanner is enabled in config"""
        return self.config.get("enabled", True)

    def get_severity_threshold(self) -> Severity:
        """Get minimum severity threshold from config"""
        threshold = self.config.get("severity_threshold", "INFO")
        return Severity[threshold]
