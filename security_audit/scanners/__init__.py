"""Security scanners"""
from .web_vulnerabilities import WebVulnerabilityScanner
from .secrets_detector import SecretsDetector
from .dependency_scanner import DependencyScanner
from .asvs_scanner import ASVSScanner
from .multilanguage_scanner import MultiLanguageScanner
from .advanced_patterns_scanner import AdvancedPatternsScanner
from .dataflow_scanner import DataFlowScanner
from .mcp_file_scanner import MCPFileScanner

# MCP Security Scanner (full async scanner, optional deps)
try:
    from .mcp_security_scanner import (
        HexStrikeMCPSecurityScanner,
        MCPToolFinding,
        MCPScanResult,
        ToolPinningEngine
    )
    MCP_SCANNER_AVAILABLE = True
except ImportError:
    MCP_SCANNER_AVAILABLE = False

__all__ = [
    'WebVulnerabilityScanner',
    'SecretsDetector',
    'DependencyScanner',
    'ASVSScanner',
    'MultiLanguageScanner',
    'AdvancedPatternsScanner',
    'DataFlowScanner',
    'MCPFileScanner',
    # Full MCP scanner (optional)
    'HexStrikeMCPSecurityScanner',
    'MCPToolFinding',
    'MCPScanResult',
    'ToolPinningEngine',
    'MCP_SCANNER_AVAILABLE',
]
