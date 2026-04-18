"""
MCP File Scanner — BaseScanner adapter for the MCP Security Scanner.

Detects MCP config files in the scanned project and triggers URL-based scanning.
Supported config file formats:
  - mcp.json
  - claude_desktop_config.json  (Claude Desktop)
  - .mcp.json
  - mcp_config.json
"""
import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List

from ..core.scanner import BaseScanner, Finding, Severity


_MCP_CONFIG_NAMES = {
    "mcp.json",
    "claude_desktop_config.json",
    ".mcp.json",
    "mcp_config.json",
}

_SERVER_URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>]+'
)


class MCPFileScanner(BaseScanner):
    """
    Scans source-tree MCP configuration files for security issues.

    For each discovered MCP server URL the scanner runs the local YARA-like
    pattern matching from HexStrikeMCPSecurityScanner.  The Cisco AI Defense
    API path is NOT triggered here (requires explicit --mcp-server flag via CLI).
    """

    def get_name(self) -> str:
        return "MCP Security Scanner"

    def get_description(self) -> str:
        return (
            "Scans MCP configuration files for Tool Poisoning, Rug Pulls, "
            "and Prompt Injection patterns."
        )

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        name = Path(file_path).name
        if name not in _MCP_CONFIG_NAMES:
            return []

        findings: List[Finding] = []

        # Parse JSON config
        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return []

        # Extract tool descriptions and server URLs
        servers = self._extract_servers(config)

        for server_name, server_info in servers.items():
            findings.extend(
                self._scan_server_entry(file_path, server_name, server_info)
            )

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_servers(self, config: dict) -> Dict[str, Any]:
        """Support both claude_desktop_config format and plain mcp.json."""
        if "mcpServers" in config:
            return config["mcpServers"]
        if "servers" in config:
            return config["servers"]
        return {}

    def _scan_server_entry(
        self, file_path: str, server_name: str, server_info: dict
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Check for inline tool descriptions (some configs embed them)
        description = server_info.get("description", "")
        if description:
            findings.extend(
                self._check_description(file_path, server_name, description)
            )

        # Check command/args for suspicious patterns
        command = server_info.get("command", "")
        args = server_info.get("args", [])
        full_command = " ".join([command] + args)
        if full_command.strip():
            findings.extend(
                self._check_description(file_path, server_name, full_command)
            )

        return findings

    def _check_description(
        self, file_path: str, tool_name: str, text: str
    ) -> List[Finding]:
        """Reuse the local YARA patterns from HexStrikeMCPSecurityScanner."""
        try:
            from .mcp_security_scanner import HexStrikeMCPSecurityScanner
        except ImportError:
            return []

        scanner = HexStrikeMCPSecurityScanner()
        mcp_findings = scanner.scan_tool_description_local(tool_name, text)

        results: List[Finding] = []
        for mf in mcp_findings:
            results.append(
                Finding(
                    scanner=self.get_name(),
                    severity=self._map_severity(mf.severity),
                    title=f"MCP {mf.finding_type}: {tool_name}",
                    description=mf.description,
                    file_path=file_path,
                    line_number=0,
                    code_snippet=mf.evidence[:200],
                    recommendation=mf.remediation or "Review and sanitize the tool description.",
                    cwe_id=mf.cwe or "CWE-74",
                    owasp_category="A03:2021 - Injection",
                )
            )
        return results

    @staticmethod
    def _map_severity(severity_str: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        return mapping.get(severity_str.upper(), Severity.MEDIUM)
