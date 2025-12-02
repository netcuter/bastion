"""
Evidence Capture System
Comprehensive evidence collection for security testing

Features:
- HTTP request/response capture
- Application logs collection
- Screenshots and screen recordings
- UI interaction traces
- Network traffic dumps
- Instrumentation logs
- Exploitation proof-of-concept evidence
"""
import json
import base64
import time
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from enum import Enum


class EvidenceType(Enum):
    """Types of evidence"""
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    VIDEO_RECORDING = "video_recording"
    APPLICATION_LOG = "application_log"
    SYSTEM_LOG = "system_log"
    NETWORK_PACKET = "network_packet"
    UI_INTERACTION = "ui_interaction"
    INSTRUMENTATION_LOG = "instrumentation_log"
    EXPLOIT_POC = "exploit_poc"
    CODE_SNIPPET = "code_snippet"
    CONFIGURATION = "configuration"


@dataclass
class HTTPEvidence:
    """HTTP request/response evidence"""
    evidence_id: str = ""
    timestamp: float = 0.0
    method: str = ""
    url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    request_body_base64: str = ""  # For binary data
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_body_base64: str = ""  # For binary data
    response_time_ms: float = 0.0
    tls_version: str = ""
    cipher_suite: str = ""
    server_certificate: str = ""
    vulnerability_id: str = ""  # Link to finding


@dataclass
class ScreenshotEvidence:
    """Screenshot evidence"""
    evidence_id: str = ""
    timestamp: float = 0.0
    screenshot_base64: str = ""
    description: str = ""
    device_info: str = ""
    screen_resolution: str = ""
    ui_state: str = ""
    vulnerability_id: str = ""


@dataclass
class LogEvidence:
    """Log file evidence"""
    evidence_id: str = ""
    timestamp: float = 0.0
    log_type: str = ""  # application, system, error, access
    log_level: str = ""  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_source: str = ""  # File path or source
    log_lines: List[str] = field(default_factory=list)
    relevant_patterns: List[str] = field(default_factory=list)
    vulnerability_id: str = ""


@dataclass
class UIInteractionTrace:
    """UI interaction trace evidence"""
    evidence_id: str = ""
    timestamp: float = 0.0
    interaction_type: str = ""  # click, input, swipe, etc.
    target_element: str = ""
    input_value: str = ""
    screenshot_before: str = ""
    screenshot_after: str = ""
    result: str = ""
    vulnerability_id: str = ""


@dataclass
class InstrumentationTrace:
    """Runtime instrumentation trace"""
    evidence_id: str = ""
    timestamp: float = 0.0
    hook_target: str = ""  # Method/function hooked
    call_stack: List[str] = field(default_factory=list)
    arguments: List[Any] = field(default_factory=list)
    return_value: Any = None
    execution_time_ms: float = 0.0
    vulnerability_id: str = ""


@dataclass
class ExploitPoCEvidence:
    """Proof of concept exploit evidence"""
    evidence_id: str = ""
    timestamp: float = 0.0
    vulnerability_type: str = ""
    exploit_payload: str = ""
    exploit_steps: List[str] = field(default_factory=list)
    pre_exploit_state: str = ""
    post_exploit_state: str = ""
    impact_demonstration: str = ""
    screenshots: List[str] = field(default_factory=list)
    network_traces: List[str] = field(default_factory=list)
    vulnerability_id: str = ""


class EvidenceCollector:
    """
    Main evidence collector

    Collects and organizes all types of evidence
    Links evidence to specific findings
    Ensures reproducibility
    """

    def __init__(self, output_dir: str = "./evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.http_evidence: List[HTTPEvidence] = []
        self.screenshot_evidence: List[ScreenshotEvidence] = []
        self.log_evidence: List[LogEvidence] = []
        self.ui_traces: List[UIInteractionTrace] = []
        self.instrumentation_traces: List[InstrumentationTrace] = []
        self.exploit_pocs: List[ExploitPoCEvidence] = []

        self.evidence_index: Dict[str, List[str]] = {}  # vuln_id -> evidence_ids

    def capture_http_request_response(self, method: str, url: str,
                                     request_headers: Dict[str, str],
                                     request_body: str,
                                     response_status: int,
                                     response_headers: Dict[str, str],
                                     response_body: str,
                                     response_time: float,
                                     vulnerability_id: str = "") -> str:
        """
        Capture HTTP request and response

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            request_headers: Request headers
            request_body: Request body
            response_status: Response status code
            response_headers: Response headers
            response_body: Response body
            response_time: Response time in milliseconds
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("http")

        evidence = HTTPEvidence(
            evidence_id=evidence_id,
            timestamp=time.time(),
            method=method,
            url=url,
            request_headers=request_headers,
            request_body=request_body[:10000],  # Limit size
            status_code=response_status,
            response_headers=response_headers,
            response_body=response_body[:10000],  # Limit size
            response_time_ms=response_time,
            vulnerability_id=vulnerability_id
        )

        # Handle binary data
        if not self._is_text(request_body):
            evidence.request_body_base64 = base64.b64encode(request_body.encode()).decode()
            evidence.request_body = "[Binary data]"

        if not self._is_text(response_body):
            evidence.response_body_base64 = base64.b64encode(response_body.encode()).decode()
            evidence.response_body = "[Binary data]"

        self.http_evidence.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "http")

        return evidence_id

    def capture_screenshot(self, screenshot_data: bytes,
                          description: str = "",
                          device_info: str = "",
                          vulnerability_id: str = "") -> str:
        """
        Capture screenshot

        Args:
            screenshot_data: Screenshot image bytes
            description: Description of what screenshot shows
            device_info: Device information
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("screenshot")

        screenshot_b64 = base64.b64encode(screenshot_data).decode()

        evidence = ScreenshotEvidence(
            evidence_id=evidence_id,
            timestamp=time.time(),
            screenshot_base64=screenshot_b64,
            description=description,
            device_info=device_info,
            vulnerability_id=vulnerability_id
        )

        self.screenshot_evidence.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "screenshot")

        # Save actual image file
        img_path = self.output_dir / f"{evidence_id}.png"
        img_path.write_bytes(screenshot_data)

        return evidence_id

    def capture_logs(self, log_lines: List[str],
                    log_type: str = "application",
                    log_level: str = "INFO",
                    log_source: str = "",
                    vulnerability_id: str = "") -> str:
        """
        Capture log entries

        Args:
            log_lines: Log lines to capture
            log_type: Type of log (application, system, error, access)
            log_level: Log level
            log_source: Source of logs (file path, etc.)
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("log")

        # Extract relevant patterns
        relevant_patterns = self._extract_relevant_patterns(log_lines)

        evidence = LogEvidence(
            evidence_id=evidence_id,
            timestamp=time.time(),
            log_type=log_type,
            log_level=log_level,
            log_source=log_source,
            log_lines=log_lines,
            relevant_patterns=relevant_patterns,
            vulnerability_id=vulnerability_id
        )

        self.log_evidence.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "log")

        return evidence_id

    def capture_ui_interaction(self, interaction_type: str,
                              target_element: str,
                              input_value: str = "",
                              screenshot_before: bytes = b"",
                              screenshot_after: bytes = b"",
                              result: str = "",
                              vulnerability_id: str = "") -> str:
        """
        Capture UI interaction trace

        Args:
            interaction_type: Type of interaction (click, input, swipe)
            target_element: Target UI element
            input_value: Input value (if applicable)
            screenshot_before: Screenshot before interaction
            screenshot_after: Screenshot after interaction
            result: Result of interaction
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("ui_trace")

        screenshot_before_b64 = base64.b64encode(screenshot_before).decode() if screenshot_before else ""
        screenshot_after_b64 = base64.b64encode(screenshot_after).decode() if screenshot_after else ""

        evidence = UIInteractionTrace(
            evidence_id=evidence_id,
            timestamp=time.time(),
            interaction_type=interaction_type,
            target_element=target_element,
            input_value=input_value,
            screenshot_before=screenshot_before_b64,
            screenshot_after=screenshot_after_b64,
            result=result,
            vulnerability_id=vulnerability_id
        )

        self.ui_traces.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "ui_trace")

        return evidence_id

    def capture_instrumentation_trace(self, hook_target: str,
                                     call_stack: List[str],
                                     arguments: List[Any],
                                     return_value: Any,
                                     execution_time: float,
                                     vulnerability_id: str = "") -> str:
        """
        Capture runtime instrumentation trace

        Args:
            hook_target: Hooked method/function
            call_stack: Call stack
            arguments: Function arguments
            return_value: Return value
            execution_time: Execution time in milliseconds
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("instrumentation")

        evidence = InstrumentationTrace(
            evidence_id=evidence_id,
            timestamp=time.time(),
            hook_target=hook_target,
            call_stack=call_stack,
            arguments=arguments,
            return_value=return_value,
            execution_time_ms=execution_time,
            vulnerability_id=vulnerability_id
        )

        self.instrumentation_traces.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "instrumentation")

        return evidence_id

    def capture_exploit_poc(self, vulnerability_type: str,
                          exploit_payload: str,
                          exploit_steps: List[str],
                          pre_exploit_state: str,
                          post_exploit_state: str,
                          impact_demonstration: str,
                          screenshots: List[bytes] = None,
                          vulnerability_id: str = "") -> str:
        """
        Capture proof of concept exploit

        Args:
            vulnerability_type: Type of vulnerability
            exploit_payload: Exploit payload used
            exploit_steps: Steps to reproduce exploit
            pre_exploit_state: State before exploit
            post_exploit_state: State after exploit
            impact_demonstration: Demonstration of impact
            screenshots: Screenshots of exploitation
            vulnerability_id: Associated vulnerability ID

        Returns:
            Evidence ID
        """
        evidence_id = self._generate_evidence_id("exploit_poc")

        screenshot_ids = []
        if screenshots:
            for i, screenshot_data in enumerate(screenshots):
                screenshot_id = self.capture_screenshot(
                    screenshot_data,
                    description=f"PoC Step {i+1}",
                    vulnerability_id=vulnerability_id
                )
                screenshot_ids.append(screenshot_id)

        evidence = ExploitPoCEvidence(
            evidence_id=evidence_id,
            timestamp=time.time(),
            vulnerability_type=vulnerability_type,
            exploit_payload=exploit_payload,
            exploit_steps=exploit_steps,
            pre_exploit_state=pre_exploit_state,
            post_exploit_state=post_exploit_state,
            impact_demonstration=impact_demonstration,
            screenshots=screenshot_ids,
            vulnerability_id=vulnerability_id
        )

        self.exploit_pocs.append(evidence)
        self._index_evidence(vulnerability_id, evidence_id)
        self._save_evidence(evidence, "exploit_poc")

        return evidence_id

    def get_evidence_for_vulnerability(self, vulnerability_id: str) -> Dict[str, List[Any]]:
        """
        Get all evidence associated with a vulnerability

        Args:
            vulnerability_id: Vulnerability ID

        Returns:
            Dict of evidence type -> evidence list
        """
        evidence_ids = self.evidence_index.get(vulnerability_id, [])

        result = {
            'http': [],
            'screenshots': [],
            'logs': [],
            'ui_traces': [],
            'instrumentation': [],
            'exploit_pocs': []
        }

        for evidence_id in evidence_ids:
            if evidence_id.startswith('http_'):
                evidence = next((e for e in self.http_evidence if e.evidence_id == evidence_id), None)
                if evidence:
                    result['http'].append(asdict(evidence))
            elif evidence_id.startswith('screenshot_'):
                evidence = next((e for e in self.screenshot_evidence if e.evidence_id == evidence_id), None)
                if evidence:
                    result['screenshots'].append(asdict(evidence))
            elif evidence_id.startswith('log_'):
                evidence = next((e for e in self.log_evidence if e.evidence_id == evidence_id), None)
                if evidence:
                    result['logs'].append(asdict(evidence))
            elif evidence_id.startswith('ui_trace_'):
                evidence = next((e for e in self.ui_traces if e.evidence_id == evidence_id), None)
                if evidence:
                    result['ui_traces'].append(asdict(evidence))
            elif evidence_id.startswith('instrumentation_'):
                evidence = next((e for e in self.instrumentation_traces if e.evidence_id == evidence_id), None)
                if evidence:
                    result['instrumentation'].append(asdict(evidence))
            elif evidence_id.startswith('exploit_poc_'):
                evidence = next((e for e in self.exploit_pocs if e.evidence_id == evidence_id), None)
                if evidence:
                    result['exploit_pocs'].append(asdict(evidence))

        return result

    def generate_evidence_report(self, vulnerability_id: str = "") -> Dict[str, Any]:
        """
        Generate comprehensive evidence report

        Args:
            vulnerability_id: Optional specific vulnerability ID

        Returns:
            Evidence report
        """
        if vulnerability_id:
            evidence = self.get_evidence_for_vulnerability(vulnerability_id)
            return {
                'vulnerability_id': vulnerability_id,
                'evidence': evidence,
                'total_evidence_items': sum(len(v) for v in evidence.values())
            }
        else:
            return {
                'summary': {
                    'total_http_captures': len(self.http_evidence),
                    'total_screenshots': len(self.screenshot_evidence),
                    'total_log_captures': len(self.log_evidence),
                    'total_ui_traces': len(self.ui_traces),
                    'total_instrumentation_traces': len(self.instrumentation_traces),
                    'total_exploit_pocs': len(self.exploit_pocs)
                },
                'vulnerabilities_with_evidence': list(self.evidence_index.keys()),
                'evidence_index': self.evidence_index
            }

    def export_evidence_bundle(self, vulnerability_id: str, output_path: str):
        """
        Export complete evidence bundle for a vulnerability

        Creates a ZIP file with all evidence
        """
        import zipfile

        evidence = self.get_evidence_for_vulnerability(vulnerability_id)

        with zipfile.ZipFile(output_path, 'w') as zipf:
            # Add JSON manifest
            manifest = {
                'vulnerability_id': vulnerability_id,
                'export_timestamp': datetime.now().isoformat(),
                'evidence_summary': {k: len(v) for k, v in evidence.items()}
            }
            zipf.writestr('manifest.json', json.dumps(manifest, indent=2))

            # Add evidence files
            for evidence_type, evidence_list in evidence.items():
                for i, evidence_item in enumerate(evidence_list):
                    filename = f"{evidence_type}/{evidence_type}_{i+1}.json"
                    zipf.writestr(filename, json.dumps(evidence_item, indent=2))

            # Add screenshot images
            for screenshot in self.screenshot_evidence:
                if screenshot.vulnerability_id == vulnerability_id:
                    img_path = self.output_dir / f"{screenshot.evidence_id}.png"
                    if img_path.exists():
                        zipf.write(img_path, f"screenshots/{screenshot.evidence_id}.png")

    # Helper methods

    def _generate_evidence_id(self, evidence_type: str) -> str:
        """Generate unique evidence ID"""
        timestamp = str(time.time())
        unique_str = f"{evidence_type}_{timestamp}"
        hash_obj = hashlib.sha256(unique_str.encode())
        return f"{evidence_type}_{hash_obj.hexdigest()[:16]}"

    def _is_text(self, data: str) -> bool:
        """Check if data is text (not binary)"""
        try:
            data.encode('utf-8')
            return True
        except:
            return False

    def _index_evidence(self, vulnerability_id: str, evidence_id: str):
        """Index evidence by vulnerability ID"""
        if vulnerability_id:
            if vulnerability_id not in self.evidence_index:
                self.evidence_index[vulnerability_id] = []
            self.evidence_index[vulnerability_id].append(evidence_id)

    def _save_evidence(self, evidence: Any, evidence_type: str):
        """Save evidence to disk"""
        evidence_dict = asdict(evidence)
        filename = f"{evidence.evidence_id}.json"
        filepath = self.output_dir / evidence_type / filename

        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(evidence_dict, indent=2))

    def _extract_relevant_patterns(self, log_lines: List[str]) -> List[str]:
        """Extract relevant patterns from logs"""
        patterns = []

        error_patterns = [
            r'ERROR',
            r'CRITICAL',
            r'Exception',
            r'Traceback',
            r'SQLSTATE',
            r'syntax error',
            r'failed',
            r'denied',
            r'unauthorized',
            r'forbidden'
        ]

        for line in log_lines:
            for pattern in error_patterns:
                if pattern.lower() in line.lower():
                    patterns.append(pattern)
                    break

        return list(set(patterns))


class EvidenceReproducibility:
    """
    Ensures evidence can be used to reproduce findings

    Generates step-by-step reproduction guides
    """

    def __init__(self, evidence_collector: EvidenceCollector):
        self.evidence_collector = evidence_collector

    def generate_reproduction_guide(self, vulnerability_id: str) -> str:
        """
        Generate step-by-step reproduction guide

        Args:
            vulnerability_id: Vulnerability ID

        Returns:
            Markdown formatted reproduction guide
        """
        evidence = self.evidence_collector.get_evidence_for_vulnerability(vulnerability_id)

        guide = f"# Vulnerability Reproduction Guide\n\n"
        guide += f"**Vulnerability ID:** {vulnerability_id}\n\n"
        guide += f"## Evidence Summary\n\n"

        for evidence_type, evidence_list in evidence.items():
            if evidence_list:
                guide += f"- {evidence_type}: {len(evidence_list)} item(s)\n"

        guide += "\n## Reproduction Steps\n\n"

        # HTTP evidence
        if evidence['http']:
            guide += "### HTTP Requests\n\n"
            for i, http_evidence in enumerate(evidence['http'], 1):
                guide += f"#### Step {i}: {http_evidence['method']} {http_evidence['url']}\n\n"
                guide += "```bash\n"
                guide += f"curl -X {http_evidence['method']} \\\n"
                guide += f"  '{http_evidence['url']}' \\\n"
                for header, value in http_evidence['request_headers'].items():
                    guide += f"  -H '{header}: {value}' \\\n"
                if http_evidence['request_body']:
                    guide += f"  -d '{http_evidence['request_body']}'\n"
                guide += "```\n\n"
                guide += f"**Expected Response Code:** {http_evidence['status_code']}\n\n"

        # Exploit PoC
        if evidence['exploit_pocs']:
            guide += "### Exploitation Steps\n\n"
            for poc in evidence['exploit_pocs']:
                guide += f"**Vulnerability Type:** {poc['vulnerability_type']}\n\n"
                guide += "**Steps:**\n\n"
                for i, step in enumerate(poc['exploit_steps'], 1):
                    guide += f"{i}. {step}\n"
                guide += f"\n**Payload:**\n```\n{poc['exploit_payload']}\n```\n\n"
                guide += f"**Impact:** {poc['impact_demonstration']}\n\n"

        # UI Interactions
        if evidence['ui_traces']:
            guide += "### UI Interaction Steps\n\n"
            for i, trace in enumerate(evidence['ui_traces'], 1):
                guide += f"{i}. {trace['interaction_type'].upper()}: {trace['target_element']}\n"
                if trace['input_value']:
                    guide += f"   - Input: `{trace['input_value']}`\n"
                guide += f"   - Result: {trace['result']}\n"

        return guide
