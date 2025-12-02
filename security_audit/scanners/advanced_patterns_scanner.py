"""
Advanced Vulnerability Patterns Scanner
Detects: ReDoS, TOCTOU, Prototype Pollution, Second-Order Injection, and more
"""
import re
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity


class AdvancedPatternsScanner(BaseScanner):
    """
    Scanner for advanced vulnerability patterns that require
    sophisticated detection logic
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Advanced Patterns Scanner"

    def get_description(self) -> str:
        return "Detects ReDoS, TOCTOU, Prototype Pollution, and other advanced vulnerabilities"

    def _init_patterns(self):
        """Initialize advanced vulnerability patterns"""

        # ReDoS (Regular Expression Denial of Service) patterns
        self.redos_patterns = [
            # Nested quantifiers - catastrophic backtracking
            (r'\([^)]*\*[^)]*\)\+', 'Nested quantifier (X*)+ - catastrophic backtracking'),
            (r'\([^)]*\+[^)]*\)\*', 'Nested quantifier (X+)* - catastrophic backtracking'),
            (r'\([^)]*\+[^)]*\)\+', 'Nested quantifier (X+)+ - severe backtracking'),
            (r'\([^)]*\*[^)]*\)\*', 'Nested quantifier (X*)* - severe backtracking'),

            # Alternation with overlapping patterns
            (r'\(.*?\|.*?\)\*', 'Alternation with quantifier (a|ab)* - potential ReDoS'),
            (r'\(.*?\|.*?\)\+', 'Alternation with quantifier (a|ab)+ - potential ReDoS'),

            # Repetition followed by same character
            (r'\.?\*\.?\*', 'Multiple .* in sequence - potential performance issue'),
            (r'\.?\+\.?\+', 'Multiple .+ in sequence - potential performance issue'),

            # Complex patterns with many quantifiers
            (r'(?:\w\*){3,}', 'Multiple quantifiers in sequence - potential ReDoS'),
        ]

        # TOCTOU (Time-of-Check-Time-of-Use) patterns
        self.toctou_patterns = {
            'python': [
                (r'os\.path\.exists\s*\([^)]+\).*?open\s*\(', 'TOCTOU: check exists before open'),
                (r'os\.path\.isfile\s*\([^)]+\).*?open\s*\(', 'TOCTOU: check isfile before open'),
                (r'os\.access\s*\([^)]+\).*?open\s*\(', 'TOCTOU: access check before open'),
                (r'Path\([^)]+\)\.exists\(\).*?open\s*\(', 'TOCTOU: Path.exists before open'),
            ],
            'php': [
                (r'file_exists\s*\([^)]+\).*?fopen\s*\(', 'TOCTOU: file_exists before fopen'),
                (r'is_file\s*\([^)]+\).*?file_get_contents', 'TOCTOU: is_file before read'),
            ],
            'java': [
                (r'\.exists\(\).*?new\s+FileInputStream', 'TOCTOU: exists check before FileInputStream'),
                (r'Files\.exists\([^)]+\).*?Files\.read', 'TOCTOU: Files.exists before read'),
            ],
        }

        # Prototype Pollution (JavaScript)
        self.prototype_pollution_patterns = [
            (r'Object\.assign\s*\([^)]*req\.(body|query|params)', 'Prototype pollution via Object.assign'),
            (r'\.\.\.req\.(body|query|params)', 'Prototype pollution via spread operator'),
            (r'__proto__\s*=', 'Direct __proto__ assignment - prototype pollution'),
            (r'constructor\.prototype', 'Constructor.prototype manipulation'),
            (r'Object\.create\s*\(.*?req\.', 'Object.create with user input'),
            (r'_.merge\s*\([^)]*req\.', 'Lodash merge with user input - prototype pollution'),
            (r'jQuery\.extend\s*\(true', 'jQuery deep extend - prototype pollution risk'),
        ]

        # Second-Order Injection patterns
        self.second_order_patterns = {
            'storage_then_output': [
                (r'\.save\(\).*?HttpResponse\(', 'Potential second-order XSS: save then output'),
                (r'\.create\(\).*?render', 'Potential second-order injection: create then render'),
            ],
            'storage_then_query': [
                (r'\.save\(\).*?\.raw\(', 'Potential second-order SQL injection'),
                (r'\.insert\(\).*?\.execute\(', 'Second-order SQL injection risk'),
            ],
        }

        # Server-Side Request Forgery (SSRF) - advanced patterns
        self.ssrf_patterns = [
            (r'requests\.get\s*\([^)]*req\.(GET|POST|query|body)', 'SSRF via requests.get with user input'),
            (r'urllib\.request\.urlopen\s*\([^)]*req\.', 'SSRF via urllib with user input'),
            (r'fetch\s*\([^)]*req\.(query|params|body)', 'SSRF via fetch with user input'),
            (r'axios\.get\s*\([^)]*req\.', 'SSRF via axios with user input'),
            (r'curl_exec\s*\([^)]*\$_(GET|POST)', 'SSRF via curl in PHP'),
        ]

        # XML External Entity (XXE) - advanced
        self.xxe_advanced_patterns = [
            (r'<!DOCTYPE[^>]*\[', 'DOCTYPE with internal subset - XXE risk'),
            (r'<!ENTITY[^>]*SYSTEM', 'ENTITY with SYSTEM - XXE vulnerability'),
            (r'<!ENTITY[^>]*PUBLIC', 'ENTITY with PUBLIC - XXE vulnerability'),
            (r'xml\.etree.*?parse\([^)]*req\.', 'XML parsing user input without defusedxml'),
        ]

        # Path Traversal - advanced patterns
        self.path_traversal_advanced = [
            (r'os\.path\.join\s*\([^)]*req\.(GET|POST|query|body)', 'Path traversal via os.path.join'),
            (r'Path\([^)]*req\..*?\)', 'Path traversal via pathlib.Path'),
            (r'\.\./.*?req\.', 'Potential path traversal with ../ and user input'),
            (r'\.\.\\.*?req\.', 'Potential path traversal with ..\\ and user input'),
        ]

        # Insecure Randomness in cryptographic context
        self.insecure_random_crypto = [
            (r'random\.random\(\).*?(key|token|secret|password)', 'Weak random for cryptographic use'),
            (r'Math\.random\(\).*?(key|token|secret)', 'Math.random() in security context'),
            (r'rand\(\).*?(password|token)', 'PHP rand() in security context - use random_bytes()'),
            (r'new Random\(\).*?(key|token)', 'Java Random in crypto context - use SecureRandom'),
        ]

        # Race Conditions
        self.race_condition_patterns = [
            (r'if\s+not\s+os\.path\.exists.*?os\.mkdir', 'Race condition: check-then-create directory'),
            (r'if\s+.*?exists.*?create', 'Race condition: exists check before create'),
        ]

        # Memory Leaks (JavaScript/Node.js)
        self.memory_leak_patterns = [
            (r'setInterval\([^)]*\)(?!.*?clearInterval)', 'setInterval without clearInterval - memory leak'),
            (r'addEventListener\([^)]*\)(?!.*?removeEventListener)', 'addEventListener without cleanup'),
            (r'new.*?Observable\([^)]*\)(?!.*?unsubscribe)', 'Observable without unsubscribe'),
        ]

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan for advanced vulnerability patterns"""
        findings = []
        lines = content.splitlines()

        # ReDoS detection
        findings.extend(self._check_redos(file_path, lines))

        # TOCTOU detection
        findings.extend(self._check_toctou(file_path, content, file_type, lines))

        # Prototype Pollution (JavaScript only)
        if file_type in ['js', 'jsx', 'ts', 'tsx']:
            findings.extend(self._check_prototype_pollution(file_path, lines))

        # Second-Order Injection
        findings.extend(self._check_second_order(file_path, content, lines))

        # Advanced SSRF
        findings.extend(self._check_ssrf(file_path, lines))

        # Advanced XXE
        if file_type in ['xml', 'py', 'java', 'php']:
            findings.extend(self._check_xxe(file_path, lines))

        # Advanced Path Traversal
        findings.extend(self._check_path_traversal(file_path, lines))

        # Insecure Randomness
        findings.extend(self._check_insecure_random(file_path, lines))

        # Race Conditions
        findings.extend(self._check_race_conditions(file_path, lines))

        # Memory Leaks (JavaScript)
        if file_type in ['js', 'jsx', 'ts', 'tsx']:
            findings.extend(self._check_memory_leaks(file_path, lines))

        return findings

    def _check_redos(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for ReDoS vulnerabilities"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            # Look for regex patterns
            regex_patterns = re.finditer(r'(?:re\.compile|RegExp|preg_match|Pattern\.compile)\s*\([\'"]([^\'"]+)[\'"]', line)

            for match in regex_patterns:
                regex_pattern = match.group(1)

                # Check for dangerous patterns
                for dangerous_pattern, description in self.redos_patterns:
                    if re.search(dangerous_pattern, regex_pattern):
                        finding = Finding(
                            scanner=self.get_name(),
                            severity=Severity.HIGH,
                            title="Regular Expression Denial of Service (ReDoS)",
                            description=f"{description}: {regex_pattern}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_code_snippet(lines, line_num),
                            recommendation="Simplify regex pattern. Avoid nested quantifiers. Test with long inputs. Consider using re2 library.",
                            cwe_id="CWE-1333",
                            owasp_category="Resource Exhaustion"
                        )
                        findings.append(finding)

        return findings

    def _check_toctou(self, file_path: str, content: str, file_type: str, lines: List[str]) -> List[Finding]:
        """Check for Time-of-Check-Time-of-Use vulnerabilities"""
        findings = []

        patterns = self.toctou_patterns.get(file_type, [])

        for pattern, description in patterns:
            # Use multiline search to catch check-then-use patterns
            matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)

            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1

                finding = Finding(
                    scanner=self.get_name(),
                    severity=Severity.MEDIUM,
                    title="Time-of-Check-Time-of-Use (TOCTOU) Race Condition",
                    description=description,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(lines, line_num),
                    recommendation="Open file directly with error handling instead of checking existence first. Use atomic operations.",
                    cwe_id="CWE-362",
                    owasp_category="Race Conditions"
                )
                findings.append(finding)

        return findings

    def _check_prototype_pollution(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for Prototype Pollution vulnerabilities"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.prototype_pollution_patterns:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.HIGH,
                        title="Prototype Pollution Vulnerability",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Validate object keys. Use Object.create(null) for dictionaries. Freeze prototypes. Use Map instead of objects for user data.",
                        cwe_id="CWE-1321",
                        owasp_category="Prototype Pollution"
                    )
                    findings.append(finding)

        return findings

    def _check_second_order(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        """Check for Second-Order Injection vulnerabilities"""
        findings = []

        for category, patterns in self.second_order_patterns.items():
            for pattern, description in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.MEDIUM,
                        title="Second-Order Injection Risk",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Sanitize data before storage AND before output. Validate on retrieval from database.",
                        cwe_id="CWE-74",
                        owasp_category="Injection"
                    )
                    findings.append(finding)

        return findings

    def _check_ssrf(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for SSRF vulnerabilities"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.ssrf_patterns:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.CRITICAL,
                        title="Server-Side Request Forgery (SSRF)",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Validate and whitelist URLs. Parse and verify hostname. Block internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x, etc.)",
                        cwe_id="CWE-918",
                        owasp_category="SSRF"
                    )
                    findings.append(finding)

        return findings

    def _check_xxe(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for XXE vulnerabilities"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.xxe_advanced_patterns:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.CRITICAL,
                        title="XML External Entity (XXE) Injection",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Disable DTD processing. Use defusedxml library. Set XMLReader features to disable external entities.",
                        cwe_id="CWE-611",
                        owasp_category="XXE"
                    )
                    findings.append(finding)

        return findings

    def _check_path_traversal(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for Path Traversal vulnerabilities"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.path_traversal_advanced:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.HIGH,
                        title="Path Traversal Vulnerability",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Use os.path.basename() to extract filename. Validate against whitelist. Use secure_filename() or Path.resolve().",
                        cwe_id="CWE-22",
                        owasp_category="Path Traversal"
                    )
                    findings.append(finding)

        return findings

    def _check_insecure_random(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for insecure randomness in cryptographic contexts"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.insecure_random_crypto:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.HIGH,
                        title="Insecure Randomness in Cryptographic Context",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Use cryptographically secure random: secrets module (Python), crypto.randomBytes (Node.js), SecureRandom (Java)",
                        cwe_id="CWE-338",
                        owasp_category="Cryptography"
                    )
                    findings.append(finding)

        return findings

    def _check_race_conditions(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for race condition patterns"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.race_condition_patterns:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.MEDIUM,
                        title="Race Condition Vulnerability",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Use atomic operations. Handle exceptions instead of pre-checking. Use file locks.",
                        cwe_id="CWE-362",
                        owasp_category="Race Conditions"
                    )
                    findings.append(finding)

        return findings

    def _check_memory_leaks(self, file_path: str, lines: List[str]) -> List[Finding]:
        """Check for memory leak patterns"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.memory_leak_patterns:
                if re.search(pattern, line):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=Severity.LOW,
                        title="Potential Memory Leak",
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation="Clean up resources properly. Use clearInterval, removeEventListener, or unsubscribe in cleanup functions.",
                        cwe_id="CWE-401",
                        owasp_category="Resource Management"
                    )
                    findings.append(finding)

        return findings

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
