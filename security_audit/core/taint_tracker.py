"""
Taint Tracking Engine for Data Flow Analysis
Tracks tainted data from sources through sanitizers to sinks
"""
import ast
import re
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaintType(Enum):
    """Types of taint sources"""
    USER_INPUT = "user_input"
    DATABASE = "database"
    FILE = "file"
    NETWORK = "network"
    UNKNOWN = "unknown"


@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    name: str
    taint_type: TaintType
    patterns: List[str]
    description: str


@dataclass
class Sanitizer:
    """Represents a data sanitization function"""
    name: str
    effective_against: List[str]  # List of vulnerability types it protects against
    patterns: List[str]
    description: str


@dataclass
class Sink:
    """Represents a dangerous operation (sink)"""
    name: str
    vulnerability_type: str
    patterns: List[str]
    severity: str
    cwe_id: str
    description: str


@dataclass
class TaintFlow:
    """Represents a complete taint flow from source to sink"""
    source: str
    source_line: int
    sink: str
    sink_line: int
    variable: str
    sanitized: bool
    sanitizer: Optional[str] = None
    vulnerability_type: str = "Unknown"
    path: List[Tuple[int, str]] = field(default_factory=list)


class TaintTracker:
    """
    Main taint tracking engine
    Performs data flow analysis to track tainted data
    """

    def __init__(self):
        self._init_sources()
        self._init_sanitizers()
        self._init_sinks()

    def _init_sources(self):
        """Initialize taint sources for different languages/frameworks"""

        # Python sources
        self.python_sources = [
            TaintSource(
                "Flask Request",
                TaintType.USER_INPUT,
                [
                    r'request\.args(?:\[|\.get)',
                    r'request\.form(?:\[|\.get)',
                    r'request\.values(?:\[|\.get)',
                    r'request\.json(?:\[|\.get)?',
                    r'request\.data',
                    r'request\.get_json\(\)',
                ],
                "Flask HTTP request parameters"
            ),
            TaintSource(
                "Django Request",
                TaintType.USER_INPUT,
                [
                    r'request\.GET(?:\[|\.get)',
                    r'request\.POST(?:\[|\.get)',
                    r'request\.body',
                    r'request\.REQUEST',
                ],
                "Django HTTP request parameters"
            ),
            TaintSource(
                "FastAPI Request",
                TaintType.USER_INPUT,
                [r'request\.query_params', r'request\.body\(\)'],
                "FastAPI request parameters"
            ),
            TaintSource(
                "Python Input",
                TaintType.USER_INPUT,
                [r'\binput\s*\(', r'sys\.stdin\.read'],
                "Direct user input"
            ),
        ]

        # JavaScript/Node.js sources
        self.javascript_sources = [
            TaintSource(
                "Express Request",
                TaintType.USER_INPUT,
                [
                    r'req\.query',
                    r'req\.body',
                    r'req\.params',
                    r'req\.headers',
                    r'req\.cookies',
                ],
                "Express.js request parameters"
            ),
            TaintSource(
                "DOM Input",
                TaintType.USER_INPUT,
                [
                    r'document\.location',
                    r'window\.location',
                    r'document\.URL',
                    r'document\.referrer',
                ],
                "Browser DOM user input"
            ),
        ]

        # PHP sources
        self.php_sources = [
            TaintSource(
                "PHP Superglobals",
                TaintType.USER_INPUT,
                [
                    r'\$_GET',
                    r'\$_POST',
                    r'\$_REQUEST',
                    r'\$_COOKIE',
                    r'\$_SERVER',
                ],
                "PHP superglobal arrays"
            ),
        ]

        # Java sources
        self.java_sources = [
            TaintSource(
                "Servlet Request",
                TaintType.USER_INPUT,
                [
                    r'request\.getParameter',
                    r'request\.getHeader',
                    r'request\.getQueryString',
                ],
                "Java Servlet request"
            ),
        ]

    def _init_sanitizers(self):
        """Initialize sanitization functions"""

        # Python sanitizers
        self.python_sanitizers = [
            Sanitizer(
                "HTML Escape",
                ["xss", "html_injection"],
                [
                    r'html\.escape\(',
                    r'cgi\.escape\(',
                    r'bleach\.clean\(',
                    r'markupsafe\.escape\(',
                    r'django\.utils\.html\.escape\(',
                ],
                "HTML escaping functions"
            ),
            Sanitizer(
                "SQL Parameterization",
                ["sql_injection"],
                [
                    r'\.execute\s*\([^)]*,\s*\[',
                    r'\.execute\s*\([^)]*,\s*\(',
                    r'\.filter\(',
                    r'\.get\(',
                    r'\.query\(',
                ],
                "Parameterized SQL queries"
            ),
            Sanitizer(
                "Path Validation",
                ["path_traversal"],
                [
                    r'os\.path\.basename\(',
                    r'pathlib\.Path\(',
                    r'werkzeug\.utils\.secure_filename\(',
                ],
                "Path sanitization functions"
            ),
            Sanitizer(
                "Shell Escape",
                ["command_injection"],
                [
                    r'shlex\.quote\(',
                    r'pipes\.quote\(',
                    r'subprocess\.run\([^)]*shell\s*=\s*False',
                ],
                "Shell command escaping"
            ),
        ]

        # JavaScript sanitizers
        self.javascript_sanitizers = [
            Sanitizer(
                "HTML Escape",
                ["xss"],
                [
                    r'escape\(',
                    r'escapeHtml\(',
                    r'sanitize\(',
                    r'DOMPurify\.sanitize\(',
                ],
                "JavaScript HTML escaping"
            ),
            Sanitizer(
                "SQL Parameterization",
                ["sql_injection"],
                [
                    r'\.query\s*\([^)]*,\s*\[',
                    r'\.prepare\(',
                ],
                "SQL parameterization in JavaScript"
            ),
        ]

        # PHP sanitizers
        self.php_sanitizers = [
            Sanitizer(
                "HTML Escape",
                ["xss"],
                [
                    r'htmlspecialchars\(',
                    r'htmlentities\(',
                    r'filter_var\([^)]*FILTER_SANITIZE',
                ],
                "PHP HTML escaping"
            ),
            Sanitizer(
                "SQL Parameterization",
                ["sql_injection"],
                [
                    r'prepare\(',
                    r'bindParam\(',
                    r'bindValue\(',
                ],
                "PHP prepared statements"
            ),
        ]

    def _init_sinks(self):
        """Initialize dangerous sinks"""

        # Python sinks
        self.python_sinks = [
            Sink(
                "SQL Execution",
                "sql_injection",
                [
                    r'\.execute\s*\(\s*["\']?(?:SELECT|INSERT|UPDATE|DELETE|DROP)',
                    r'\.raw\s*\(',
                    r'cursor\.execute\(',
                ],
                "CRITICAL",
                "CWE-89",
                "Direct SQL execution"
            ),
            Sink(
                "Command Execution",
                "command_injection",
                [
                    r'\beval\s*\(',
                    r'\bexec\s*\(',
                    r'os\.system\(',
                    r'subprocess\.call\(',
                    r'subprocess\.Popen\(',
                    r'subprocess\.run\(',
                ],
                "CRITICAL",
                "CWE-78",
                "System command execution"
            ),
            Sink(
                "HTML Output",
                "xss",
                [
                    r'HttpResponse\(',
                    r'render_template_string\(',
                    r'\.innerHTML\s*=',
                    r'mark_safe\(',
                ],
                "HIGH",
                "CWE-79",
                "HTML output without escaping"
            ),
            Sink(
                "File Operations",
                "path_traversal",
                [
                    r'\bopen\s*\(',
                    r'os\.remove\(',
                    r'os\.unlink\(',
                    r'shutil\.rmtree\(',
                ],
                "HIGH",
                "CWE-22",
                "File system operations"
            ),
        ]

        # JavaScript sinks
        self.javascript_sinks = [
            Sink(
                "SQL Execution",
                "sql_injection",
                [
                    r'\.query\s*\(',
                    r'\.execute\s*\(',
                    r'db\.run\(',
                ],
                "CRITICAL",
                "CWE-89",
                "SQL query execution"
            ),
            Sink(
                "Command Execution",
                "command_injection",
                [
                    r'\beval\s*\(',
                    r'Function\s*\(',
                    r'child_process\.exec\(',
                    r'child_process\.spawn\(',
                ],
                "CRITICAL",
                "CWE-78",
                "Command execution"
            ),
            Sink(
                "DOM Manipulation",
                "xss",
                [
                    r'\.innerHTML\s*=',
                    r'\.outerHTML\s*=',
                    r'document\.write\(',
                    r'\.insertAdjacentHTML\(',
                    r'dangerouslySetInnerHTML',
                ],
                "HIGH",
                "CWE-79",
                "DOM manipulation"
            ),
        ]

        # PHP sinks
        self.php_sinks = [
            Sink(
                "SQL Execution",
                "sql_injection",
                [
                    r'mysql_query\(',
                    r'mysqli_query\(',
                    r'->query\(',
                    r'->exec\(',
                ],
                "CRITICAL",
                "CWE-89",
                "PHP SQL execution"
            ),
            Sink(
                "Command Execution",
                "command_injection",
                [
                    r'\beval\s*\(',
                    r'\bexec\s*\(',
                    r'system\(',
                    r'passthru\(',
                    r'shell_exec\(',
                ],
                "CRITICAL",
                "CWE-78",
                "PHP command execution"
            ),
            Sink(
                "HTML Output",
                "xss",
                [
                    r'\becho\s+',
                    r'\bprint\s+',
                    r'<\?=',
                ],
                "HIGH",
                "CWE-79",
                "PHP output"
            ),
        ]

    def track_taint_flow(self, code: str, file_type: str) -> List[TaintFlow]:
        """
        Main entry point for taint tracking

        Args:
            code: Source code to analyze
            file_type: File extension (py, js, php, etc.)

        Returns:
            List of detected taint flows
        """
        if file_type == 'py':
            return self._track_python_taint(code)
        elif file_type in ['js', 'jsx', 'ts', 'tsx']:
            return self._track_javascript_taint(code)
        elif file_type == 'php':
            return self._track_php_taint(code)
        else:
            return self._track_generic_taint(code, file_type)

    def _track_python_taint(self, code: str) -> List[TaintFlow]:
        """Track taint in Python code using AST"""
        flows = []

        try:
            tree = ast.parse(code)
            lines = code.splitlines()

            # Find all tainted variables
            tainted_vars = self._find_tainted_variables_python(tree, lines)

            # Find all sinks
            sinks_found = self._find_sinks_python(tree, lines)

            # Find sanitizers
            sanitized_vars = self._find_sanitized_variables_python(tree, lines)

            # Match tainted vars to sinks
            for sink_info in sinks_found:
                sink_line, sink_pattern, sink_code, sink_obj = sink_info

                # Check if any tainted variable is used in this sink
                for var_name, source_line in tainted_vars:
                    if var_name in sink_code:
                        # Check if this variable was sanitized
                        is_sanitized = var_name in sanitized_vars

                        flow = TaintFlow(
                            source=f"Tainted variable '{var_name}'",
                            source_line=source_line,
                            sink=sink_obj.description,
                            sink_line=sink_line,
                            variable=var_name,
                            sanitized=is_sanitized,
                            vulnerability_type=sink_obj.vulnerability_type,
                            path=[(source_line, f"Source: {var_name}"),
                                  (sink_line, f"Sink: {sink_obj.name}")]
                        )
                        flows.append(flow)

        except SyntaxError:
            # If AST parsing fails, fall back to regex-based tracking
            flows = self._track_generic_taint(code, 'py')

        return flows

    def _find_tainted_variables_python(self, tree: ast.AST, lines: List[str]) -> List[Tuple[str, int]]:
        """Find variables assigned from taint sources"""
        tainted_vars = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if right side is a taint source
                source_code = ast.get_source_segment(lines, node.value) if hasattr(ast, 'get_source_segment') else ""

                for source in self.python_sources:
                    for pattern in source.patterns:
                        if re.search(pattern, source_code or str(node.value)):
                            # Get variable names being assigned
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars.append((target.id, node.lineno))

        return tainted_vars

    def _find_sinks_python(self, tree: ast.AST, lines: List[str]) -> List[Tuple[int, str, str, Sink]]:
        """Find dangerous sinks in Python code"""
        sinks_found = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                line_num = node.lineno
                line_code = lines[line_num - 1] if line_num <= len(lines) else ""

                for sink in self.python_sinks:
                    for pattern in sink.patterns:
                        if re.search(pattern, line_code):
                            sinks_found.append((line_num, pattern, line_code, sink))

        return sinks_found

    def _find_sanitized_variables_python(self, tree: ast.AST, lines: List[str]) -> Set[str]:
        """Find variables that have been sanitized"""
        sanitized_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                source_code = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

                for sanitizer in self.python_sanitizers:
                    for pattern in sanitizer.patterns:
                        if re.search(pattern, source_code):
                            # Mark target variables as sanitized
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    sanitized_vars.add(target.id)

        return sanitized_vars

    def _track_javascript_taint(self, code: str) -> List[TaintFlow]:
        """Track taint in JavaScript code using regex (simplified)"""
        return self._track_generic_taint(code, 'js')

    def _track_php_taint(self, code: str) -> List[TaintFlow]:
        """Track taint in PHP code using regex"""
        return self._track_generic_taint(code, 'php')

    def _track_generic_taint(self, code: str, file_type: str) -> List[TaintFlow]:
        """
        Generic regex-based taint tracking for languages without AST support
        Less precise but works for all languages
        """
        flows = []
        lines = code.splitlines()

        # Select appropriate sources, sanitizers, sinks based on file type
        if file_type in ['js', 'jsx', 'ts', 'tsx']:
            sources = self.javascript_sources
            sanitizers = self.javascript_sanitizers
            sinks = self.javascript_sinks
        elif file_type == 'php':
            sources = self.php_sources
            sanitizers = self.php_sanitizers
            sinks = self.php_sinks
        elif file_type == 'py':
            sources = self.python_sources
            sanitizers = self.python_sanitizers
            sinks = self.python_sinks
        else:
            # For other languages, use a combined approach
            sources = self.python_sources + self.javascript_sources
            sanitizers = self.python_sanitizers + self.javascript_sanitizers
            sinks = self.python_sinks + self.javascript_sinks

        # Track variable assignments from sources
        tainted_vars = {}  # var_name -> line_num

        for line_num, line in enumerate(lines, start=1):
            # Find variable assignments from taint sources
            for source in sources:
                for pattern in source.patterns:
                    if re.search(pattern, line):
                        # Extract variable name (simple regex)
                        var_match = re.search(r'(\w+)\s*=.*?' + pattern, line)
                        if var_match:
                            var_name = var_match.group(1)
                            tainted_vars[var_name] = line_num

            # Find sinks using tainted variables
            for sink in sinks:
                for pattern in sink.patterns:
                    if re.search(pattern, line):
                        # Check if any tainted variable is in this line
                        for var_name, source_line in tainted_vars.items():
                            if var_name in line:
                                # Check if sanitized
                                is_sanitized = self._check_if_sanitized(
                                    var_name, source_line, line_num, lines, sanitizers
                                )

                                flow = TaintFlow(
                                    source=f"Tainted variable '{var_name}'",
                                    source_line=source_line,
                                    sink=sink.description,
                                    sink_line=line_num,
                                    variable=var_name,
                                    sanitized=is_sanitized,
                                    vulnerability_type=sink.vulnerability_type,
                                    path=[(source_line, f"Source"), (line_num, f"Sink")]
                                )
                                flows.append(flow)

        return flows

    def _check_if_sanitized(self, var_name: str, source_line: int, sink_line: int,
                           lines: List[str], sanitizers: List[Sanitizer]) -> bool:
        """Check if a variable was sanitized between source and sink"""

        # Check lines between source and sink
        for line_num in range(source_line, sink_line):
            if line_num <= len(lines):
                line = lines[line_num - 1]

                # Check if variable is reassigned with sanitizer
                for sanitizer in sanitizers:
                    for pattern in sanitizer.patterns:
                        if var_name in line and re.search(pattern, line):
                            return True

        return False
