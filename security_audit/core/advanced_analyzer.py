"""
Advanced Code Analyzer with Call Graph and Interprocedural Analysis
Performs multi-file, cross-function vulnerability detection
"""
import ast
import re
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from .taint_tracker import TaintTracker, TaintFlow


@dataclass
class Function:
    """Represents a function in the codebase"""
    name: str
    file_path: str
    line_number: int
    parameters: List[str]
    returns: bool
    calls: List[str] = field(default_factory=list)  # Functions this function calls
    called_by: List[str] = field(default_factory=list)  # Functions that call this
    has_taint_source: bool = False
    has_taint_sink: bool = False
    local_variables: Set[str] = field(default_factory=set)


@dataclass
class CallPath:
    """Represents a call path from source to sink"""
    functions: List[Function]
    taint_flows: List[TaintFlow]
    vulnerability_type: str
    severity: str


class CallGraph:
    """
    Builds and analyzes call graph for interprocedural analysis
    """

    def __init__(self):
        self.functions: Dict[str, Function] = {}  # function_name -> Function
        self.edges: Dict[str, Set[str]] = defaultdict(set)  # caller -> set of callees
        self.taint_tracker = TaintTracker()

    def add_function(self, func: Function):
        """Add a function to the call graph"""
        self.functions[func.name] = func

    def add_call_edge(self, caller: str, callee: str):
        """Add a call edge from caller to callee"""
        self.edges[caller].add(callee)

        if caller in self.functions and callee in self.functions:
            self.functions[caller].calls.append(callee)
            self.functions[callee].called_by.append(caller)

    def build_from_python_ast(self, file_path: str, code: str):
        """Build call graph from Python AST"""
        try:
            tree = ast.parse(code)
            self._extract_functions_python(tree, file_path)
            self._extract_calls_python(tree)
        except SyntaxError as e:
            print(f"[!] Syntax error in {file_path}: {e}")

    def _extract_functions_python(self, tree: ast.AST, file_path: str):
        """Extract all function definitions from Python AST"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                params = [arg.arg for arg in node.args.args]

                func = Function(
                    name=node.name,
                    file_path=file_path,
                    line_number=node.lineno,
                    parameters=params,
                    returns=self._has_return(node)
                )

                # Check if function has taint sources or sinks
                func_code = ast.unparse(node) if hasattr(ast, 'unparse') else ""
                func.has_taint_source = self._contains_taint_source(func_code)
                func.has_taint_sink = self._contains_taint_sink(func_code)

                # Extract local variables
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                func.local_variables.add(target.id)

                self.add_function(func)

    def _extract_calls_python(self, tree: ast.AST):
        """Extract function calls from Python AST"""
        current_function = None

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                current_function = node.name

            elif isinstance(node, ast.Call) and current_function:
                callee_name = None

                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr

                if callee_name and callee_name in self.functions:
                    self.add_call_edge(current_function, callee_name)

    def _has_return(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has return statement"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return True
        return False

    def _contains_taint_source(self, code: str) -> bool:
        """Check if code contains taint sources"""
        source_patterns = [
            r'request\.(args|form|values|json|data|GET|POST)',
            r'input\s*\(',
            r'sys\.stdin',
        ]
        return any(re.search(pattern, code) for pattern in source_patterns)

    def _contains_taint_sink(self, code: str) -> bool:
        """Check if code contains taint sinks"""
        sink_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'os\.system\(',
            r'subprocess\.',
            r'\.execute\(',
            r'cursor\.execute\(',
        ]
        return any(re.search(pattern, code) for pattern in sink_patterns)

    def find_paths(self, start: str, end: str, max_depth: int = 10) -> List[List[str]]:
        """
        Find all paths from start function to end function

        Args:
            start: Starting function name
            end: Ending function name
            max_depth: Maximum path depth to search

        Returns:
            List of paths (each path is a list of function names)
        """
        paths = []
        visited = set()

        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth:
                return

            if current == end:
                paths.append(path.copy())
                return

            if current in visited:
                return

            visited.add(current)

            for callee in self.edges.get(current, []):
                path.append(callee)
                dfs(callee, path, depth + 1)
                path.pop()

            visited.remove(current)

        dfs(start, [start], 0)
        return paths

    def find_source_to_sink_paths(self) -> List[CallPath]:
        """
        Find all paths from functions with taint sources to functions with sinks

        Returns:
            List of call paths representing potential vulnerabilities
        """
        call_paths = []

        # Find all source functions
        source_funcs = [f for f in self.functions.values() if f.has_taint_source]

        # Find all sink functions
        sink_funcs = [f for f in self.functions.values() if f.has_taint_sink]

        # Find paths between each source-sink pair
        for source_func in source_funcs:
            for sink_func in sink_funcs:
                paths = self.find_paths(source_func.name, sink_func.name)

                for path in paths:
                    # Build CallPath object
                    func_objects = [self.functions[fname] for fname in path if fname in self.functions]

                    call_path = CallPath(
                        functions=func_objects,
                        taint_flows=[],
                        vulnerability_type="Interprocedural Taint Flow",
                        severity="HIGH"
                    )
                    call_paths.append(call_path)

        return call_paths

    def get_function_complexity(self, func_name: str) -> Dict[str, Any]:
        """Calculate complexity metrics for a function"""
        if func_name not in self.functions:
            return {}

        func = self.functions[func_name]

        return {
            "name": func_name,
            "calls_count": len(func.calls),
            "called_by_count": len(func.called_by),
            "parameters_count": len(func.parameters),
            "local_vars_count": len(func.local_variables),
            "has_taint_source": func.has_taint_source,
            "has_taint_sink": func.has_taint_sink,
        }

    def get_most_called_functions(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get the most frequently called functions"""
        func_call_counts = [(fname, len(func.called_by)) for fname, func in self.functions.items()]
        func_call_counts.sort(key=lambda x: x[1], reverse=True)
        return func_call_counts[:top_n]

    def get_deepest_call_chains(self, top_n: int = 10) -> List[Tuple[List[str], int]]:
        """Get the deepest call chains in the codebase"""
        all_chains = []

        for func_name in self.functions:
            # DFS to find longest chain from this function
            max_chain = []
            visited = set()

            def find_longest_chain(current: str, chain: List[str]):
                nonlocal max_chain
                if len(chain) > len(max_chain):
                    max_chain = chain.copy()

                if current in visited:
                    return

                visited.add(current)

                for callee in self.edges.get(current, []):
                    chain.append(callee)
                    find_longest_chain(callee, chain)
                    chain.pop()

                visited.remove(current)

            find_longest_chain(func_name, [func_name])
            all_chains.append((max_chain, len(max_chain)))

        all_chains.sort(key=lambda x: x[1], reverse=True)
        return all_chains[:top_n]


class AdvancedAnalyzer:
    """
    Advanced analyzer combining taint tracking, call graph analysis,
    and interprocedural data flow analysis
    """

    def __init__(self):
        self.call_graph = CallGraph()
        self.taint_tracker = TaintTracker()
        self.files_analyzed: Set[str] = set()

    def analyze_directory(self, directory: str, file_extensions: List[str] = None) -> Dict[str, Any]:
        """
        Analyze entire directory with interprocedural analysis

        Args:
            directory: Directory path to analyze
            file_extensions: List of file extensions to analyze (e.g., ['.py', '.js'])

        Returns:
            Analysis results including vulnerabilities and metrics
        """
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.php', '.java']

        directory_path = Path(directory)
        results = {
            "vulnerabilities": [],
            "call_graph_metrics": {},
            "interprocedural_flows": [],
        }

        # Build call graph from all files
        for file_path in directory_path.rglob('*'):
            if file_path.suffix in file_extensions and file_path.is_file():
                self._analyze_file(str(file_path), file_path.suffix)

        # Find interprocedural vulnerabilities
        interprocedural_paths = self.call_graph.find_source_to_sink_paths()
        results["interprocedural_flows"] = [self._format_call_path(cp) for cp in interprocedural_paths]

        # Calculate metrics
        results["call_graph_metrics"] = {
            "total_functions": len(self.call_graph.functions),
            "total_edges": sum(len(callees) for callees in self.call_graph.edges.values()),
            "most_called": self.call_graph.get_most_called_functions(5),
            "deepest_chains": [(chain, depth) for chain, depth in self.call_graph.get_deepest_call_chains(5)],
        }

        return results

    def _analyze_file(self, file_path: str, file_extension: str):
        """Analyze single file and add to call graph"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            if file_extension == '.py':
                self.call_graph.build_from_python_ast(file_path, code)

            # Track taint flows within this file
            file_type = file_extension.lstrip('.')
            taint_flows = self.taint_tracker.track_taint_flow(code, file_type)

            self.files_analyzed.add(file_path)

        except Exception as e:
            print(f"[!] Error analyzing {file_path}: {e}")

    def _format_call_path(self, call_path: CallPath) -> Dict[str, Any]:
        """Format call path for output"""
        return {
            "path": [f"{func.name}@{func.file_path}:{func.line_number}" for func in call_path.functions],
            "vulnerability_type": call_path.vulnerability_type,
            "severity": call_path.severity,
            "depth": len(call_path.functions),
        }

    def analyze_single_file(self, file_path: str, code: str, file_type: str) -> Dict[str, Any]:
        """
        Analyze a single file for advanced vulnerabilities

        Args:
            file_path: Path to file
            code: Source code
            file_type: File extension (py, js, etc.)

        Returns:
            Analysis results with taint flows and data flow issues
        """
        results = {
            "taint_flows": [],
            "data_flow_issues": [],
            "metrics": {},
        }

        # Perform taint tracking
        taint_flows = self.taint_tracker.track_taint_flow(code, file_type)
        results["taint_flows"] = [self._format_taint_flow(flow) for flow in taint_flows]

        # Build mini call graph for this file
        if file_type == 'py':
            try:
                self.call_graph.build_from_python_ast(file_path, code)
            except:
                pass

        return results

    def _format_taint_flow(self, flow: TaintFlow) -> Dict[str, Any]:
        """Format taint flow for output"""
        return {
            "source": flow.source,
            "source_line": flow.source_line,
            "sink": flow.sink,
            "sink_line": flow.sink_line,
            "variable": flow.variable,
            "sanitized": flow.sanitized,
            "vulnerability_type": flow.vulnerability_type,
            "severity": "INFO" if flow.sanitized else "HIGH",
            "path": flow.path,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            "files_analyzed": len(self.files_analyzed),
            "functions_found": len(self.call_graph.functions),
            "call_edges": sum(len(callees) for callees in self.call_graph.edges.values()),
        }
