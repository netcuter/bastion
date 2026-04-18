"""
Reachability Analysis

Answers: "Can user-controlled input actually reach this finding via a live entrypoint?"

Statuses:
  REACHABLE   — BFS through call graph found path from entrypoint to finding's function
  UNREACHABLE — No path exists (dead code, internal utility)
  UNKNOWN     — Could not determine (no entrypoints found, dynamic dispatch, etc.)
"""

import ast
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

from .scanner import Finding


class Reachability(Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass
class Entrypoint:
    kind: str           # http_route | cli | event_handler | cron
    file_path: str
    line_number: int
    function_name: str
    method: Optional[str] = None        # HTTP method if route
    path_pattern: Optional[str] = None  # URL pattern if route
    framework: Optional[str] = None


@dataclass
class ReachabilityVerdict:
    finding_id: str
    reachability: Reachability
    entrypoints: List[Entrypoint] = field(default_factory=list)
    path: List[str] = field(default_factory=list)   # call chain
    confidence: float = 0.5
    explanation: str = ""


# ---------------------------------------------------------------------------
# Entrypoint detection patterns
# ---------------------------------------------------------------------------

_FLASK_ROUTE = re.compile(
    r'@(?:app|bp|blueprint)\.(route|get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]*)[\'"]',
    re.MULTILINE,
)
_FASTAPI_ROUTE = re.compile(
    r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*[\'"]([^\'"]*)[\'"]',
    re.MULTILINE,
)
_EXPRESS_ROUTE = re.compile(
    r'(?:app|router)\.(get|post|put|delete|patch|use)\s*\(\s*[\'"]([^\'"]*)[\'"]',
    re.MULTILINE,
)
_DJANGO_URL = re.compile(
    r'(?:path|re_path)\s*\(\s*[\'"]([^\'"]*)[\'"].*?,\s*(\w+)',
    re.MULTILINE,
)
_SPRING_MAPPING = re.compile(
    r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*(?:\([^)]*\))?',
    re.MULTILINE,
)
_LARAVEL_ROUTE = re.compile(
    r'Route::(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]*)[\'"].*?,\s*(?:\[.*?,\s*)?[\'"](\w+)',
    re.MULTILINE,
)
_CLICK_CMD = re.compile(r'@\w+\.command\(\)', re.MULTILINE)
_ARGPARSE = re.compile(r'ArgumentParser\s*\(', re.MULTILINE)
_CELERY_TASK = re.compile(r'@(?:app|celery)\.task', re.MULTILINE)
_MAIN_GUARD = re.compile(r'if\s+__name__\s*==\s*[\'"]__main__[\'"]', re.MULTILINE)

# Map decorator line -> function name (next def after decorator)
_DEF_AFTER = re.compile(r'def\s+(\w+)\s*\(')


def _fn_after(content: str, match_end: int) -> Optional[str]:
    """Find the function defined right after a decorator match."""
    rest = content[match_end:]
    m = _DEF_AFTER.search(rest)
    if m and m.start() < 300:  # must be close
        return m.group(1)
    return None


class ReachabilityAnalyzer:
    """
    Discovers entrypoints across a project and determines
    whether each static finding is reachable from any of them.
    """

    def __init__(self, call_edges: Optional[Dict[str, Set[str]]] = None):
        # call_edges: caller -> set[callee] (from existing CallGraph)
        self._edges: Dict[str, Set[str]] = call_edges or {}
        self._reversed: Dict[str, Set[str]] = {}  # callee -> set[callers]
        self._entrypoints: List[Entrypoint] = []
        self._entrypoint_fns: Set[str] = set()
        self._build_reversed()

    def _build_reversed(self) -> None:
        for caller, callees in self._edges.items():
            for callee in callees:
                self._reversed.setdefault(callee, set()).add(caller)

    # ------------------------------------------------------------------
    # Entrypoint discovery
    # ------------------------------------------------------------------

    def discover_entrypoints(self, project_root: Path) -> List[Entrypoint]:
        self._entrypoints = []
        for ext in ("*.py", "*.js", "*.ts", "*.php", "*.java", "*.rb"):
            for fpath in project_root.rglob(ext):
                if any(p in str(fpath) for p in ("node_modules", "__pycache__", ".git", "venv")):
                    continue
                try:
                    content = fpath.read_text(errors="ignore")
                except OSError:
                    continue
                self._scan_file_for_entrypoints(str(fpath), content, fpath.suffix)

        self._entrypoint_fns = {e.function_name for e in self._entrypoints}
        return self._entrypoints

    def _scan_file_for_entrypoints(self, path: str, content: str, ext: str) -> None:
        ep = self._entrypoints

        if ext == ".py":
            # Flask / FastAPI
            for pattern, framework, kind in [
                (_FLASK_ROUTE, "flask", "http_route"),
                (_FASTAPI_ROUTE, "fastapi", "http_route"),
            ]:
                for m in pattern.finditer(content):
                    fn = _fn_after(content, m.end())
                    if fn:
                        ep.append(Entrypoint(kind=kind, file_path=path,
                                             line_number=content[:m.start()].count("\n") + 1,
                                             function_name=fn,
                                             method=m.group(1).upper() if m.lastindex >= 1 else None,
                                             path_pattern=m.group(2) if m.lastindex >= 2 else None,
                                             framework=framework))
            # Django urls.py
            if "urlpatterns" in content or "path(" in content:
                for m in _DJANGO_URL.finditer(content):
                    fn = m.group(2)
                    ep.append(Entrypoint(kind="http_route", file_path=path,
                                         line_number=content[:m.start()].count("\n") + 1,
                                         function_name=fn, framework="django",
                                         path_pattern=m.group(1)))
            # Click commands
            for m in _CLICK_CMD.finditer(content):
                fn = _fn_after(content, m.end())
                if fn:
                    ep.append(Entrypoint(kind="cli", file_path=path,
                                         line_number=content[:m.start()].count("\n") + 1,
                                         function_name=fn, framework="click"))
            # argparse main
            if _ARGPARSE.search(content) and _MAIN_GUARD.search(content):
                ep.append(Entrypoint(kind="cli", file_path=path, line_number=1,
                                      function_name="main", framework="argparse"))
            # Celery
            for m in _CELERY_TASK.finditer(content):
                fn = _fn_after(content, m.end())
                if fn:
                    ep.append(Entrypoint(kind="event_handler", file_path=path,
                                         line_number=content[:m.start()].count("\n") + 1,
                                         function_name=fn, framework="celery"))

        elif ext in (".js", ".ts"):
            for m in _EXPRESS_ROUTE.finditer(content):
                # Anonymous function or next identifier
                ep.append(Entrypoint(kind="http_route", file_path=path,
                                      line_number=content[:m.start()].count("\n") + 1,
                                      function_name=f"express_handler_{m.start()}",
                                      method=m.group(1).upper(),
                                      path_pattern=m.group(2),
                                      framework="express"))

        elif ext == ".php":
            for m in _LARAVEL_ROUTE.finditer(content):
                ep.append(Entrypoint(kind="http_route", file_path=path,
                                      line_number=content[:m.start()].count("\n") + 1,
                                      function_name=m.group(3),
                                      method=m.group(1).upper(),
                                      path_pattern=m.group(2),
                                      framework="laravel"))

        elif ext == ".java":
            for m in _SPRING_MAPPING.finditer(content):
                fn = _fn_after(content, m.end())
                if fn:
                    ep.append(Entrypoint(kind="http_route", file_path=path,
                                          line_number=content[:m.start()].count("\n") + 1,
                                          function_name=fn, framework="spring"))

    # ------------------------------------------------------------------
    # Reachability analysis
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Finding) -> ReachabilityVerdict:
        vid = getattr(finding, "id", f"{finding.file_path}:{finding.line_number}")

        if not self._entrypoints:
            return ReachabilityVerdict(
                finding_id=vid,
                reachability=Reachability.UNKNOWN,
                confidence=0.3,
                explanation="No entrypoints discovered in project.",
            )

        # Try to infer containing function from AST (Python only)
        containing_fn = self._infer_function(finding.file_path, finding.line_number)
        if not containing_fn:
            return ReachabilityVerdict(
                finding_id=vid,
                reachability=Reachability.UNKNOWN,
                confidence=0.4,
                explanation="Could not determine containing function.",
            )

        # BFS backward through call graph
        path = self._bfs_to_entrypoint(containing_fn)

        if path is not None:
            reached_eps = [e for e in self._entrypoints if e.function_name == path[0]]
            return ReachabilityVerdict(
                finding_id=vid,
                reachability=Reachability.REACHABLE,
                entrypoints=reached_eps,
                path=path,
                confidence=0.85,
                explanation=f"Reachable via: {' → '.join(path)}",
            )

        # Check if containing function is itself an entrypoint
        if containing_fn in self._entrypoint_fns:
            eps = [e for e in self._entrypoints if e.function_name == containing_fn]
            return ReachabilityVerdict(
                finding_id=vid,
                reachability=Reachability.REACHABLE,
                entrypoints=eps,
                path=[containing_fn],
                confidence=0.95,
                explanation="Finding is directly inside an entrypoint function.",
            )

        return ReachabilityVerdict(
            finding_id=vid,
            reachability=Reachability.UNREACHABLE,
            confidence=0.7,
            explanation=f"No path from any entrypoint to '{containing_fn}' found in call graph.",
        )

    def analyze_batch(self, findings: List[Finding]) -> List[ReachabilityVerdict]:
        return [self.analyze_finding(f) for f in findings]

    def _bfs_to_entrypoint(self, target_fn: str) -> Optional[List[str]]:
        """BFS through reversed edges: from target backward to any entrypoint."""
        if target_fn in self._entrypoint_fns:
            return [target_fn]
        if not self._reversed:
            return None

        visited: Set[str] = {target_fn}
        queue: deque = deque([[target_fn]])

        while queue:
            path = queue.popleft()
            current = path[0]
            for caller in self._reversed.get(current, set()):
                if caller in visited:
                    continue
                new_path = [caller] + path
                if caller in self._entrypoint_fns:
                    return new_path
                visited.add(caller)
                if len(new_path) < 15:  # depth cap
                    queue.append(new_path)
        return None

    def _infer_function(self, file_path: str, line_number: int) -> Optional[str]:
        """Find the function name that contains the given line (Python only)."""
        if not file_path.endswith(".py"):
            return None
        try:
            content = Path(file_path).read_text(errors="ignore")
            tree = ast.parse(content)
        except (OSError, SyntaxError):
            return None

        best: Optional[str] = None
        best_start = -1
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.lineno <= line_number:
                end = getattr(node, "end_lineno", node.lineno + 999)
                if node.lineno > best_start and line_number <= end:
                    best = node.name
                    best_start = node.lineno
        return best
