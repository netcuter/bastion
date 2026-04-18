"""Tests for Reachability Analysis."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_audit.core.reachability import Reachability, ReachabilityAnalyzer
from security_audit.core.scanner import Finding, Severity


def _finding(file_path: str, line: int) -> Finding:
    return Finding(
        scanner="test", severity=Severity.HIGH, title="SQLi",
        description="test", file_path=file_path, line_number=line,
        code_snippet="cursor.execute(query)", recommendation="use parameterized queries",
    )


class TestEntrypointDiscovery:
    def test_discovers_flask_route(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            "@app.route('/search')\ndef search():\n    pass\n"
        )
        analyzer = ReachabilityAnalyzer()
        eps = analyzer.discover_entrypoints(tmp_path)
        assert any(e.function_name == "search" and e.framework == "flask" for e in eps)

    def test_discovers_fastapi_route(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text(
            "@app.get('/users')\ndef list_users():\n    pass\n"
        )
        analyzer = ReachabilityAnalyzer()
        eps = analyzer.discover_entrypoints(tmp_path)
        assert any(e.function_name == "list_users" for e in eps)

    def test_no_entrypoints_returns_empty(self, tmp_path):
        f = tmp_path / "utils.py"
        f.write_text("def helper():\n    pass\n")
        analyzer = ReachabilityAnalyzer()
        eps = analyzer.discover_entrypoints(tmp_path)
        assert eps == []


class TestReachabilityVerdict:
    def test_reachable_via_call_graph(self, tmp_path):
        # Flask route 'search' calls 'run_query' which has the finding
        code = (
            "@app.route('/search')\n"
            "def search():\n"
            "    return run_query(request.args['q'])\n\n"
            "def run_query(q):\n"
            "    cursor.execute(f'SELECT * FROM t WHERE x={q}')\n"
        )
        f = tmp_path / "app.py"
        f.write_text(code)

        call_edges = {"search": {"run_query"}}
        analyzer = ReachabilityAnalyzer(call_edges)
        analyzer.discover_entrypoints(tmp_path)

        finding = _finding(str(f), 6)
        verdict = analyzer.analyze_finding(finding)
        assert verdict.reachability == Reachability.REACHABLE

    def test_unreachable_dead_code(self, tmp_path):
        code = (
            "@app.route('/search')\n"
            "def search():\n"
            "    pass\n\n"
            "def internal_helper():\n"
            "    cursor.execute(evil_query)\n"
        )
        f = tmp_path / "app.py"
        f.write_text(code)

        # No call edge from search to internal_helper
        analyzer = ReachabilityAnalyzer({})
        analyzer.discover_entrypoints(tmp_path)

        finding = _finding(str(f), 6)
        verdict = analyzer.analyze_finding(finding)
        assert verdict.reachability == Reachability.UNREACHABLE

    def test_unknown_when_no_entrypoints(self, tmp_path):
        code = "def helper():\n    cursor.execute(q)\n"
        f = tmp_path / "utils.py"
        f.write_text(code)

        analyzer = ReachabilityAnalyzer({})
        analyzer.discover_entrypoints(tmp_path)  # finds nothing

        finding = _finding(str(f), 2)
        verdict = analyzer.analyze_finding(finding)
        assert verdict.reachability == Reachability.UNKNOWN

    def test_directly_in_entrypoint(self, tmp_path):
        code = (
            "@app.route('/vuln')\n"
            "def vuln_route():\n"
            "    cursor.execute(f'SELECT * WHERE id={request.args[\"id\"]}')\n"
        )
        f = tmp_path / "app.py"
        f.write_text(code)

        analyzer = ReachabilityAnalyzer({})
        analyzer.discover_entrypoints(tmp_path)

        finding = _finding(str(f), 3)
        verdict = analyzer.analyze_finding(finding)
        assert verdict.reachability == Reachability.REACHABLE
