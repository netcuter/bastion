"""Tests for SBOM/VEX feature."""
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_audit.reporters.cyclonedx_reporter import generate_sbom
from security_audit.reporters.vex_reporter import generate_vex
from security_audit.integrations.osv_client import query_osv
from security_audit.integrations.epss_client import get_epss


SAMPLE_DEP = {
    "name": "lodash",
    "version": "4.17.20",
    "ecosystem": "npm",
    "purl": "pkg:npm/lodash@4.17.20",
    "licenses": ["MIT"],
    "cves": [
        {
            "cve_id": "CVE-2021-23337",
            "severity": "HIGH",
            "cvss_score": 7.2,
            "epss_score": 0.012,
            "epss_percentile": 0.85,
            "description": "Lodash command injection via template",
            "fixed_version": "4.17.21",
        }
    ],
}


class TestCycloneDXReporter:
    def test_valid_cyclonedx_structure(self):
        out = generate_sbom([SAMPLE_DEP], "/project/myapp")
        doc = json.loads(out)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert len(doc["components"]) == 1
        assert doc["components"][0]["name"] == "lodash"
        assert doc["components"][0]["purl"] == "pkg:npm/lodash@4.17.20"

    def test_vulnerabilities_included(self):
        doc = json.loads(generate_sbom([SAMPLE_DEP], "/project"))
        assert len(doc["vulnerabilities"]) == 1
        v = doc["vulnerabilities"][0]
        assert v["id"] == "CVE-2021-23337"
        assert any(p["name"] == "epss:score" for p in v.get("properties", []))

    def test_no_cves_omits_vulnerabilities_key(self):
        dep = {**SAMPLE_DEP, "cves": []}
        doc = json.loads(generate_sbom([dep], "/project"))
        assert "vulnerabilities" not in doc

    def test_metadata_contains_tool_info(self):
        doc = json.loads(generate_sbom([], "/project/app"))
        assert doc["metadata"]["tools"][0]["name"] == "bastion"
        assert doc["metadata"]["component"]["name"] == "app"


class TestVEXReporter:
    def test_valid_vex_structure(self):
        stmts = [
            {
                "vuln_id": "CVE-2021-23337",
                "product": "pkg:npm/lodash@4.17.20",
                "status": "affected",
                "detail": "Template function reachable from user input",
            }
        ]
        doc = json.loads(generate_vex(stmts, "myapp"))
        assert doc["bomFormat"] == "CycloneDX"
        v = doc["vulnerabilities"][0]
        assert v["id"] == "CVE-2021-23337"
        assert v["analysis"]["state"] == "affected"

    def test_not_affected_with_justification(self):
        stmts = [
            {
                "vuln_id": "CVE-2021-23337",
                "product": "pkg:npm/lodash@4.17.20",
                "status": "not_affected",
                "justification": "protected_by_compiler",
            }
        ]
        doc = json.loads(generate_vex(stmts, "myapp"))
        assert doc["vulnerabilities"][0]["analysis"]["justification"] == "protected_by_compiler"


class TestOSVClient:
    def test_returns_empty_on_network_error(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = query_osv("django", "2.2.0", "PyPI")
        assert result == []

    def test_parses_osv_response(self, tmp_path):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"vulns": [{"id": "GHSA-xxx", "summary": "test vuln"}]}
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch("security_audit.integrations.osv_client.CACHE_DIR", tmp_path):
            result = query_osv("django", "2.2.0", "PyPI")
        assert len(result) == 1
        assert result[0]["id"] == "GHSA-xxx"


class TestEPSSClient:
    def test_returns_zeros_on_error(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            score, pct = get_epss("CVE-2021-23337")
        assert score == 0.0
        assert pct == 0.0

    def test_parses_epss_response(self, tmp_path):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"data": [{"epss": "0.0123", "percentile": "0.87654"}]}
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch("security_audit.integrations.epss_client.CACHE_DIR", tmp_path):
            score, pct = get_epss("CVE-2021-23337")
        assert abs(score - 0.0123) < 0.0001
        assert abs(pct - 0.87654) < 0.0001
