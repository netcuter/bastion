"""CycloneDX 1.6 SBOM reporter."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .._version import __version__


def generate_sbom(dependencies: list[dict], project_path: str) -> str:
    """
    Emit a CycloneDX 1.6 JSON SBOM.

    Each dependency dict must have keys:
      name, version, ecosystem, purl
    Optional: licenses (list[str]), cves (list[dict] with cve_id, severity,
              cvss_score, epss_score, epss_percentile, description, fixed_version)
    """
    components = [_to_component(d) for d in dependencies]
    vulnerabilities = []
    for d in dependencies:
        for cve in d.get("cves", []):
            vulnerabilities.append(_to_vuln(cve, d))

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "netcuter",
                    "name": "bastion",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": Path(project_path).name,
            },
        },
        "components": components,
    }
    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    return json.dumps(sbom, indent=2)


def _to_component(dep: dict) -> dict:
    comp: dict[str, Any] = {
        "type": "library",
        "name": dep["name"],
        "version": dep.get("version", "unknown"),
        "purl": dep.get("purl", ""),
    }
    if dep.get("licenses"):
        comp["licenses"] = [{"license": {"id": lic}} for lic in dep["licenses"]]
    return comp


def _to_vuln(cve: dict, dep: dict) -> dict:
    vuln: dict[str, Any] = {
        "id": cve["cve_id"],
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{cve['cve_id']}"},
        "ratings": [
            {
                "source": {"name": "OSV"},
                "severity": cve.get("severity", "unknown").lower(),
                "score": cve.get("cvss_score", 0),
            }
        ],
        "description": cve.get("description", ""),
        "affects": [{"ref": dep.get("purl", dep["name"])}],
    }
    if cve.get("epss_score"):
        vuln["properties"] = [
            {"name": "epss:score", "value": str(cve["epss_score"])},
            {"name": "epss:percentile", "value": str(cve.get("epss_percentile", 0))},
        ]
    return vuln
