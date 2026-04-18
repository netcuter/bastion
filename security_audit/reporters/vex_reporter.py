"""VEX (Vulnerability Exploitability eXchange) reporter — CycloneDX VEX format."""
import json
import uuid
from datetime import datetime, timezone

from .._version import __version__


def generate_vex(statements: list[dict], project_name: str) -> str:
    """
    Emit a CycloneDX VEX JSON document.

    Each statement dict must have:
      vuln_id, product (purl), status
    Optional: justification, detail
    """
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "netcuter", "name": "bastion", "version": __version__}],
                "component": {"type": "application", "name": project_name},
            },
            "vulnerabilities": [_to_vex_entry(s) for s in statements],
        },
        indent=2,
    )


def _to_vex_entry(stmt: dict) -> dict:
    entry: dict = {
        "id": stmt["vuln_id"],
        "analysis": {
            "state": stmt["status"],  # affected | not_affected | fixed | under_investigation
        },
        "affects": [{"ref": stmt["product"]}],
    }
    if stmt.get("justification"):
        entry["analysis"]["justification"] = stmt["justification"]
    if stmt.get("detail"):
        entry["analysis"]["detail"] = stmt["detail"]
    return entry
