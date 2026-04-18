"""OSV.dev client — query CVEs for a package version with 24h local cache."""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

CACHE_DIR = Path.home() / ".cache" / "bastion" / "osv"
CACHE_TTL = 86400  # 24 h


def _cache_path(ecosystem: str, name: str, version: str) -> Path:
    key = f"{ecosystem}_{name}_{version}".replace("/", "_").replace(":", "_")
    return CACHE_DIR / f"{key}.json"


def _load_cache(path: Path) -> Optional[list]:
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL:
        return None
    return json.loads(path.read_text())


def _save_cache(path: Path, data: list) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def query_osv(name: str, version: str, ecosystem: str) -> list[dict]:
    """Return list of OSV vuln dicts for the given package/version."""
    cache = _cache_path(ecosystem, name, version)
    hit = _load_cache(cache)
    if hit is not None:
        return hit

    payload = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode()
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError):
        return []

    vulns = data.get("vulns", [])
    _save_cache(cache, vulns)
    return vulns
