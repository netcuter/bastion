"""FIRST.org EPSS client — exploitation probability score with 24h cache."""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

CACHE_DIR = Path.home() / ".cache" / "bastion" / "epss"
CACHE_TTL = 86400


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id}.json"


def get_epss(cve_id: str) -> tuple[float, float]:
    """Return (score, percentile) for a CVE-ID. Returns (0.0, 0.0) on error."""
    cache = _cache_path(cve_id)
    if cache.exists() and time.time() - cache.stat().st_mtime < CACHE_TTL:
        d = json.loads(cache.read_text())
        return d["score"], d["percentile"]

    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        items = data.get("data", [])
        if not items:
            return 0.0, 0.0
        score = float(items[0].get("epss", 0))
        pct = float(items[0].get("percentile", 0))
    except (urllib.error.URLError, OSError, KeyError, ValueError):
        return 0.0, 0.0

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"score": score, "percentile": pct}))
    return score, pct
