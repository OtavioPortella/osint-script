import os
import time
import requests

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


def _headers(api_key: str) -> dict:
    return {"X-OTX-API-KEY": api_key, "User-Agent": "soc-ti", "Accept": "application/json"}


def _get(url: str, api_key: str, timeout: int = 20) -> dict | None:
    try:
        r = requests.get(url, headers=_headers(api_key), timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def _key() -> str:
    return os.getenv("OTX_API_KEY", "").strip()


def enrich_domain(domain: str, sleep_s: float = 1.0) -> list[dict]:
    key = _key()
    if not key:
        return []
    data = _get(f"{OTX_BASE}/domain/{domain}/general", key)
    if not data:
        return []
    pulse_info = data.get("pulse_info", {}) or {}
    count = int(pulse_info.get("count", 0) or 0)
    if count <= 0:
        return []
    pulses = pulse_info.get("pulses") or []
    time.sleep(sleep_s)
    return [
        {
            "type": "otx_domain",
            "indicator": domain,
            "pulse_count": count,
            "pulses": [
                {"name": p.get("name"), "id": p.get("id"), "tlp": p.get("tlp")} for p in pulses[:5]
            ],
        }
    ]


def enrich_ipv4(ip: str, sleep_s: float = 1.0) -> list[dict]:
    key = _key()
    if not key:
        return []
    data = _get(f"{OTX_BASE}/IPv4/{ip}/general", key)
    if not data:
        return []
    pulse_info = data.get("pulse_info", {}) or {}
    count = int(pulse_info.get("count", 0) or 0)
    if count <= 0:
        return []
    pulses = pulse_info.get("pulses") or []
    time.sleep(sleep_s)
    return [
        {
            "type": "otx_ipv4",
            "indicator": ip,
            "pulse_count": count,
            "pulses": [
                {"name": p.get("name"), "id": p.get("id"), "tlp": p.get("tlp")} for p in pulses[:5]
            ],
        }
    ]
