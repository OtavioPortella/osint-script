import time
import requests
from typing import List, Dict, Optional

PUBLIC_ENDPOINT = "https://leakcheck.io/api/public"


def check(email: str, timeout: int = 15) -> Optional[Dict]:
    try:
        r = requests.get(PUBLIC_ENDPOINT, params={"check": email}, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("success"):
            return None
        found = int(data.get("found", 0) or 0)
        if found <= 0:
            return None
        return {
            "type": "leakcheck_public",
            "query": email,
            "found": found,
            "fields": data.get("fields", []),
            "sources": data.get("sources", []),
        }
    except Exception:
        return None


def scan_emails(emails: List[str], sleep_s: float = 1.2, max_emails: int = 200) -> List[Dict]:
    findings = []
    for e in emails[:max_emails]:
        hit = check(e)
        if hit:
            findings.append(hit)
        time.sleep(sleep_s)
    return findings
