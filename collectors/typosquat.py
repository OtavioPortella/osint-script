import subprocess
import json
import socket

DNSTWIST_PATH = "/root/osint-tools/dnstwist/dnstwist.py"


def run_dnstwist(domain: str) -> list:
    p = subprocess.run(
        ["python3", DNSTWIST_PATH, "-f", "json", domain], capture_output=True, text=True
    )

    if p.returncode != 0 or not (p.stdout or "").strip():
        return []

    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return []


def resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def scan_domain(domain: str) -> list[dict]:
    data = run_dnstwist(domain)
    findings = []

    for d in data:
        if isinstance(d, dict) and d.get("dns-a"):
            ty = d.get("domain")
            ip = resolve_ip(ty) if ty else None
            if ty and ip:
                findings.append({"type": "typosquat", "original": domain, "domain": ty, "ip": ip})

    return findings
