import requests


def scan_domain(domain: str) -> list[dict]:
    """
    Retorna 1 finding por subdomínio encontrado em CT logs via crt.sh
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return []

        data = r.json()
        subs = set()

        for entry in data:
            name_val = (entry.get("name_value") or "").strip()
            if not name_val:
                continue

            # name_value pode vir com múltiplas linhas
            for item in name_val.splitlines():
                s = item.strip().lower()
                if not s:
                    continue
                # filtra só o que contém o domínio
                if s.endswith(domain.lower()):
                    subs.add(s)

        findings = [{"type": "certificate_subdomain", "subdomain": s} for s in sorted(subs)]
        return findings
    except Exception:
        return []
