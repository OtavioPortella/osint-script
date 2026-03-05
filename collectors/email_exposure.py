import subprocess

COMMON_PREFIXES = [
    "contato",
    "financeiro",
    "suporte",
    "admin",
    "rh",
    "ti",
    "comercial",
    "faturamento",
]


def _parse_services(stdout: str) -> list[str]:
    services = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if "[+]" in line:
            # formato típico: "[+] ServiceName"
            try:
                svc = line.split("[+]", 1)[1].strip()
                if svc:
                    services.append(svc)
            except Exception:
                continue
    return sorted(set(services))


def scan_domain(domain: str) -> list[dict]:
    findings = []
    for prefix in COMMON_PREFIXES:
        email = f"{prefix}@{domain}"
        try:
            p = subprocess.run(
                ["holehe", email, "--only-used", "--no-color"], capture_output=True, text=True
            )
            if p.returncode != 0:
                continue
            services = _parse_services(p.stdout)
            if services:
                findings.append(
                    {
                        "type": "email_exposure",
                        "email": email,
                        "accounts_found": len(services),
                        "services": services,
                    }
                )
        except Exception:
            continue
    return findings
