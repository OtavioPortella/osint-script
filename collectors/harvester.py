import re
import subprocess
from typing import List, Dict, Set


def _extract_emails(text: str, domain: str) -> Set[str]:
    pattern = re.compile(rf"[A-Z0-9._%+-]+@{re.escape(domain)}", re.IGNORECASE)
    return set(m.group(0).lower() for m in pattern.finditer(text))


def scan_domain(domain: str, limit: int = 200) -> List[Dict]:
    """
    Executa theHarvester e extrai emails via regex (resistente a mudanças de output).
    """
    candidates = ["duckduckgo", "crtsh"]
    emails: Set[str] = set()
    used_sources = []

    for src in candidates:
        try:
            cmd = ["theHarvester", "-d", domain, "-b", src, "-l", str(limit)]
            p = subprocess.run(cmd, capture_output=True, text=True)
            output = (p.stdout or "") + "\n" + (p.stderr or "")

            if p.returncode != 0:
                continue

            found = _extract_emails(output, domain)
            if found:
                emails.update(found)
                used_sources.append(src)

        except FileNotFoundError:
            return [
                {
                    "type": "harvester_error",
                    "domain": domain,
                    "error": "theHarvester not found in PATH",
                }
            ]
        except Exception:
            continue

    return [
        {
            "type": "harvester_emails",
            "domain": domain,
            "sources": used_sources,
            "emails": sorted(emails),
            "count": len(emails),
        }
    ]
