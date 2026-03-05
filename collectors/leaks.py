import subprocess

LEAKSEARCH_PATH = "/root/osint-tools/LeakSearch/LeakSearch.py"


def scan_domain(domain: str) -> list[dict]:
    """
    Executa LeakSearch e retorna 1 finding com raw_output se houver indício de resultado.
    """
    try:
        p = subprocess.run(
            ["python3", LEAKSEARCH_PATH, "-k", domain], capture_output=True, text=True
        )

        out = (p.stdout or "") + "\n" + (p.stderr or "")
        if p.returncode != 0:
            return []

        # Heurística simples: se encontrou records
        if "Found" in out and "records" in out:
            return [{"type": "leak", "query": domain, "raw_output": out}]

        return []
    except Exception:
        return []
