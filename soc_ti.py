import json
import re
import yaml

from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

from collectors.typosquat import scan_domain as scan_typosquat
from collectors.leaks import scan_domain as scan_leaksrch
from collectors.email_exposure import scan_domain as scan_holehe_domain
from collectors.cert_monitor import scan_domain as scan_cert
from collectors.harvester import scan_domain as scan_harvester
from collectors.leakcheck_public import scan_emails as scan_leakcheck
from collectors.otx import enrich_domain as otx_domain, enrich_ipv4 as otx_ip

SUSPICIOUS_SUBDOMAIN_KEYWORDS = {
    "login",
    "sso",
    "auth",
    "vpn",
    "mail",
    "webmail",
    "owa",
    "admin",
    "portal",
    "secure",
    "support",
    "billing",
    "finance",
    "accounts",
    "autodiscover",
}


def load_config(path="config.yaml"):
    if Path(path).exists():
        return yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
    return {}


def _is_suspicious_subdomain(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in SUSPICIOUS_SUBDOMAIN_KEYWORDS)


def load_list(path: str) -> list[str]:
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def save_json(data, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _mask_secret(s: str, show_last: int = 2) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if len(s) <= show_last:
        return "*" * len(s)
    return "*" * (len(s) - show_last) + s[-show_last:]


def _parse_leaksearch_raw(raw: str) -> list[dict]:
    if not raw:
        return []
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "Username@Domain" in line or set(line) <= {"-", " "}:
            continue
        m = re.match(r"^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+(\S+)\s*$", line)
        if m:
            rows.append({"email": m.group(1), "password": m.group(2)})
    return rows


def score_finding(f: dict) -> tuple[int, str, str]:
    t = f.get("type", "")
    score = 0
    reason = ""

    if t == "leakcheck_public":
        found = int(f.get("found", 0) or 0)
        sources = f.get("sources", []) or []
        score = min(100, 70 + min(30, found * 5) + min(15, len(sources) * 5))
        reason = f"LeakCheck found={found}, sources={len(sources)}"

    elif t == "leak":
        score = 70
        reason = "LeakSearch hit (credential exposure)"

    elif t == "typosquat":
        score = 60
        reason = "Typosquat with active IP"

    elif t == "certificate_subdomain":
        sub = f.get("subdomain", "")
        if _is_suspicious_subdomain(sub):
            score = 60
            reason = "Suspicious subdomain keyword in certificate"
        else:
            score = 20
            reason = "Certificate subdomain (baseline needed)"

    elif t == "email_exposure":
        cnt = int(f.get("accounts_found", 0) or 0)
        if cnt >= 5:
            score = 50
        elif cnt >= 3:
            score = 35
        else:
            score = 15
        reason = f"Holehe accounts_found={cnt}"

    elif t in ("otx_domain", "otx_ipv4"):
        pc = int(f.get("pulse_count", 0) or 0)
        score = min(100, 40 + pc * 10)
        reason = f"OTX pulses={pc}"

    else:
        score = 10
        reason = "Unclassified"

    if score >= 85:
        sev = "critical"
    elif score >= 65:
        sev = "high"
    elif score >= 40:
        sev = "medium"
    else:
        sev = "low"

    return score, sev, reason


def normalize_and_filter(findings: list[dict], min_severity: str = "medium") -> list[dict]:
    sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = sev_rank[min_severity]
    filtered = []

    for f in findings:
        score, sev, reason = score_finding(f)
        f2 = dict(f)
        f2["score"] = score
        f2["severity"] = sev
        f2["reason"] = reason
        f2["ts"] = datetime.now(timezone.utc).isoformat()
        if sev_rank[sev] >= threshold:
            filtered.append(f2)

    filtered.sort(key=lambda x: x.get("score", 0), reverse=True)
    return filtered


def write_txt_report(findings: list[dict], out_path: str, mask_passwords: bool = True) -> None:
    sections = defaultdict(list)

    for f in findings:
        t = f.get("type", "unknown")
        if t == "typosquat":
            sections["DNSTwist (Typosquat)"].append(f)
        elif t == "leak":
            sections["LeakSearch (Leaks)"].append(f)
        elif t == "leakcheck_public":
            sections["LeakCheck (Public API)"].append(f)
        elif t == "email_exposure":
            sections["Holehe (Email Exposure)"].append(f)
        elif t == "certificate_subdomain":
            sections["crt.sh (Certificate Transparency)"].append(f)
        elif t == "harvester_emails":
            sections["theHarvester (Email Enumeration)"].append(f)
        elif t.startswith("otx_"):
            sections["OTX (Enrichment)"].append(f)
        else:
            sections["Outros"].append(f)

    lines = []
    lines.append("SOC-TI Report")
    lines.append("=" * 60)
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")

    order = [
        "LeakSearch (Leaks)",
        "LeakCheck (Public API)",
        "OTX (Enrichment)",
        "Holehe (Email Exposure)",
        "DNSTwist (Typosquat)",
        "crt.sh (Certificate Transparency)",
        "theHarvester (Email Enumeration)",
        "Outros",
    ]

    for sec in order:
        items = sections.get(sec, [])
        if not items:
            continue

        lines.append("")
        lines.append(sec)
        lines.append("-" * 60)
        lines.append(f"Count: {len(items)}")
        lines.append("")

        if sec == "LeakSearch (Leaks)":
            for i, it in enumerate(items, start=1):
                score = it.get("score")
                sev = it.get("severity")
                ts = it.get("ts")
                q = it.get("query")
                rows = _parse_leaksearch_raw(it.get("raw_output", ""))

                lines.append(f"[{i}] query={q} severity={sev} score={score} ts={ts}")
                if not rows:
                    lines.append("  (não foi possível extrair tabela)")
                    continue

                seen = set()
                for r in rows:
                    email = r["email"].lower()
                    if email in seen:
                        continue
                    seen.add(email)
                    pwd = r.get("password", "")
                    pwd = _mask_secret(pwd, 2) if mask_passwords else pwd
                    lines.append(f"  - {email} | password={pwd}")
                lines.append("")

        elif sec == "LeakCheck (Public API)":
            for i, it in enumerate(items, start=1):
                lines.append(
                    f"[{i}] {it.get('query')} | found={it.get('found')} | sources={len(it.get('sources', []) or [])} | severity={it.get('severity')} score={it.get('score')}"
                )
                for s in (it.get("sources") or [])[:20]:
                    lines.append(f"  - source: {s}")
                lines.append("")

        elif sec == "OTX (Enrichment)":
            for i, it in enumerate(items, start=1):
                lines.append(
                    f"[{i}] {it.get('type')} {it.get('indicator')} | pulses={it.get('pulse_count')} | severity={it.get('severity')} score={it.get('score')}"
                )
                for p in (it.get("pulses") or [])[:10]:
                    lines.append(f"  - pulse: {p.get('name')} (tlp={p.get('tlp')})")
                lines.append("")

        elif sec == "Holehe (Email Exposure)":
            for i, it in enumerate(items, start=1):
                lines.append(
                    f"[{i}] {it.get('email')} | accounts_found={it.get('accounts_found')} | severity={it.get('severity')} score={it.get('score')}"
                )
                for s in (it.get("services") or [])[:50]:
                    lines.append(f"  - {s}")
                lines.append("")

        elif sec == "DNSTwist (Typosquat)":
            for i, it in enumerate(items, start=1):
                lines.append(
                    f"[{i}] {it.get('original')} -> {it.get('domain')} | ip={it.get('ip')} | severity={it.get('severity')} score={it.get('score')}"
                )

        elif sec == "crt.sh (Certificate Transparency)":
            subs = sorted(
                set([it.get("subdomain") for it in items if it.get("subdomain")]),
                key=lambda x: x.lower(),
            )
            lines.append(f"Unique subdomains: {len(subs)}")
            for s in subs:
                tag = " (suspicious)" if _is_suspicious_subdomain(s) else ""
                lines.append(f"  - {s}{tag}")

        elif sec == "theHarvester (Email Enumeration)":
            for i, it in enumerate(items, start=1):
                domain = it.get("domain")
                emails = it.get("emails", []) or []
                sources = it.get("sources", []) or []
                lines.append(
                    f"[{i}] domain={domain} | emails={len(emails)} | sources={','.join(sources)}"
                )
                for e in emails[:120]:
                    lines.append(f"  - {e}")
                if len(emails) > 120:
                    lines.append(f"  ... (+{len(emails)-120} mais)")
                lines.append("")

        else:
            for i, it in enumerate(items, start=1):
                lines.append(f"[{i}] {it}")

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    domains = load_list("assets/domains.txt")
    seed_emails = load_list("assets/emails.txt") if Path("assets/emails.txt").exists() else []

    all_findings = []

    for d in domains:
        print(f"\n[+] Analisando: {d}")

        # Typosquat
        typos = scan_typosquat(d)
        print(f"  Typosquats encontrados: {len(typos)}")
        all_findings.extend(typos)

        # LeakSearch
        leaks = scan_leaksrch(d)
        print(f"  LeakSearch hits: {len(leaks)}")
        all_findings.extend(leaks)

        # Cert Monitor
        certs = scan_cert(d)
        print(f"  Cert subdomínios: {len(certs)}")
        all_findings.extend(certs)

        # theHarvester (emails)
        harv = scan_harvester(d)
        all_findings.extend(harv)

        harv_emails = []
        if harv and isinstance(harv, list) and harv[0].get("type") == "harvester_emails":
            harv_emails = harv[0].get("emails", [])
        print(f"  Emails via theHarvester: {len(harv_emails)}")

        # LeakCheck (public) -> consulta emails (seed + harvester)
        merged_emails = sorted(set(seed_emails + harv_emails))
        leakcheck_hits = scan_leakcheck(merged_emails)
        print(f"  LeakCheck hits: {len(leakcheck_hits)}")
        all_findings.extend(leakcheck_hits)

        # Holehe (prefixos comuns)
        holehe_hits = scan_holehe_domain(d)
        print(f"  Holehe hits: {len(holehe_hits)}")
        all_findings.extend(holehe_hits)

        # OTX enrichment (apenas no que faz sentido)
        # - IPs dos typosquats
        for t in typos:
            ip = t.get("ip")
            if ip:
                all_findings.extend(otx_ip(ip))

        # - subdomínios suspeitos do crt.sh
        for c in certs:
            sub = c.get("subdomain", "")
            if sub and _is_suspicious_subdomain(sub):
                all_findings.extend(otx_domain(sub))

        # Salvar raw + importante + TXT organizado
        save_json(all_findings, "output/soc_ti_raw.json")

        important = normalize_and_filter(all_findings, min_severity="medium")
        save_json(important, "output/soc_ti_important.json")

        # Relatórios TXT
        def write_txt_report(
            findings: list[dict], out_path: str, mask_passwords: bool = True

        ) -> None:
            """
            Relatório amplo:
            - Mostra TODAS as ferramentas (mesmo com 0)
            - Organiza por DOMÍNIO e por FERRAMENTA
            - Evita dump gigante (mostra amostra quando necessário)
            """
            # Index por domínio (quando existir)

        per_domain = defaultdict(list)

        def section(title: str) -> list[str]:
            return ["", title, "-" * 70]

    lines = []
    lines.append("SOC-TI Report (FULL)")
    lines.append("=" * 70)
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}Z")
    lines.append("")

    tool_order = [
        "LeakSearch (Leaks)",
        "LeakCheck (Public API)",
        "Holehe (Email Exposure)",
        "DNSTwist (Typosquat)",
        "crt.sh (Certificate Transparency)",
        "theHarvester (Email Enumeration)",
        "OTX (Enrichment)",
        "Outros",
    ]

    def classify_tool(f: dict) -> str:
        t = f.get("type", "unknown")
        if t == "leak":
            return "LeakSearch (Leaks)"
        if t == "leakcheck_public":
            return "LeakCheck (Public API)"
        if t == "email_exposure":
            return "Holehe (Email Exposure)"
        if t == "typosquat":
            return "DNSTwist (Typosquat)"
        if t == "certificate_subdomain":
            return "crt.sh (Certificate Transparency)"
        if t == "harvester_emails":
            return "theHarvester (Email Enumeration)"
        if t.startswith("otx_"):
            return "OTX (Enrichment)"
        return "Outros"

    # Para cada domínio, imprime todas as seções
    for dom in sorted(per_domain.keys(), key=lambda x: x.lower()):
        dom_findings = per_domain[dom]
        lines.append("")
        lines.append("#" * 70)
        lines.append(f"DOMAIN: {dom}")
        lines.append("#" * 70)

        # agrupa por ferramenta
        by_tool = defaultdict(list)
        for f in dom_findings:
            by_tool[classify_tool(f)].append(f)

        # sempre imprime todas as ferramentas (mesmo vazias)
        for tool in tool_order:
            items = by_tool.get(tool, [])
            lines.extend(section(tool))
            lines.append(f"Count: {len(items)}")

            if not items:
                lines.append("  - (no results)")
                continue

            # Impressão detalhada por ferramenta (com limites)
            if tool == "LeakSearch (Leaks)":
                for it in items:
                    q = it.get("query", dom)
                    rows = _parse_leaksearch_raw(it.get("raw_output", ""))
                    lines.append(f"  Query: {q} | extracted_rows={len(rows)}")
                    if not rows:
                        continue
                    seen = set()
                    for r in rows[:100]:
                        email = r["email"].lower()
                        if email in seen:
                            continue
                        seen.add(email)
                        pwd = r.get("password", "")
                        pwd = _mask_secret(pwd, 2) if mask_passwords else pwd
                        lines.append(f"    - {email} | password={pwd}")
                    if len(rows) > 100:
                        lines.append(f"    ... (+{len(rows)-100} more rows)")

            elif tool == "LeakCheck (Public API)":
                for it in items[:50]:
                    lines.append(
                        f"  - {it.get('query')} | found={it.get('found')} | sources={len(it.get('sources', []) or [])}"
                    )
                    for s in (it.get("sources") or [])[:10]:
                        lines.append(f"      - source: {s}")
                if len(items) > 50:
                    lines.append(f"  ... (+{len(items)-50} more)")

            elif tool == "Holehe (Email Exposure)":
                for it in items[:50]:
                    lines.append(
                        f"  - {it.get('email')} | accounts_found={it.get('accounts_found')}"
                    )
                    for s in (it.get("services") or [])[:15]:
                        lines.append(f"      - {s}")
                if len(items) > 50:
                    lines.append(f"  ... (+{len(items)-50} more)")

            elif tool == "DNSTwist (Typosquat)":
                for it in items[:100]:
                    lines.append(
                        f"  - {it.get('domain')} | ip={it.get('ip')} | original={it.get('original')}"
                    )
                if len(items) > 100:
                    lines.append(f"  ... (+{len(items)-100} more)")

            elif tool == "crt.sh (Certificate Transparency)":
                subs = sorted(
                    set([it.get("subdomain") for it in items if it.get("subdomain")]),
                    key=lambda x: x.lower(),
                )
                lines.append(f"  Unique subdomains: {len(subs)}")
                for s in subs[:200]:
                    tag = " (suspicious)" if _is_suspicious_subdomain(s) else ""
                    lines.append(f"    - {s}{tag}")
                if len(subs) > 200:
                    lines.append(f"    ... (+{len(subs)-200} more)")

            elif tool == "theHarvester (Email Enumeration)":
                # normalmente 1 item por domínio
                it = items[0]
                emails = it.get("emails", []) or []
                sources = it.get("sources", []) or []
                lines.append(f"  Sources: {', '.join(sources) if sources else '(none)'}")
                lines.append(f"  Emails: {len(emails)}")
                for e in emails[:200]:
                    lines.append(f"    - {e}")
                if len(emails) > 200:
                    lines.append(f"    ... (+{len(emails)-200} more)")

            elif tool == "OTX (Enrichment)":
                for it in items[:100]:
                    lines.append(
                        f"  - {it.get('type')} {it.get('indicator')} | pulse_count={it.get('pulse_count')}"
                    )
                    for p in (it.get("pulses") or [])[:5]:
                        lines.append(f"      - pulse: {p.get('name')} (tlp={p.get('tlp')})")
                if len(items) > 100:
                    lines.append(f"  ... (+{len(items)-100} more)")

            else:
                for it in items[:50]:
                    lines.append(f"  - {it}")
                if len(items) > 50:
                    lines.append(f"  ... (+{len(items)-50} more)")

        print("\n=== OK ===")
        print("output/soc_ti_report_important.txt")
        print("output/soc_ti_report_full.txt")


if __name__ == "__main__":
    main()
