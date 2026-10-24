"""DNS reconnaissance: records, mail-security posture (SPF / DMARC / DKIM hints)."""

from typing import Dict, List

try:
    import dns.exception
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:  # degrade gracefully; see README
    HAVE_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = 5
    r.timeout = 3
    return r


def query(name: str, rtype: str) -> List[str]:
    if not HAVE_DNSPYTHON:
        return []
    try:
        answers = _resolver().resolve(name, rtype)
        return sorted(a.to_text().strip('"') for a in answers)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


def get_records(domain: str) -> Dict[str, object]:
    if not HAVE_DNSPYTHON:
        return {"error": "dnspython not installed (pip install dnspython)"}
    return {rt: query(domain, rt) for rt in RECORD_TYPES}


def mail_security(domain: str) -> Dict[str, object]:
    """Inspect SPF, DMARC, and common DKIM selectors (public DNS only)."""
    if not HAVE_DNSPYTHON:
        return {"error": "dnspython not installed (pip install dnspython)", "findings": []}
    txt = query(domain, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = [t for t in query(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]

    dkim = {}
    for sel in COMMON_DKIM_SELECTORS:
        res = query(f"{sel}._domainkey.{domain}", "TXT")
        if res:
            dkim[sel] = res[0][:80] + ("..." if len(res[0]) > 80 else "")

    findings = []
    if not spf:
        findings.append("No SPF record found - domain can be spoofed more easily.")
    elif any(s.endswith("+all") for s in spf):
        findings.append("SPF uses '+all' - effectively allows any sender.")
    elif any(s.endswith("?all") for s in spf):
        findings.append("SPF uses '?all' (neutral) - weak policy.")
    if not dmarc:
        findings.append("No DMARC record found.")
    else:
        d = dmarc[0].lower().replace(" ", "")
        if "p=none" in d:
            findings.append("DMARC policy is 'none' (monitoring only, no enforcement).")

    return {"spf": spf, "dmarc": dmarc, "dkim_selectors_found": dkim, "findings": findings}
