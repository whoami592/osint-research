"""IP / infrastructure intelligence using free public endpoints."""

import socket
from typing import Any, Dict, List

from .utils import is_ip, safe_get, session


def resolve(domain: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def ip_info(ip: str) -> Dict[str, Any]:
    """Geo/ASN data from ipinfo.io (free, no key, rate limited)."""
    if not is_ip(ip):
        return {"error": "not an IP"}
    resp = safe_get(session(), f"https://ipinfo.io/{ip}/json")
    info: Dict[str, Any] = {"ip": ip, "reverse_dns": reverse_dns(ip)}
    if resp is not None and resp.status_code == 200:
        d = resp.json()
        for k in ("org", "city", "region", "country", "timezone", "hostname"):
            if d.get(k):
                info[k] = d[k]
    return info


def analyze_domain_ips(domain: str) -> List[Dict[str, Any]]:
    return [ip_info(ip) for ip in resolve(domain)]
