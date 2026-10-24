"""Passive subdomain discovery via Certificate Transparency logs (crt.sh).

No packets are sent to the target - only public CT data is queried.
"""

from typing import List

from .utils import log, safe_get, session


def from_crtsh(domain: str, timeout: int = 30) -> List[str]:
    sess = session()
    resp = safe_get(sess, "https://crt.sh/", timeout=timeout,
                    params={"q": f"%.{domain}", "output": "json"})
    if resp is None or resp.status_code != 200:
        log.warning("crt.sh unavailable or returned an error")
        return []
    try:
        entries = resp.json()
    except ValueError:
        log.warning("crt.sh returned non-JSON data")
        return []

    found = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                found.add(name)
    return sorted(found)


def from_hackertarget(domain: str) -> List[str]:
    """Secondary passive source (free tier, rate limited)."""
    sess = session()
    resp = safe_get(sess, "https://api.hackertarget.com/hostsearch/", params={"q": domain})
    if resp is None or resp.status_code != 200 or "error" in resp.text[:30].lower():
        return []
    return sorted({line.split(",")[0].lower() for line in resp.text.splitlines() if "," in line})


def discover(domain: str) -> List[str]:
    names = set(from_crtsh(domain)) | set(from_hackertarget(domain))
    return sorted(names)
