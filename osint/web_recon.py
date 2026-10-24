"""Web reconnaissance: HTTP security headers, tech hints, robots.txt, security.txt."""

import re
from typing import Any, Dict, Optional

from .utils import safe_get, session

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing - downgrade/MITM risk.",
    "content-security-policy": "CSP missing - weaker XSS mitigation.",
    "x-frame-options": "X-Frame-Options missing - clickjacking risk (unless CSP frame-ancestors is set).",
    "x-content-type-options": "X-Content-Type-Options missing - MIME sniffing risk.",
    "referrer-policy": "Referrer-Policy missing.",
    "permissions-policy": "Permissions-Policy missing.",
}

TECH_SIGNATURES = {
    "WordPress": r"wp-content|wp-includes",
    "Drupal": r"Drupal\.settings|sites/default/files",
    "Joomla": r"/media/jui/|Joomla!",
    "Shopify": r"cdn\.shopify\.com",
    "Wix": r"static\.wixstatic\.com",
    "React": r"data-reactroot|react\.production",
    "Angular": r"ng-version=",
    "Vue.js": r"vue(\.min)?\.js|data-v-",
    "jQuery": r"jquery[-.]?\d*(\.min)?\.js",
    "Bootstrap": r"bootstrap(\.min)?\.(css|js)",
    "Cloudflare": r"cloudflare",
}


def fetch_site(domain: str) -> Dict[str, Any]:
    sess = session()
    resp: Optional[object] = None
    for scheme in ("https", "http"):
        resp = safe_get(sess, f"{scheme}://{domain}", allow_redirects=True)
        if resp is not None:
            break
    if resp is None:
        return {"error": "Site unreachable on HTTP/HTTPS"}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [msg for h, msg in SECURITY_HEADERS.items() if h not in headers]

    body = resp.text[:200_000] if resp.text else ""
    tech = [name for name, pat in TECH_SIGNATURES.items()
            if re.search(pat, body, re.I) or re.search(pat, str(headers), re.I)]

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)

    return {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "title": title_match.group(1).strip()[:150] if title_match else None,
        "generator": generator.group(1) if generator else None,
        "technologies": sorted(set(tech)),
        "redirect_chain": [r.url for r in resp.history],
        "missing_security_headers": missing,
        "cookies": [
            {"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr("HttpOnly")}
            for c in resp.cookies
        ],
    }


def well_known_files(domain: str) -> Dict[str, Any]:
    sess = session()
    out: Dict[str, Any] = {}
    for path in ("/robots.txt", "/.well-known/security.txt", "/sitemap.xml"):
        resp = safe_get(sess, f"https://{domain}{path}", allow_redirects=False)
        if resp is not None and resp.status_code == 200 and resp.text.strip():
            out[path] = resp.text[:1500]
    return out
