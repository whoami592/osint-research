"""WHOIS lookup for domains (registrar-level public data)."""

from typing import Any, Dict

try:
    import whois  # python-whois
except ImportError:  # pragma: no cover
    whois = None


def _clean(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        return [_clean(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def lookup(domain: str) -> Dict[str, Any]:
    if whois is None:
        return {"error": "python-whois not installed (pip install python-whois)"}
    try:
        data = whois.whois(domain)
    except Exception as exc:  # whois raises many exception types
        return {"error": str(exc)}

    keys = [
        "registrar", "creation_date", "expiration_date", "updated_date",
        "name_servers", "status", "dnssec", "org", "country", "emails",
    ]
    return {k: _clean(data.get(k)) for k in keys if data.get(k)}
