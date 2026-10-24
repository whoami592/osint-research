"""TLS certificate inspection (a normal TLS handshake on port 443)."""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict


def inspect(domain: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"Certificate verification failed: {exc.verify_message}"}
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}

    def flat(rdn):
        return {k: v for t in rdn for k, v in t}

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    findings = []
    if days_left < 0:
        findings.append("Certificate is EXPIRED.")
    elif days_left < 30:
        findings.append(f"Certificate expires soon ({days_left} days).")
    if version in ("TLSv1", "TLSv1.1"):
        findings.append(f"Outdated protocol negotiated: {version}.")

    return {
        "subject": flat(cert.get("subject", ())),
        "issuer": flat(cert.get("issuer", ())),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "days_left": days_left,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "san": sans,
        "findings": findings,
    }
