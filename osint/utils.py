"""Shared helpers: validation, HTTP session, logging."""

import logging
import re
import socket
from typing import Optional

import requests

USER_AGENT = "OSINT-Research-Toolkit/1.0 (+passive recon; by Mr. Sabaz Ali Khan)"
DEFAULT_TIMEOUT = 10

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE
)

log = logging.getLogger("osint")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def normalize_domain(value: str) -> str:
    """Strip scheme/path/port and lowercase. Raise ValueError if invalid."""
    v = value.strip().lower()
    v = re.sub(r"^[a-z]+://", "", v)
    v = v.split("/")[0].split(":")[0].rstrip(".")
    if not DOMAIN_RE.match(v):
        raise ValueError(f"Invalid domain: {value!r}")
    return v


def is_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def safe_get(
    sess: requests.Session, url: str, timeout: int = DEFAULT_TIMEOUT, **kw
) -> Optional[requests.Response]:
    try:
        return sess.get(url, timeout=timeout, **kw)
    except requests.RequestException as exc:
        log.debug("GET %s failed: %s", url, exc)
        return None
