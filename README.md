# OSINT Research Toolkit

A passive, public-source reconnaissance toolkit for domains and infrastructure, written in Python.

**Author:** Mr. Sabaz Ali Khan, Cyber Security Engineer

> Use only on domains you own or are explicitly authorized to assess.
> This tool uses public data sources (DNS, WHOIS, Certificate Transparency, public HTTP responses).
> It performs no port scanning, brute forcing, or exploitation.

## Features

| Module | What it does |
|---|---|
| `whois` | Registrar, creation/expiry dates, name servers, status |
| `dns` | A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records |
| `mail` | SPF, DMARC, common DKIM selectors, with weakness findings |
| `subdomains` | Passive discovery via crt.sh and HackerTarget |
| `ip` | Resolution, reverse DNS, ASN/org and geolocation (ipinfo.io) |
| `ssl` | Certificate issuer, SANs, expiry, TLS version |
| `web` | Security headers audit, tech fingerprinting, cookie flags, robots.txt, security.txt |

Reports are written as **JSON**, **Markdown**, and a dark-themed **HTML** file, with a consolidated "Key Findings" section.

## Install

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
# Full run
python osint_cli.py example.com

# Selected modules
python osint_cli.py example.com -m dns mail ssl

# Only an HTML report, custom folder
python osint_cli.py example.com -f html -o out/

# Verbose
python osint_cli.py example.com -v
```

Reports land in `reports/<domain>.{json,md,html}`.

## Project layout

```
osint-research/
├── osint_cli.py          # CLI entry point
├── requirements.txt
├── README.md
└── osint/
    ├── __init__.py
    ├── utils.py          # validation, HTTP session, logging
    ├── whois_lookup.py
    ├── dns_recon.py
    ├── subdomains.py
    ├── ip_intel.py
    ├── ssl_info.py
    ├── web_recon.py
    └── report.py         # JSON / Markdown / HTML writers
```

## Extending

Add a module under `osint/`, expose a function that returns a dict or list, then register it in `run()` and `MODULES` inside `osint_cli.py`.

## Legal

You are responsible for complying with applicable laws and the terms of the third-party services queried (crt.sh, ipinfo.io, HackerTarget). Obtain written authorization before assessing systems you do not own.
