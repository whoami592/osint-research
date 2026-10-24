#!/usr/bin/env python3
"""OSINT Research Toolkit - command line interface.

Passive, public-source reconnaissance for domains you own or are
authorized to assess.

Author: Mr. Sabaz Ali Khan (Cyber Security Engineer)
"""

import argparse
import sys
from pathlib import Path

from osint import __author__, __version__
from osint import dns_recon, ip_intel, report, ssl_info, subdomains, web_recon, whois_lookup
from osint.utils import log, normalize_domain, setup_logging

BANNER = rf"""
   ___  ____ ___ _   _ _____   ____                               _
  / _ \/ ___|_ _| \ | |_   _| |  _ \ ___  ___  ___  __ _ _ __ ___| |__
 | | | \___ \| ||  \| | | |   | |_) / _ \/ __|/ _ \/ _` | '__/ __| '_ \
 | |_| |___) | || |\  | | |   |  _ <  __/\__ \  __/ (_| | | | (__| | | |
  \___/|____/___|_| \_| |_|   |_| \_\___||___/\___|\__,_|_|  \___|_| |_|

  OSINT Research Toolkit v{__version__}  |  by {__author__}
  Passive recon only - use on authorized targets.
"""

MODULES = ["whois", "dns", "mail", "subdomains", "ip", "ssl", "web"]


def run(domain: str, modules: list) -> dict:
    results = {"meta": {"target": domain, "generated": report.now_iso(), "modules": modules}}

    if "whois" in modules:
        log.info("WHOIS lookup")
        results["whois"] = whois_lookup.lookup(domain)
    if "dns" in modules:
        log.info("DNS records")
        results["dns"] = dns_recon.get_records(domain)
    if "mail" in modules:
        log.info("Mail security (SPF/DMARC/DKIM)")
        results["mail_security"] = dns_recon.mail_security(domain)
    if "subdomains" in modules:
        log.info("Passive subdomain discovery (CT logs)")
        results["subdomains"] = subdomains.discover(domain)
    if "ip" in modules:
        log.info("IP intelligence")
        results["ip_intel"] = ip_intel.analyze_domain_ips(domain)
    if "ssl" in modules:
        log.info("TLS certificate")
        results["ssl"] = ssl_info.inspect(domain)
    if "web" in modules:
        log.info("Web headers and technology hints")
        results["web"] = web_recon.fetch_site(domain)
        results["well_known_files"] = web_recon.well_known_files(domain)

    results["findings"] = report.collect_findings(results)
    return results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint_cli",
        description="Passive OSINT research toolkit for domains and infrastructure.",
    )
    p.add_argument("target", help="Domain to research, e.g. example.com")
    p.add_argument("-m", "--modules", nargs="+", choices=MODULES + ["all"], default=["all"],
                   help="Modules to run (default: all)")
    p.add_argument("-o", "--output", default="reports", help="Output directory (default: reports)")
    p.add_argument("-f", "--formats", nargs="+", choices=["json", "md", "html"],
                   default=["json", "md", "html"], help="Report formats")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--no-banner", action="store_true", help="Hide banner")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main() -> int:
    args = build_parser().parse_args()
    setup_logging(args.verbose)
    if not args.no_banner:
        print(BANNER)

    try:
        domain = normalize_domain(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    modules = MODULES if "all" in args.modules else args.modules
    log.info("Target: %s | modules: %s", domain, ", ".join(modules))

    try:
        results = run(domain, modules)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    stem = domain.replace(".", "_")
    if "json" in args.formats:
        report.to_json(results, out / f"{stem}.json")
    if "md" in args.formats:
        report.to_markdown(results, out / f"{stem}.md")
    if "html" in args.formats:
        report.to_html(results, out / f"{stem}.html")

    print(f"\nDone. {len(results['findings'])} finding(s). Reports saved in: {out.resolve()}")
    for f in results["findings"][:10]:
        print(f"  - {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
