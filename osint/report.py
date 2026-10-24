"""Report writers: JSON, Markdown, and HTML."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from . import __author__, __version__


def collect_findings(results: Dict[str, Any]) -> List[str]:
    findings: List[str] = []
    mail = results.get("mail_security") or {}
    findings += mail.get("findings", [])
    web = results.get("web") or {}
    findings += web.get("missing_security_headers", [])
    ssl_data = results.get("ssl") or {}
    findings += ssl_data.get("findings", [])
    for c in web.get("cookies", []) or []:
        if not c.get("secure"):
            findings.append(f"Cookie '{c['name']}' lacks the Secure flag.")
        if not c.get("httponly"):
            findings.append(f"Cookie '{c['name']}' lacks the HttpOnly flag.")
    return findings


def to_json(results: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")


def _md_value(v: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(v, dict):
        return "\n".join(f"{pad}- **{k}**: {_md_value(x, indent + 1).lstrip()}" for k, x in v.items())
    if isinstance(v, list):
        if not v:
            return "_none_"
        if all(not isinstance(x, (dict, list)) for x in v):
            return ", ".join(f"`{x}`" for x in v)
        return "\n".join(f"{pad}- {_md_value(x, indent + 1).lstrip()}" for x in v)
    return str(v)


def to_markdown(results: Dict[str, Any], path: Path) -> None:
    target = results["meta"]["target"]
    lines = [
        f"# OSINT Report: {target}",
        "",
        f"_Generated {results['meta']['generated']} by OSINT Research Toolkit v{__version__} - {__author__}_",
        "",
    ]
    findings = results.get("findings", [])
    lines += ["## Key Findings", ""]
    lines += [f"- {f}" for f in findings] if findings else ["- No notable issues detected."]
    lines.append("")
    for section, data in results.items():
        if section in ("meta", "findings") or not data:
            continue
        lines += [f"## {section.replace('_', ' ').title()}", "", _md_value(data), ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def to_html(results: Dict[str, Any], path: Path) -> None:
    target = html.escape(results["meta"]["target"])
    findings = results.get("findings", [])
    esc = html.escape

    sections = []
    for section, data in results.items():
        if section in ("meta", "findings") or not data:
            continue
        body = esc(json.dumps(data, indent=2, default=str))
        sections.append(f"<section><h2>{esc(section.replace('_', ' ').title())}</h2><pre>{body}</pre></section>")

    items = "".join(f"<li>{esc(f)}</li>" for f in findings) or "<li>No notable issues detected.</li>"
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Report - {target}</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#0f1419;color:#e6e6e6;margin:0;padding:2rem;line-height:1.5}}
 h1{{color:#4fd1c5}} h2{{color:#63b3ed;border-bottom:1px solid #2d3748;padding-bottom:.3rem}}
 section{{max-width:960px;margin:1.5rem auto}} header{{max-width:960px;margin:auto}}
 pre{{background:#1a202c;padding:1rem;border-radius:8px;overflow:auto;font-size:.85rem}}
 .findings{{background:#2d1f1f;border-left:4px solid #fc8181;padding:.5rem 1.5rem;border-radius:4px}}
 footer{{max-width:960px;margin:2rem auto;color:#718096;font-size:.8rem}}
</style></head><body>
<header><h1>OSINT Report: {target}</h1>
<p>Generated {esc(results['meta']['generated'])}</p></header>
<section><h2>Key Findings</h2><ul class="findings">{items}</ul></section>
{''.join(sections)}
<footer>OSINT Research Toolkit v{__version__} &middot; {esc(__author__)} &middot; passive public-source data only</footer>
</body></html>"""
    path.write_text(doc, encoding="utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
