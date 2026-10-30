"""Subdomain intelligence module.

Passive subdomain discovery using Certificate Transparency logs via crt.sh.
Results are deduplicated, with source and timestamp recorded. Optional DNS
resolution is performed for each discovered subdomain.
"""

from __future__ import annotations

from typing import Any

import httpx

from nighthawk.core.validation import validate_domain
from nighthawk.modules.base import HttpClient, resolve_dns


async def _fetch_crtsh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh for certificates mentioning the domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with HttpClient() as client:
        try:
            response = await client.get(url, module="subdomains")
        except httpx.RequestError:  # type: ignore[name-defined]
            return []
        if response.status_code != 200:
            return []
        try:
            return response.json()
        except ValueError:
            return []


def run(domain: str, session=None) -> list[dict[str, Any]]:
    """Passively discover subdomains via crt.sh Certificate Transparency data.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    import asyncio

    domain = validate_domain(domain)

    try:
        entries = asyncio.run(_fetch_crtsh(domain))
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _fetch_crtsh(domain))
            entries = future.result()

    # Deduplicate by subdomain name, keeping earliest timestamp.
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries or []:
        name_value = entry.get("name_value") or entry.get("common_name") or ""
        for name in str(name_value).split("\n"):
            name = name.strip().lower().rstrip(".")
            if not name or name == domain or not name.endswith("." + domain):
                continue
            if name not in seen:
                seen[name] = {
                    "subdomain": name,
                    "source": "crt.sh",
                    "timestamp": entry.get("entry_timestamp") or entry.get("not_before"),
                    "issuer": entry.get("issuer_name"),
                }

    results = []
    for subdomain, info in sorted(seen.items()):
        # Optional DNS resolution.
        resolved = []
        try:
            dns = resolve_dns(subdomain, ["A", "AAAA", "CNAME"])
            resolved = {rt: vals for rt, vals in dns.items() if vals}
        except Exception:  # pragma: no cover - resolution is optional
            resolved = {}

        results.append(
            {
                "module": "subdomains",
                "target": domain,
                "result_data": {
                    "subdomain": subdomain,
                    "resolved": resolved,
                    **info,
                },
                "source": "https://crt.sh/",
                "confidence": "medium",
            }
        )

    if not results:
        results.append(
            {
                "module": "subdomains",
                "target": domain,
                "result_data": {
                    "subdomains": [],
                    "message": "no subdomains discovered via Certificate Transparency",
                },
                "source": "https://crt.sh/",
                "confidence": "none",
            }
        )

    return results


__all__ = ["run"]
