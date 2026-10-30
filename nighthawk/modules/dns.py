"""DNS intelligence module.

Standalone DNS record resolution (A, AAAA, MX, NS, TXT, CNAME, SOA) exposed as
its own module for CLI/dashboard use.
"""

from __future__ import annotations

from typing import Any

from nighthawk.core.validation import validate_domain
from nighthawk.modules.base import resolve_dns


def run(domain: str, session=None) -> list[dict[str, Any]]:
    """Resolve DNS records for a domain.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    domain = validate_domain(domain)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    try:
        dns_results = resolve_dns(domain, record_types)
    except Exception as exc:  # pragma: no cover - defensive
        dns_results = {rt: [] for rt in record_types}
        error = str(exc)
    else:
        error = None

    dns_data = {rt: vals for rt, vals in dns_results.items() if vals}
    if not dns_data and not error:
        dns_data = {}
        message = "no DNS records discovered"
    else:
        message = None

    return [
        {
            "module": "dns",
            "target": domain,
            "result_data": {
                "dns": dns_data,
                "error": error,
                "message": message,
            },
            "source": f"dns://{domain}",
            "confidence": "high" if dns_data else "none",
        }
    ]


__all__ = ["run"]
