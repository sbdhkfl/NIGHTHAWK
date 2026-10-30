"""Domain intelligence module.

Performs DNS lookups (A, AAAA, MX, NS, TXT, CNAME, SOA) and RDAP registration
lookup for a domain name.
"""

from __future__ import annotations

from typing import Any

from nighthawk.core.validation import validate_domain
from nighthawk.integrations.rdap import rdap_lookup
from nighthawk.modules.base import resolve_dns


def run(domain: str, session=None) -> list[dict[str, Any]]:
    """Run DNS and RDAP lookups for a domain.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    domain = validate_domain(domain)
    findings: list[dict[str, Any]] = []

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_error: str | None = None
    try:
        dns_results = resolve_dns(domain, record_types)
    except Exception as exc:  # pragma: no cover - defensive
        dns_results = {rt: [] for rt in record_types}
        dns_error = str(exc)

    dns_data = {rt: vals for rt, vals in dns_results.items() if vals}
    if dns_data or dns_error:
        findings.append(
            {
                "module": "domain",
                "target": domain,
                "result_data": {
                    "dns": dns_data,
                    "error": dns_error,
                },
                "source": f"dns://{domain}",
                "confidence": "high" if dns_data else "none",
            }
        )

    # RDAP registration information.
    try:
        rdap = rdap_lookup(domain)
    except Exception as exc:  # pragma: no cover - defensive
        rdap = {"error": str(exc)}

    rdap_data = {k: v for k, v in rdap.items() if v is not None and v != {}}
    if rdap_data:
        findings.append(
            {
                "module": "domain",
                "target": domain,
                "result_data": {"rdap": rdap_data},
                "source": rdap_data.get("rdap_url")
                or f"https://rdap.org/domain/{domain}",
                "confidence": "medium",
            }
        )

    if not findings:
        findings.append(
            {
                "module": "domain",
                "target": domain,
                "result_data": {
                    "dns": {},
                    "rdap": {},
                    "message": "no DNS or registration records discovered",
                },
                "source": f"dns://{domain}",
                "confidence": "none",
            }
        )

    return findings


__all__ = ["run"]
