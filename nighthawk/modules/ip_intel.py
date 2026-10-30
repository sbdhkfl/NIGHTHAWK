"""IP intelligence module.

Validates IPv4/IPv6 addresses, rejects private/loopback/multicast/reserved
addresses for external lookups, performs RDAP lookup, reverse DNS, and
reports network/registration information.

Never claims precise physical geolocation from an IP address.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import dns.resolver
import dns.reversename

from nighthawk.core.validation import is_private_or_reserved, validate_ip
from nighthawk.integrations.rdap import rdap_lookup


def run(ip: str, session=None) -> list[dict[str, Any]]:
    """Run IP intelligence lookups.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    ip = validate_ip(ip)

    if is_private_or_reserved(ip):
        return [
            {
                "module": "ip",
                "target": ip,
                "result_data": {
                    "error": "refused: private, loopback, multicast or reserved address",
                    "note": "external intelligence lookups are not performed for non-public addresses",
                },
                "source": None,
                "confidence": "none",
            }
        ]

    findings: list[dict[str, Any]] = []

    # Reverse DNS.
    reverse_dns: list[str] = []
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", raise_on_no_answer=False)
        reverse_dns = [str(rdata).rstrip(".") for rdata in answers]
    except Exception:  # pragma: no cover - best effort
        reverse_dns = []

    findings.append(
        {
            "module": "ip",
            "target": ip,
            "result_data": {
                "version": ipaddress.ip_address(ip).version,
                "reverse_dns": reverse_dns,
            },
            "source": f"dns://{ip}",
            "confidence": "high" if reverse_dns else "medium",
        }
    )

    # RDAP registration / ASN / network range.
    try:
        rdap = rdap_lookup(ip)
    except Exception as exc:  # pragma: no cover - defensive
        rdap = {"error": str(exc)}

    rdap_data = {k: v for k, v in rdap.items() if v is not None and v != {}}
    if rdap_data:
        network = {
            k: rdap_data.get(k)
            for k in ("startAddress", "endAddress", "ipVersion", "cidr0_cidr")
            if rdap_data.get(k)
        }
        org = None
        for entity in rdap_data.get("entities", []):
            if "registrant" in [r.lower() for r in entity.get("roles", [])] or org is None:
                org = entity.get("name") or org
        findings.append(
            {
                "module": "ip",
                "target": ip,
                "result_data": {
                    "rdap": rdap_data,
                    "organization": org,
                    "network_range": network or None,
                    "asn": rdap_data.get("handle"),
                },
                "source": rdap_data.get("rdap_url") or f"https://rdap.org/ip/{ip}",
                "confidence": "medium",
                "note": "country-level registration info only; no precise geolocation claimed",
            }
        )

    if not findings:
        findings.append(
            {
                "module": "ip",
                "target": ip,
                "result_data": {
                    "message": "no registration or reverse-DNS data discovered",
                },
                "source": None,
                "confidence": "none",
            }
        )

    return findings


__all__ = ["run"]
