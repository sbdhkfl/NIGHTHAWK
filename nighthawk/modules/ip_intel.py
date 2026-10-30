"""IP intelligence module.

Provides public network-registration and DNS intelligence only. Private,
loopback, multicast, link-local, reserved and otherwise non-global addresses
are never sent to external intelligence providers.
"""
from __future__ import annotations

import ipaddress
from typing import Any

import dns.resolver
import dns.reversename

from nighthawk.core.config import get_settings
from nighthawk.core.validation import is_private_or_reserved, validate_ip
from nighthawk.integrations.abuseipdb import check_ip_reputation
from nighthawk.integrations.rdap import rdap_lookup
from nighthawk.integrations.public_footprint import collect_public_search_findings


def _safe_reverse_dns(ip: str) -> list[str]:
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", raise_on_no_answer=False)
        return sorted({str(item).rstrip(".") for item in answers})
    except Exception:
        return []


def run(ip: str, session=None) -> list[dict[str, Any]]:
    """Run public IP registration and reverse-DNS lookups."""
    ip = validate_ip(ip)
    address = ipaddress.ip_address(ip)

    if is_private_or_reserved(ip) or not address.is_global:
        return [{
            "module": "ip", "target": ip,
            "result_data": {
                "error": "refused: address is not globally routable",
                "address_type": "private, loopback, link-local, multicast, reserved, or otherwise non-global",
                "note": "External intelligence lookups are not performed for non-public addresses.",
            },
            "source": None, "confidence": "none",
        }]

    findings: list[dict[str, Any]] = []
    reverse_dns = _safe_reverse_dns(ip)
    findings.append({
        "module": "ip", "target": ip,
        "result_data": {
            "version": address.version,
            "is_global": address.is_global,
            "is_multicast": address.is_multicast,
            "is_private": address.is_private,
            "reverse_dns": reverse_dns,
            "reverse_dns_found": bool(reverse_dns),
        },
        "source": f"dns://{ip}", "confidence": "high" if reverse_dns else "medium",
    })

    try:
        rdap = rdap_lookup(ip)
    except Exception:
        rdap = {"error": "RDAP provider request failed"}
    rdap_data = {k: v for k, v in rdap.items() if v is not None and v != {}}
    if rdap_data:
        network = {
            key: rdap_data.get(key)
            for key in ("startAddress", "endAddress", "ipVersion", "cidr0_cidr")
            if rdap_data.get(key)
        }
        organization = None
        for entity in rdap_data.get("entities", []):
            roles = [role.lower() for role in entity.get("roles", [])]
            if "registrant" in roles or organization is None:
                organization = entity.get("name") or organization
        findings.append({
            "module": "ip", "target": ip,
            "result_data": {
                "rdap": rdap_data,
                "organization": organization,
                "network_range": network or None,
                "asn_or_registry_handle": rdap_data.get("handle"),
                "registration_country": rdap_data.get("country"),
                "note": "Network registration data identifies an allocation or provider, not the individual using the address.",
            },
            "source": rdap_data.get("rdap_url") or f"https://rdap.org/ip/{ip}",
            "confidence": "medium",
        })

    api_key = get_settings().ABUSEIPDB_API_KEY
    if api_key:
        reputation = check_ip_reputation(ip, api_key)
        findings.append({
            "module": "ip", "target": ip,
            "result_data": {
                "abuseipdb": reputation,
                "interpretation": "Reputation scores are community/provider signals, not proof that an address is malicious.",
            },
            "source": "https://www.abuseipdb.com/", "confidence": "medium",
        })

    if len(findings) == 1 and not reverse_dns:
        findings.append({
            "module": "ip", "target": ip,
            "result_data": {"message": "No RDAP or reverse-DNS information was discovered."},
            "source": None, "confidence": "none",
        })
    findings.extend(collect_public_search_findings(
        ip, "ip", f'"{ip}"'
    ))
    return findings


__all__ = ["run"]
