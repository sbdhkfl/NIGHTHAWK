"""RDAP integration for domain and IP registration lookup.

Uses the public RDAP protocol (https://rdap.org / IANA bootstrap) to look up
registration data for domains and IP addresses. No API key required.
"""

from __future__ import annotations

from typing import Any

import httpx

from nighthawk.modules.base import HttpClient, assert_outbound_safe

_RDAP_BOOTSTRAP = "https://rdap.org"


def _sanitize_rdap_object(obj: dict[str, Any]) -> dict[str, Any]:
    """Keep only safe, human-readable fields from an RDAP JSON response."""
    if not isinstance(obj, dict):
        return {}
    safe: dict[str, Any] = {}
    for key in (
        "handle", "name", "type", "status", "port43", "lang",
        "startAddress", "endAddress", "ipVersion", "cidr0_cidr",
    ):
        if key in obj:
            safe[key] = obj[key]
    # Dates
    for key in ("registrationDate", "updatedDate", "expirationDate"):
        if key in obj:
            safe[key] = obj[key]
    # Entities (registrar / registrant / tech) names and roles
    entities = obj.get("entities")
    if isinstance(entities, list):
        safe_entities = []
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            vcard_array = entity.get("vcardArray")
            name = None
            roles = entity.get("roles", [])
            if isinstance(vcard_array, list) and len(vcard_array) > 1:
                for item in vcard_array[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        name = item[3]
            safe_entities.append(
                {"name": name, "roles": roles if isinstance(roles, list) else []}
            )
        safe["entities"] = safe_entities
    # Nameservers
    ns = obj.get("nameservers")
    if isinstance(ns, list):
        safe["nameservers"] = [
            {"ldn": n.get("ldn"), "ipAddresses": n.get("ipAddresses", [])}
            for n in ns
            if isinstance(n, dict)
        ]
    return safe


async def _fetch_json(url: str) -> dict[str, Any] | None:
    assert_outbound_safe(url)
    async with HttpClient() as client:
        try:
            response = await client.get(url, module="rdap")
        except httpx.RequestError:
            return None
        if response.status_code != 200:
            return None
        try:
            return response.json()
        except ValueError:
            return None


async def _rdap_query(target: str) -> dict[str, Any]:
    """Query RDAP for a domain or IP, returning a sanitized result dict."""
    url = f"{_RDAP_BOOTSTRAP}/{target}"
    data = await _fetch_json(url)
    if data is None:
        return {"target": target, "rdap_url": url, "error": "no response from RDAP server"}
    return {"target": target, "rdap_url": url, **_sanitize_rdap_object(data)}


def rdap_lookup(target: str) -> dict[str, Any]:
    """Look up registration data for a domain or IP via RDAP.

    Returns a dict with sanitized fields. Empty dict means no usable data.
    """
    import asyncio

    try:
        return asyncio.run(_rdap_query(target))
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _rdap_query(target))
            return future.result()


__all__ = ["rdap_lookup"]
