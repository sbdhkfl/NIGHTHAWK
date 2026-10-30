"""Defensive lookup against CISA's Known Exploited Vulnerabilities catalog.

This module looks up a CVE identifier in a public defensive feed. It does not
scan hosts, exploit vulnerabilities, or test systems.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any

import httpx

from nighthawk.modules.base import HttpClient

_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _fetch_catalog() -> dict[str, Any]:
    async with HttpClient(timeout=20) as client:
        try:
            response = await client.get(_FEED_URL, module="cisa-kev")
        except (httpx.RequestError, ValueError):
            return {"error": "CISA KEV feed request failed"}
        if response.status_code != 200:
            return {"error": f"CISA KEV feed returned HTTP {response.status_code}"}
        try:
            payload = response.json()
        except ValueError:
            return {"error": "CISA KEV feed returned invalid JSON"}
        return payload if isinstance(payload, dict) else {"error": "Unexpected CISA KEV format"}


def _catalog() -> dict[str, Any]:
    try:
        return asyncio.run(_fetch_catalog())
    except RuntimeError:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, _fetch_catalog()).result()


def run(cve_id: str, session=None) -> list[dict[str, Any]]:
    """Find a CVE in the public CISA Known Exploited Vulnerabilities catalog."""
    cve = cve_id.strip().upper()
    if len(cve) > 24 or not __import__("re").fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise ValueError("expected a CVE identifier such as CVE-2024-12345")
    payload = _catalog()
    if payload.get("error"):
        return [{
            "module": "kev", "target": cve,
            "result_data": {"error": payload["error"]},
            "source": _FEED_URL, "confidence": "none",
        }]
    match = next(
        (item for item in payload.get("vulnerabilities", [])
         if isinstance(item, dict) and item.get("cveID", "").upper() == cve),
        None,
    )
    data = {
        "listed_in_cisa_kev": bool(match),
        "catalog_date": payload.get("dateReleased"),
        "message": "CISA lists this CVE as known exploited." if match
                   else "CVE was not found in the current CISA KEV catalog.",
    }
    if match:
        for key in ("vendorProject", "product", "vulnerabilityName", "dateAdded",
                    "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse"):
            if key in match:
                data[key] = match[key]
    return [{
        "module": "kev", "target": cve, "result_data": data,
        "source": _FEED_URL, "confidence": "high",
    }]


__all__ = ["run"]
