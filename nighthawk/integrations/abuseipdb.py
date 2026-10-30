"""Optional AbuseIPDB reputation integration.

The IP is submitted only when the user explicitly configures ABUSEIPDB_API_KEY.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx

from nighthawk.modules.base import HttpClient

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip: str, api_key: str) -> dict[str, Any]:
    query = urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""})
    url = f"{_ENDPOINT}?{query}"

    async def _fetch() -> dict[str, Any]:
        async with HttpClient(timeout=12) as client:
            try:
                response = await client.get(
                    url, module="abuseipdb",
                    extra_headers={"Key": api_key, "Accept": "application/json"},
                )
            except (httpx.RequestError, ValueError):
                return {"error": "AbuseIPDB request failed"}
            if response.status_code != 200:
                return {"error": f"AbuseIPDB returned HTTP {response.status_code}"}
            try:
                data = response.json().get("data", {})
            except (ValueError, AttributeError):
                return {"error": "Invalid AbuseIPDB response"}
            # Keep a conservative subset; omit reporter identities and comments.
            return {
                key: data.get(key) for key in (
                    "ipAddress", "isPublic", "ipVersion", "isWhitelisted",
                    "abuseConfidenceScore", "countryCode", "usageType",
                    "isp", "domain", "totalReports", "numDistinctUsers",
                ) if data.get(key) is not None
            }

    import asyncio
    try:
        return asyncio.run(_fetch())
    except RuntimeError:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, _fetch()).result()


__all__ = ["check_ip_reputation"]
