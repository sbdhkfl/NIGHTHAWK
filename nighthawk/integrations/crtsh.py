"""crt.sh integration for passive subdomain discovery.

Used directly by the subdomains module; kept here for provider clarity.
"""

from __future__ import annotations

from typing import Any

import httpx

from nighthawk.modules.base import HttpClient, assert_outbound_safe


async def query_crtsh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh for certificates mentioning ``domain``.

    Returns a list of raw certificate entries (may be empty on failure).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    assert_outbound_safe(url)
    async with HttpClient() as client:
        try:
            response = await client.get(url, module="crtsh")
        except httpx.RequestError:
            return []
        if response.status_code != 200:
            return []
        try:
            return response.json()
        except ValueError:
            return []


__all__ = ["query_crtsh"]
