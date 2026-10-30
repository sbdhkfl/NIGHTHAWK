"""Have I Been Pwned integration.

Only used when the user explicitly configures HIBP_API_KEY. The email address
is sent to HIBP's API (with user authorization via the configured key) to check
whether it appears in known breaches. Passwords are never sent or stored.
"""

from __future__ import annotations

from typing import Any

import httpx

from nighthawk.modules.base import HttpClient, assert_outbound_safe

_HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


def hibp_lookup(email: str, api_key: str) -> dict[str, Any]:
    """Check HIBP for breaches involving ``email``.

    Returns a dict with breach summary or an error key. Empty dict on failure.
    Requires an API key (user authorization).
    """
    assert_outbound_safe(_HIBP_URL.format(email=email))
    headers = {
        "User-Agent": "NIGHTHAWK-OSINT/1.0.0",
        "hibp-api-key": api_key,
    }
    import asyncio

    async def _fetch() -> dict[str, Any]:
        async with HttpClient() as client:
            try:
                response = await client.get(
                    _HIBP_URL.format(email=email), module="hibp", extra_headers=headers
                )
            except httpx.RequestError:
                return {"error": "network error contacting HIBP"}
            if response.status_code == 404:
                return {"breaches": [], "count": 0, "message": "no breaches found for this email"}
            if response.status_code == 401:
                return {"error": "unauthorized: invalid HIBP API key"}
            if response.status_code == 429:
                return {"error": "rate limited by HIBP"}
            if response.status_code != 200:
                return {"error": f"HIBP returned HTTP {response.status_code}"}
            try:
                breaches = response.json()
            except ValueError:
                return {"error": "unable to parse HIBP response"}
            summary = [
                {
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                }
                for b in breaches
                if isinstance(b, dict)
            ]
            return {"breaches": summary, "count": len(summary)}

    try:
        return asyncio.run(_fetch())
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _fetch())
            return future.result()


__all__ = ["hibp_lookup"]
