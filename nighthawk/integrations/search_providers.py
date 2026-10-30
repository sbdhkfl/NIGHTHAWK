"""Optional public search provider integrations.

Supports Brave Search and Tavily via API keys loaded from environment
variables (via nighthawk.core.config). No credentials are hardcoded and no
search engine scraping is performed.
"""

from __future__ import annotations

from typing import Any

import httpx

from nighthawk.core.config import get_settings
from nighthawk.modules.base import HttpClient, assert_outbound_safe


def _brave_search(query: str) -> list[dict[str, Any]]:
    settings = get_settings()
    api_key = settings.BRAVE_SEARCH_API_KEY
    if not api_key:
        return []
    assert_outbound_safe("https://api.search.brave.com")
    import asyncio

    async def _fetch() -> list[dict[str, Any]]:
        async with HttpClient() as client:
            try:
                response = await client.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    params={"q": query, "count": 10},
                    headers={
                        "Accept": "application/json",
                        "X-Subscription-Token": api_key,
                    },
                    module="brave",
                )
            except httpx.RequestError:
                return []
            if response.status_code != 200:
                return []
            try:
                data = response.json()
            except ValueError:
                return []
            results = []
            for item in data.get("web", {}).get("results", []):
                results.append(
                    {
                        "provider": "Brave Search",
                        "title": item.get("title"),
                        "url": item.get("url"),
                        "snippet": item.get("description"),
                    }
                )
            return results

    try:
        return asyncio.run(_fetch())
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _fetch())
            return future.result()


def _tavily_search(query: str) -> list[dict[str, Any]]:
    settings = get_settings()
    api_key = settings.TAVILY_API_KEY
    if not api_key:
        return []
    assert_outbound_safe("https://api.tavily.com")

    import asyncio

    async def _fetch() -> list[dict[str, Any]]:
        async with HttpClient() as client:
            try:
                response = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "max_results": 10,
                    },
                    headers={"Content-Type": "application/json"},
                    module="tavily",
                )
            except httpx.RequestError:
                return []
            if response.status_code != 200:
                return []
            try:
                data = response.json()
            except ValueError:
                return []
            results = []
            for item in data.get("results", []):
                results.append(
                    {
                        "provider": "Tavily",
                        "title": item.get("title"),
                        "url": item.get("url"),
                        "snippet": item.get("content"),
                    }
                )
            return results

    try:
        return asyncio.run(_fetch())
    except RuntimeError:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _fetch())
            return future.result()


def search_all_providers(query: str) -> list[dict[str, Any]]:
    """Run the query across all configured search providers and merge results."""
    results: list[dict[str, Any]] = []
    results.extend(_brave_search(query))
    results.extend(_tavily_search(query))
    return results


__all__ = ["search_all_providers"]
