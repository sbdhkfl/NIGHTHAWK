"""Opt-in public-web reference discovery for authorized self-audits.

This integration sends the supplied identifier to configured search providers
only when NIGHTHAWK_ENABLE_PUBLIC_SEARCH=true. Results are leads, never proof
of account ownership or identity.
"""
from __future__ import annotations

from typing import Any

from nighthawk.core.config import get_settings
from nighthawk.integrations.search_providers import search_all_providers


def collect_public_search_findings(
    target: str, module: str, query: str
) -> list[dict[str, Any]]:
    """Return a small, deduplicated set of public search references.

    Search providers receive the query. This is disabled by default because
    identifiers such as email addresses and usernames can be personal data.
    """
    settings = get_settings()
    if not settings.ENABLE_PUBLIC_SEARCH:
        return []

    try:
        results = search_all_providers(query)
    except Exception:
        return [{
            "module": module,
            "target": target,
            "result_data": {
                "search_status": "provider_error",
                "message": "Configured public search provider request failed.",
            },
            "source": None,
            "confidence": "none",
        }]

    findings: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for item in results:
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        findings.append({
            "module": module,
            "target": target,
            "result_data": {
                "match_type": "possible_public_reference",
                "provider": item.get("provider"),
                "title": item.get("title"),
                "url": url,
                "snippet": item.get("snippet"),
                "interpretation": (
                    "A search result contains or relates to the query. "
                    "It does not prove account ownership, identity, or current control."
                ),
            },
            "source": url,
            "confidence": "low",
        })
        if len(findings) >= 8:
            break

    if not findings:
        return [{
            "module": module,
            "target": target,
            "result_data": {
                "search_status": "no_results",
                "message": "No public search references were returned by configured providers.",
            },
            "source": None,
            "confidence": "none",
        }]
    return findings


__all__ = ["collect_public_search_findings"]
