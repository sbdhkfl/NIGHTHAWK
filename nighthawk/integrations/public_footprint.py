"""API-free links for manual public-page email footprint checks.

NIGHTHAWK does not call a search API for email lookups. The user's browser
sends the query to the search engine only if a generated link is opened.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from nighthawk.core.config import get_settings
from nighthawk.integrations.search_providers import search_all_providers


EMAIL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "social_media": ("facebook.com", "instagram.com", "reddit.com", "x.com", "linkedin.com", "pinterest.com", "tiktok.com"),
    "developer": ("github.com", "gitlab.com", "stackoverflow.com", "dev.to", "codeberg.org", "sourcehut.org"),
    "professional_and_portfolio": ("linkedin.com", "medium.com", "about.me", "substack.com"),
    "forums_and_communities": ("reddit.com", "discourse.org", "community.", "groups.google.com"),
    "gaming_and_streaming": ("twitch.tv", "steamcommunity.com", "itch.io", "youtube.com"),
}


def collect_email_public_references(email: str) -> list[dict[str, Any]]:
    """Create category-specific search links without using an API."""
    findings: list[dict[str, Any]] = []
    for category, sites in EMAIL_CATEGORIES.items():
        site_query = " OR ".join(f"site:{site}" for site in sites)
        query = f'"{email}" ({site_query})'
        search_url = "https://www.google.com/search?" + urlencode({"q": query})
        findings.append({
            "module": "email_public",
            "target": email,
            "result_data": {
                "category": category,
                "status": "manual_search",
                "search_engine": "Google",
                "search_url": search_url,
                "query": query,
                "message": "Open the link and review results manually. A result is not proof of account registration.",
                "privacy": "NIGHTHAWK makes no API request. Google receives the email query only if you open the link.",
            },
            "source": search_url,
            "confidence": "none",
        })
    return findings


def collect_public_search_findings(target: str, module: str, query: str) -> list[dict[str, Any]]:
    """Generic opt-in public-page search used by non-email modules."""
    settings = get_settings()
    if not settings.ENABLE_PUBLIC_SEARCH:
        return []
    if not (settings.BRAVE_SEARCH_API_KEY or settings.TAVILY_API_KEY):
        return [{
            "module": module,
            "target": target,
            "result_data": {"search_status": "provider_not_configured", "message": "Configure BRAVE_SEARCH_API_KEY or TAVILY_API_KEY."},
            "source": None,
            "confidence": "none",
        }]
    try:
        results = search_all_providers(query)
    except Exception:
        results = []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in results:
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")) or url in seen:
            continue
        seen.add(url)
        findings.append({
            "module": module,
            "target": target,
            "result_data": {
                "match_type": "possible_public_reference",
                "provider": item.get("provider"),
                "title": item.get("title"),
                "url": url,
                "snippet": item.get("snippet"),
                "interpretation": "A public search result is a lead only; it does not establish identity, account ownership, or current account access.",
            },
            "source": url,
            "confidence": "low",
        })
        if len(findings) >= 8:
            break
    return findings


__all__ = ["collect_email_public_references", "collect_public_search_findings", "EMAIL_CATEGORIES"]
