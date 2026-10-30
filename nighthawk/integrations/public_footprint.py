"""Opt-in, search-engine-indexed public references for authorized self-audits.

This does not query login, password-reset, or account-recovery endpoints. Search
results are public-page leads, never proof that an address has an account.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from nighthawk.core.config import get_settings
from nighthawk.integrations.search_providers import search_all_providers


EMAIL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "social_media": (
        "facebook.com", "instagram.com", "reddit.com", "x.com",
        "linkedin.com", "pinterest.com", "tiktok.com",
    ),
    "developer": (
        "github.com", "gitlab.com", "stackoverflow.com", "dev.to",
        "codeberg.org", "sourcehut.org",
    ),
    "professional_and_portfolio": (
        "linkedin.com", "medium.com", "about.me", "substack.com",
    ),
    "forums_and_communities": (
        "reddit.com", "discourse.org", "community.", "groups.google.com",
    ),
    "gaming_and_streaming": (
        "twitch.tv", "steamcommunity.com", "itch.io", "youtube.com",
    ),
}


def _provider_ready(settings) -> bool:
    return bool(settings.BRAVE_SEARCH_API_KEY or settings.TAVILY_API_KEY)


def collect_email_public_references(email: str) -> list[dict[str, Any]]:
    """Search public indexed pages by category, only after explicit opt-in."""
    settings = get_settings()
    if not settings.ENABLE_PUBLIC_SEARCH:
        return [{
            "module": "email_public",
            "target": email,
            "result_data": {
                "status": "disabled",
                "message": "Set NIGHTHAWK_ENABLE_PUBLIC_SEARCH=true to enable public-page searches.",
            },
            "source": None,
            "confidence": "none",
        }]
    if not _provider_ready(settings):
        return [{
            "module": "email_public",
            "target": email,
            "result_data": {
                "status": "provider_not_configured",
                "message": "Add BRAVE_SEARCH_API_KEY or TAVILY_API_KEY to .env, then restart NIGHTHAWK.",
            },
            "source": None,
            "confidence": "none",
        }]

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for category, sites in EMAIL_CATEGORIES.items():
        site_query = " OR ".join(f"site:{site}" for site in sites)
        query = f'"{email}" ({site_query})'
        try:
            results = search_all_providers(query)
        except Exception:
            findings.append({
                "module": "email_public",
                "target": email,
                "result_data": {
                    "category": category,
                    "status": "provider_error",
                    "message": "Public search provider request failed.",
                },
                "source": None,
                "confidence": "none",
            })
            continue

        category_count = 0
        for item in results:
            url = item.get("url")
            if not isinstance(url, str):
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if normalized in seen:
                continue
            seen.add(normalized)
            findings.append({
                "module": "email_public",
                "target": email,
                "result_data": {
                    "category": category,
                    "match_type": "possible_public_reference",
                    "provider": item.get("provider"),
                    "title": item.get("title"),
                    "url": url,
                    "snippet": item.get("snippet"),
                    "interpretation": (
                        "A search engine indexed a public page containing or relating "
                        "to this email. It does not confirm registration, ownership, "
                        "or current account access."
                    ),
                },
                "source": url,
                "confidence": "low",
            })
            category_count += 1
            if category_count >= 5:
                break

    if not findings:
        findings.append({
            "module": "email_public",
            "target": email,
            "result_data": {
                "status": "no_public_references",
                "message": "No matching public pages were returned for the searched categories.",
            },
            "source": None,
            "confidence": "none",
        })
    return findings



def collect_public_search_findings(
    target: str, module: str, query: str
) -> list[dict[str, Any]]:
    """Generic opt-in public-page search used by non-email modules."""
    settings = get_settings()
    if not settings.ENABLE_PUBLIC_SEARCH:
        return []
    if not _provider_ready(settings):
        return [{
            "module": module,
            "target": target,
            "result_data": {
                "search_status": "provider_not_configured",
                "message": "Configure BRAVE_SEARCH_API_KEY or TAVILY_API_KEY.",
            },
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
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        if url in seen:
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
                "interpretation": (
                    "A public search result is a lead only; it does not establish "
                    "identity, account ownership, or current account access."
                ),
            },
            "source": url,
            "confidence": "low",
        })
        if len(findings) >= 8:
            break
    return findings


__all__ = ["collect_email_public_references", "collect_public_search_findings", "EMAIL_CATEGORIES"]
