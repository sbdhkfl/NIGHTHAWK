"""Public search intelligence module.

Provider-based search architecture. Integrations are optional and configured
through environment variables (API keys). No search engines are scraped.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from nighthawk.integrations.search_providers import search_all_providers


def run(query: str, session=None) -> list[dict[str, Any]]:
    """Run a public search across configured providers.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    if not query or not query.strip():
        return [
            {
                "module": "search",
                "target": query,
                "result_data": {
                    "error": "search query is required",
                },
                "source": None,
                "confidence": "none",
            }
        ]

    query = query.strip()
    timestamp = _dt.datetime.now(_dt.UTC).isoformat()
    results = search_all_providers(query)

    findings: list[dict[str, Any]] = []
    for result in results:
        findings.append(
            {
                "module": "search",
                "target": query,
                "result_data": {
                    "provider": result.get("provider"),
                    "title": result.get("title"),
                    "url": result.get("url"),
                    "snippet": result.get("snippet"),
                    "searched_at": timestamp,
                },
                "source": result.get("url"),
                "confidence": "medium",
            }
        )

    if not findings:
        findings.append(
            {
                "module": "search",
                "target": query,
                "result_data": {
                    "results": [],
                    "message": "no search providers configured or no results returned",
                },
                "source": None,
                "confidence": "none",
            }
        )

    return findings


__all__ = ["run"]
