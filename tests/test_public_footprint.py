"""Tests for opt-in public footprint reference searches."""

from nighthawk.core.config import reset_settings_cache
from nighthawk.integrations.public_footprint import collect_public_search_findings


def test_public_search_disabled_by_default(monkeypatch):
    monkeypatch.delenv("NIGHTHAWK_ENABLE_PUBLIC_SEARCH", raising=False)
    reset_settings_cache()
    assert collect_public_search_findings("alice@example.com", "email", '"alice@example.com"') == []
    reset_settings_cache()


def test_public_search_returns_cautious_possible_matches(monkeypatch):
    monkeypatch.setenv("NIGHTHAWK_ENABLE_PUBLIC_SEARCH", "true")
    reset_settings_cache()
    monkeypatch.setattr(
        "nighthawk.integrations.public_footprint.search_all_providers",
        lambda query: [
            {
                "provider": "Test Search",
                "title": "Public page",
                "url": "https://example.org/profile",
                "snippet": "A public reference",
            },
            {
                "provider": "Test Search",
                "title": "Duplicate",
                "url": "https://example.org/profile",
                "snippet": "Duplicate URL",
            },
            {"provider": "Test Search", "title": "Bad URL", "url": "javascript:alert(1)"},
        ],
    )

    findings = collect_public_search_findings(
        "alice@example.com", "email", '"alice@example.com"'
    )
    assert len(findings) == 1
    assert findings[0]["confidence"] == "low"
    assert findings[0]["result_data"]["match_type"] == "possible_public_reference"
    assert "does not prove" in findings[0]["result_data"]["interpretation"]
    reset_settings_cache()
