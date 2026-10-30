"""Tests for categorized public email reference searches."""
from nighthawk.core.config import reset_settings_cache
from nighthawk.integrations.public_footprint import collect_email_public_references


def test_email_public_search_explains_missing_provider(monkeypatch):
    monkeypatch.setenv("NIGHTHAWK_ENABLE_PUBLIC_SEARCH", "true")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    reset_settings_cache()
    findings = collect_email_public_references("self@example.org")
    assert findings[0]["result_data"]["status"] == "provider_not_configured"
    reset_settings_cache()


def test_email_public_search_uses_safe_categories_and_marks_leads(monkeypatch):
    monkeypatch.setenv("NIGHTHAWK_ENABLE_PUBLIC_SEARCH", "true")
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    reset_settings_cache()
    calls = []

    def fake_search(query):
        calls.append(query)
        return [{
            "provider": "Test Search",
            "title": "Public developer profile",
            "url": "https://github.com/example",
            "snippet": "Public page mentioning the test address",
        }]

    monkeypatch.setattr(
        "nighthawk.integrations.public_footprint.search_all_providers",
        fake_search,
    )
    findings = collect_email_public_references("self@example.org")
    assert calls
    assert any("site:github.com" in query for query in calls)
    assert not any("dating" in query.lower() or "porn" in query.lower() for query in calls)
    assert findings[0]["confidence"] == "low"
    assert findings[0]["result_data"]["match_type"] == "possible_public_reference"
    reset_settings_cache()
