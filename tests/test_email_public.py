"""Tests for API-free categorized public email search links."""
from urllib.parse import parse_qs, urlparse

from nighthawk.integrations.public_footprint import collect_email_public_references


def test_email_public_search_needs_no_provider_or_opt_in(monkeypatch):
    monkeypatch.delenv("NIGHTHAWK_ENABLE_PUBLIC_SEARCH", raising=False)
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)

    def unexpected_api_call(*args, **kwargs):
        raise AssertionError("email-public must not call a search API")

    monkeypatch.setattr(
        "nighthawk.integrations.public_footprint.search_all_providers",
        unexpected_api_call,
    )
    findings = collect_email_public_references("self@example.org")
    assert len(findings) == 5
    assert all(item["result_data"]["status"] == "manual_search" for item in findings)
    assert all(item["result_data"]["search_url"].startswith("https://www.google.com/search?") for item in findings)


def test_email_public_links_cover_supported_categories_without_account_claims():
    findings = collect_email_public_references("self@example.org")
    categories = {item["result_data"]["category"] for item in findings}
    assert categories == {
        "social_media",
        "developer",
        "professional_and_portfolio",
        "forums_and_communities",
        "gaming_and_streaming",
    }
    for item in findings:
        query = parse_qs(urlparse(item["result_data"]["search_url"]).query)["q"][0]
        assert '"self@example.org"' in query
        assert item["confidence"] == "none"
        assert "not proof" in item["result_data"]["message"]
