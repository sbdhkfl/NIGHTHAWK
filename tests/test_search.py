"""Tests for optional search provider integrations (no keys configured)."""


from nighthawk.core.config import reset_settings_cache
from nighthawk.integrations.search_providers import search_all_providers


def test_search_no_keys(monkeypatch):
    for k in ("BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.setenv(k, "")
    reset_settings_cache()
    assert search_all_providers("test query") == []
