"""Tests for API timeouts and malformed external responses."""

from unittest.mock import AsyncMock, patch

import httpx

from nighthawk.integrations.hibp import hibp_lookup
from nighthawk.integrations.rdap import rdap_lookup


class FakeResponse:
    status_code = 200

    def json(self):
        raise ValueError("not json")


@patch("nighthawk.integrations.rdap.HttpClient.get", new_callable=AsyncMock)
def test_rdap_timeout(mock_get):
    mock_get.side_effect = httpx.ConnectTimeout("timeout")
    result = rdap_lookup("example.com")
    assert "error" in result


@patch("nighthawk.integrations.rdap.HttpClient.get", new_callable=AsyncMock)
def test_rdap_malformed_json(mock_get):
    mock_get.return_value = FakeResponse()
    result = rdap_lookup("example.com")
    assert "error" in result


@patch("nighthawk.integrations.hibp.HttpClient.get", new_callable=AsyncMock)
def test_hibp_404_no_breaches(mock_get):
    class NotFound:
        status_code = 404

    mock_get.return_value = NotFound()
    result = hibp_lookup("alice@example.com", "key")
    assert result.get("breaches") == []
    assert result.get("count") == 0


@patch("nighthawk.integrations.hibp.HttpClient.get", new_callable=AsyncMock)
def test_hibp_network_error(mock_get):
    mock_get.side_effect = httpx.RequestError("boom")
    result = hibp_lookup("alice@example.com", "key")
    assert "error" in result
