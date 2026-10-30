"""Tests for the username intelligence module."""

from unittest.mock import AsyncMock, patch

from nighthawk.modules.username import run


class FakeResponse:
    def __init__(self, status_code, url):
        self.status_code = status_code
        self.url = url


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_200_same_url(mock_get):
    mock_get.return_value = FakeResponse(200, "https://github.com/octocat")
    findings = run("octocat")
    gh = [f for f in findings if f["result_data"]["platform"] == "GitHub"][0]
    assert gh["result_data"]["status_code"] == 200
    assert gh["result_data"]["classification"] == "likely_exists"
    assert gh["confidence"] == "low"  # 200 is never proof
    assert gh["source"] == "https://github.com/octocat"


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_200_redirect_is_inconclusive(mock_get):
    mock_get.return_value = FakeResponse(200, "https://github.com/someone-else")
    findings = run("octocat")
    gh = [f for f in findings if f["result_data"]["platform"] == "GitHub"][0]
    assert gh["result_data"]["redirected"] is True
    assert gh["result_data"]["classification"] == "inconclusive"
    assert gh["confidence"] == "low"


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_404(mock_get):
    mock_get.return_value = FakeResponse(404, "https://github.com/nonexistent")
    findings = run("nonexistentuser12345")
    gh = [f for f in findings if f["result_data"]["platform"] == "GitHub"][0]
    assert gh["result_data"]["classification"] == "likely_not_exists"
    assert gh["confidence"] == "none"


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_429_blocked(mock_get):
    mock_get.return_value = FakeResponse(429, "https://www.reddit.com/user/x")
    findings = run("x")
    rd = [f for f in findings if f["result_data"]["platform"] == "Reddit"][0]
    assert rd["result_data"]["classification"] == "blocked"


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_500_inconclusive(mock_get):
    mock_get.return_value = FakeResponse(500, "https://medium.com/@x")
    findings = run("x")
    med = [f for f in findings if f["result_data"]["platform"] == "Medium"][0]
    assert med["result_data"]["classification"] == "inconclusive"


@patch("nighthawk.modules.username.HttpClient.get", new_callable=AsyncMock)
def test_username_network_error(mock_get):
    mock_get.side_effect = OSError("network down")
    findings = run("octocat")
    gh = [f for f in findings if f["result_data"]["platform"] == "GitHub"][0]
    assert gh["result_data"]["classification"] == "error"
    assert gh["confidence"] == "none"
    assert gh["source"] is None


def test_platforms_non_empty():
    from nighthawk.modules.username import PLATFORMS

    assert len(PLATFORMS) >= 6
