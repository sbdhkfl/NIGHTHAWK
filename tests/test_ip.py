"""Tests for IP intelligence."""

from unittest.mock import patch

import pytest

from nighthawk.core.validation import ValidationError
from nighthawk.modules.ip_intel import run as ip_run


def test_private_ip_rejected():
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "224.0.0.1"):
        findings = ip_run(ip)
        assert findings[0]["result_data"]["error"].startswith("refused")
        assert findings[0]["confidence"] == "none"
        assert findings[0]["source"] is None


def test_invalid_ip():
    with pytest.raises(ValidationError):
        ip_run("999.999.999.999")


@patch("nighthawk.modules.ip_intel.rdap_lookup")
@patch("dns.resolver.resolve", return_value=[])
def test_public_ip_success(mock_resolve, mock_rdap):
    mock_rdap.return_value = {
        "target": "8.8.8.8",
        "rdap_url": "https://rdap.org/ip/8.8.8.8",
        "handle": "AS15169",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "ipVersion": 4,
        "entities": [{"name": "Google LLC", "roles": ["registrant"]}],
    }
    findings = ip_run("8.8.8.8")
    assert any(f["module"] == "ip" and f["result_data"].get("reverse_dns") is not None for f in findings)
    rdap = [f for f in findings if f["result_data"].get("rdap")]
    assert rdap
    assert rdap[0]["result_data"]["organization"] == "Google LLC"
    network = rdap[0]["result_data"]["network_range"]
    assert network and network.get("startAddress") == "8.8.8.0"
    result_text = str(rdap[0]["result_data"]).lower()
    assert "geolocation" not in result_text
