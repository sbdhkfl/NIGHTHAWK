"""Tests for DNS and domain modules."""

from unittest.mock import patch

import pytest

from nighthawk.core.validation import ValidationError
from nighthawk.modules.dns import run as dns_run
from nighthawk.modules.domain import run as domain_run


def fake_resolve(domain, record_types=None):
    record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    if domain == "fail.example":
        return {rt: [] for rt in record_types}
    return {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "MX": ["10 mail.example.com."],
        "NS": ["ns1.example.com."],
        "TXT": ["v=spf1 -all"],
        "CNAME": [],
        "SOA": [],
    }


@patch("nighthawk.modules.domain.resolve_dns", new=fake_resolve)
@patch("nighthawk.modules.domain.rdap_lookup", return_value={"handle": "D123"})
def test_domain_success(mock_rdap):
    findings = domain_run("example.com")
    dns_findings = [f for f in findings if f["result_data"].get("dns")]
    assert dns_findings
    assert dns_findings[0]["result_data"]["dns"]["A"] == ["93.184.216.34"]
    rdap_findings = [f for f in findings if f["result_data"].get("rdap")]
    assert rdap_findings
    assert rdap_findings[0]["result_data"]["rdap"]["handle"] == "D123"


@patch("nighthawk.modules.domain.resolve_dns", new=fake_resolve)
@patch("nighthawk.modules.domain.rdap_lookup", return_value={})
def test_domain_no_records(mock_rdap):
    findings = domain_run("fail.example")
    assert findings
    assert findings[0]["result_data"]["dns"] == {}
    assert findings[0]["confidence"] == "none"


@patch("nighthawk.modules.dns.resolve_dns", new=fake_resolve)
def test_dns_success():
    findings = dns_run("example.com")
    assert findings[0]["module"] == "dns"
    assert findings[0]["result_data"]["dns"]["MX"] == ["10 mail.example.com."]
    assert findings[0]["confidence"] == "high"


@patch("nighthawk.modules.dns.resolve_dns", new=fake_resolve)
def test_dns_no_records():
    findings = dns_run("fail.example")
    assert findings[0]["confidence"] == "none"
    assert findings[0]["result_data"]["dns"] == {}


def test_dns_invalid_domain():
    with pytest.raises(ValidationError):
        dns_run("not a domain")
