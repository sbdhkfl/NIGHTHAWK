"""Tests for email intelligence."""
from unittest.mock import patch

import pytest

from nighthawk.core.validation import ValidationError
from nighthawk.modules.email import DISPOSABLE_DOMAINS
from nighthawk.modules.email import run as email_run


@patch("nighthawk.modules.email._resolve_records", side_effect=lambda name, kind: {
    ("example.com", "MX"): ["10 ASPMX.L.GOOGLE.COM."],
    ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
}.get((name, kind), []))
def test_email_success_no_hibp(mock_dns, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "")
    from nighthawk.core.config import reset_settings_cache
    reset_settings_cache()
    findings = email_run("alice@example.com")
    assert any(f["result_data"].get("syntax_valid") for f in findings)
    mx = next(f for f in findings if "mx_records" in f["result_data"])
    assert mx["result_data"]["has_mx"] is True
    assert mx["result_data"]["mail_provider_hint"] == "Google Workspace / Gmail"
    auth = next(f for f in findings if "spf_present" in f["result_data"])
    assert auth["result_data"]["spf_present"] is True
    assert auth["result_data"]["dmarc_present"] is True


@patch("nighthawk.modules.email._resolve_records", return_value=[])
def test_email_disposable(mock_dns):
    disposable = next(iter(DISPOSABLE_DOMAINS))
    findings = email_run(f"user@{disposable}")
    disp = [f for f in findings if f["result_data"].get("suspected_disposable")]
    assert disp and disp[0]["result_data"]["suspected_disposable"] is True


def test_invalid_email():
    with pytest.raises(ValidationError):
        email_run("not-an-email")
