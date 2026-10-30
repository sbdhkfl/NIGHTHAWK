"""Tests for email intelligence."""

from unittest.mock import patch

import pytest

from nighthawk.core.validation import ValidationError
from nighthawk.modules.email import DISPOSABLE_DOMAINS
from nighthawk.modules.email import run as email_run


@patch("nighthawk.modules.email.resolve_dns", new=lambda *a, **k: {"MX": ["10 mail.example.com."]})
def test_email_success_no_hibp(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "")
    from nighthawk.core.config import reset_settings_cache

    reset_settings_cache()
    findings = email_run("alice@example.com")
    syntax = [f for f in findings if f["result_data"].get("syntax_valid")]
    assert syntax
    mx = [f for f in findings if "mx_records" in f["result_data"]]
    assert mx and mx[0]["result_data"]["has_mx"] is True


@patch("nighthawk.modules.email.resolve_dns", new=lambda *a, **k: {})
def test_email_disposable():
    disposable = next(iter(DISPOSABLE_DOMAINS))
    findings = email_run(f"user@{disposable}")
    disp = [f for f in findings if f["result_data"].get("suspected_disposable")]
    assert disp
    assert disp[0]["result_data"]["suspected_disposable"] is True


def test_invalid_email():
    with pytest.raises(ValidationError):
        email_run("not-an-email")
