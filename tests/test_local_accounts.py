"""Tests for the local-only email account inventory."""
import csv

import pytest

from nighthawk.modules.local_accounts import run


def test_finds_only_exact_email_matches_and_never_returns_passwords(tmp_path):
    path = tmp_path / "browser-export.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "url", "username", "password"])
        writer.writeheader()
        writer.writerow({"name": "Example", "url": "https://example.org/login", "username": "me@example.org", "password": "secret-value"})
        writer.writerow({"name": "Other", "url": "https://other.org", "username": "someone@example.org", "password": "another-secret"})
    findings = run("me@example.org", str(path))
    assert len(findings) == 1
    data = findings[0]["result_data"]
    assert data["service_domain"] == "example.org"
    assert "password" not in str(data).lower()
    assert "secret-value" not in str(findings)


def test_rejects_csv_without_expected_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("site,secret\nexample.org,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="website/URL"):
        run("me@example.org", str(path))


def test_rejects_oversized_export(tmp_path):
    path = tmp_path / "large.csv"
    path.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="5 MiB"):
        run("me@example.org", str(path))
