"""Tests for defensive CISA KEV lookup."""
from unittest.mock import patch

from nighthawk.modules.kev import run


@patch("nighthawk.modules.kev._catalog")
def test_cve_listed(mock_catalog):
    mock_catalog.return_value = {
        "dateReleased": "2026-01-01",
        "vulnerabilities": [{
            "cveID": "CVE-2024-12345",
            "vendorProject": "Example",
            "product": "Example Product",
            "requiredAction": "Apply vendor mitigation",
        }],
    }
    result = run("cve-2024-12345")[0]["result_data"]
    assert result["listed_in_cisa_kev"] is True
    assert result["vendorProject"] == "Example"


@patch("nighthawk.modules.kev._catalog", return_value={"vulnerabilities": []})
def test_cve_not_listed(mock_catalog):
    assert run("CVE-2024-12345")[0]["result_data"]["listed_in_cisa_kev"] is False
