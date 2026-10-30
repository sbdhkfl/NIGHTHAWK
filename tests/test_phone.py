"""Tests for phone metadata."""
from nighthawk.modules.phone import run


def test_phone_metadata_does_not_claim_identity():
    result = run("+14155552671")[0]["result_data"]
    assert result["country_calling_code"] == 1
    assert result["possible"] is True
    assert "subscriber" in result["metadata_note"]


def test_phone_requires_international_format():
    import pytest
    with pytest.raises(ValueError):
        run("not a phone")
