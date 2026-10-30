"""Tests for input validation."""

import pytest

from nighthawk.core.validation import (
    ValidationError,
    is_private_or_reserved,
    validate_domain,
    validate_email,
    validate_image_filename,
    validate_ip,
    validate_username,
)


def test_valid_username():
    assert validate_username("octocat") == "octocat"
    assert validate_username("user.name-1") == "user.name-1"


@pytest.mark.parametrize("bad", ["", "   ", "user name", "user@host", "a" * 201])
def test_invalid_username(bad):
    with pytest.raises(ValidationError):
        validate_username(bad)


def test_valid_domain():
    assert validate_domain("Example.COM") == "example.com"
    assert validate_domain("sub.example.com.") == "sub.example.com"


@pytest.mark.parametrize("bad", ["", "-example.com", "example..com", "example", "a" * 300])
def test_invalid_domain(bad):
    with pytest.raises(ValidationError):
        validate_domain(bad)


def test_valid_email():
    assert validate_email("Alices@Example.COM") == "alices@example.com"


@pytest.mark.parametrize(
    "bad", ["", "no-at-sign", "@domain.com", "user@", "user@-domain.com", "a" * 70 + "@d.com"]
)
def test_invalid_email(bad):
    with pytest.raises(ValidationError):
        validate_email(bad)


def test_valid_ip():
    assert validate_ip("8.8.8.8") == "8.8.8.8"
    assert validate_ip("2001:db8::1") == "2001:db8::1"


@pytest.mark.parametrize("bad", ["", "999.999.999.999", "not-an-ip", "256.1.1.1"])
def test_invalid_ip(bad):
    with pytest.raises(ValidationError):
        validate_ip(bad)


@pytest.mark.parametrize(
    "ip,private",
    [
        ("127.0.0.1", True),
        ("10.0.0.5", True),
        ("172.16.0.1", True),
        ("192.168.1.1", True),
        ("::1", True),
        ("fe80::1", True),
        ("224.0.0.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("2001:db8::1", True),  # documentation range is treated as reserved
    ],
)
def test_private_or_reserved(ip, private):
    assert is_private_or_reserved(ip) is private


def test_validate_image_filename_ok(tmp_path):
    assert validate_image_filename("photo.jpg") == "photo.jpg"
    assert validate_image_filename("dir/../evil.png") == "evil.png"


@pytest.mark.parametrize("bad", ["", "script.sh", "photo.html", "image.bmp"])
def test_validate_image_filename_bad(bad):
    with pytest.raises(ValidationError):
        validate_image_filename(bad)
