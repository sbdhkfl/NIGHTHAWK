"""Input validation utilities for intelligence targets."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import dns.exception
import dns.name

# Reasonable limits to keep lookups sane and avoid abuse.
MAX_USERNAME_LENGTH = 200
MAX_DOMAIN_LENGTH = 253
MAX_EMAIL_LENGTH = 254

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*(?:\.[A-Za-z]{2,})$"
)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class ValidationError(ValueError):
    """Raised when a target fails validation."""


def validate_username(value: str) -> str:
    """Validate a username.

    Returns the normalized username or raises ValidationError.
    """
    if not value or not isinstance(value, str):
        raise ValidationError("username is required")
    username = value.strip()
    if len(username) > MAX_USERNAME_LENGTH:
        raise ValidationError(f"username too long (max {MAX_USERNAME_LENGTH} chars)")
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            "username may only contain letters, digits, underscore, dot and hyphen"
        )
    return username


def validate_domain(value: str) -> str:
    """Validate a domain name.

    Returns the lowercased domain or raises ValidationError.
    """
    if not value or not isinstance(value, str):
        raise ValidationError("domain is required")
    domain = value.strip().lower().rstrip(".")
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise ValidationError(f"domain too long (max {MAX_DOMAIN_LENGTH} chars)")
    if not _DOMAIN_RE.match(domain):
        raise ValidationError("invalid domain name")
    return domain


def validate_email(value: str) -> str:
    """Validate email syntax only (no network checks).

    Returns the normalized email or raises ValidationError.
    """
    if not value or not isinstance(value, str):
        raise ValidationError("email is required")
    email = value.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH:
        raise ValidationError(f"email too long (max {MAX_EMAIL_LENGTH} chars)")
    if not _EMAIL_RE.match(email):
        raise ValidationError("invalid email address")
    local, _, domain = email.rpartition("@")
    if len(local) > 64:
        raise ValidationError("email local part too long")
    validate_domain(domain)  # also validates the domain part
    return email


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address string.

    Returns the normalized IP string or raises ValidationError.
    """
    if not value or not isinstance(value, str):
        raise ValidationError("IP address is required")
    ip = value.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValidationError("invalid IPv4 or IPv6 address") from exc
    return str(addr)


def is_private_or_reserved(ip_str: str) -> bool:
    """Return True if the IP is private, loopback, multicast or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
    )


def validate_image_filename(filename: str) -> str:
    """Validate an uploaded image filename against the allowed extensions.

    Returns the safe basename or raises ValidationError.
    """
    from nighthawk.core.config import get_settings

    if not filename:
        raise ValidationError("filename is required")
    name = Path(filename).name
    suffix = Path(name).suffix.lower()
    if suffix not in get_settings().ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(
            f"unsupported image format '{suffix}'. "
            f"Allowed: {', '.join(sorted(get_settings().ALLOWED_IMAGE_EXTENSIONS))}"
        )
    return name


# Re-export dns validation helpers for modules.
def is_valid_dns_name(value: str) -> bool:
    try:
        dns.name.from_text(value)
        return True
    except dns.exception.DNSException:
        return False
