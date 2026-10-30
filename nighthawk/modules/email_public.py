"""API-free category search links for an email address."""
from __future__ import annotations

from typing import Any

from nighthawk.core.validation import validate_email
from nighthawk.integrations.public_footprint import collect_email_public_references


def run(email: str, session=None) -> list[dict[str, Any]]:
    return collect_email_public_references(validate_email(email))


__all__ = ["run"]
