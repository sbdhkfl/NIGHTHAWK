"""Local-only audit of a user's own browser/password-manager CSV export.

Only service URLs and usernames matching the supplied email are returned.
Password and other secret columns are never included in findings or persisted.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nighthawk.core.validation import validate_email

MAX_EXPORT_BYTES = 5 * 1024 * 1024
MAX_ROWS = 50_000
URL_COLUMNS = ("url", "website", "origin", "hostname")
USERNAME_COLUMNS = ("username", "user name", "login", "email")


def run(email: str, csv_path: str, session=None) -> list[dict[str, Any]]:
    """Find matching email usernames in a locally supplied CSV export."""
    email = validate_email(email)
    path = Path(csv_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"CSV export not found: {path}")
    if path.stat().st_size > MAX_EXPORT_BYTES:
        raise ValueError("CSV export exceeds the 5 MiB safety limit")

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV export is empty or has no header row")
        normalized = {name.strip().lower(): name for name in reader.fieldnames if name}
        url_key = next((normalized[k] for k in URL_COLUMNS if k in normalized), None)
        username_key = next((normalized[k] for k in USERNAME_COLUMNS if k in normalized), None)
        if not url_key or not username_key:
            raise ValueError(
                "CSV must contain a website/URL column and a username/email column"
            )

        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_ROWS:
                raise ValueError("CSV export exceeds the 50,000-row safety limit")
            stored_username = (row.get(username_key) or "").strip()
            if stored_username.casefold() != email.casefold():
                continue
            raw_url = (row.get(url_key) or "").strip()
            parsed = urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            if parsed.username or parsed.password:
                continue
            domain = parsed.hostname.lower().rstrip(".")
            key = (domain, stored_username.casefold())
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "module": "email_local_audit",
                "target": email,
                "result_data": {
                    "service_domain": domain,
                    "service_url": f"{parsed.scheme}://{domain}",
                    "matched_field": "username",
                    "evidence": "Exact email match in the user's local CSV export",
                    "interpretation": (
                        "This shows a matching saved-login entry in the supplied export; "
                        "it does not prove the account is active or currently accessible."
                    ),
                    "secrets_handling": (
                        "Password and secret columns are ignored and are not returned."
                    ),
                },
                "source": None,
                "confidence": "high",
            })
    return findings


__all__ = ["run"]
