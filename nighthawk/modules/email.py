"""Email intelligence module.

Performs syntax and domain validation, MX record checks, optional disposable
email domain detection, and optional Have I Been Pwned lookup (only with an
explicitly configured API key).

Privacy:
- Never sends an email address externally without authorization (HIBP requires
  a configured API key).
- Never stores passwords or attempts logins.
"""

from __future__ import annotations

from typing import Any

from nighthawk.core.config import get_settings
from nighthawk.core.validation import validate_email
from nighthawk.integrations.hibp import hibp_lookup
from nighthawk.modules.base import resolve_dns

# Small maintained list of well-known disposable email domains. Optional and
# non-exhaustive; results are clearly marked as "suspected disposable".
DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "temp-mail.org", "dispostable.com", "maildrop.cc",
    "yopmail.com", "tempmailo.com", "getnada.com",
})


def run(email: str, session=None) -> list[dict[str, Any]]:
    """Run email intelligence checks.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    email = validate_email(email)
    _, domain = email.rsplit("@", 1)
    findings: list[dict[str, Any]] = []

    # Syntax + domain validity already enforced by validate_email.
    findings.append(
        {
            "module": "email",
            "target": email,
            "result_data": {
                "syntax_valid": True,
                "domain": domain,
            },
            "source": None,
            "confidence": "high",
        }
    )

    # MX record check.
    mx_records: list[str] = []
    try:
        dns = resolve_dns(domain, ["MX"])
        mx_records = dns.get("MX", [])
    except Exception:  # pragma: no cover - best effort
        mx_records = []

    mx_confidence = "high" if mx_records else "none"
    findings.append(
        {
            "module": "email",
            "target": email,
            "result_data": {
                "mx_records": mx_records,
                "has_mx": bool(mx_records),
                "message": (
                    "domain accepts mail" if mx_records else "no MX records discovered"
                ),
            },
            "source": f"dns://{domain}",
            "confidence": mx_confidence,
        }
    )

    # Disposable domain detection.
    is_disposable = domain in DISPOSABLE_DOMAINS
    findings.append(
        {
            "module": "email",
            "target": email,
            "result_data": {
                "suspected_disposable": is_disposable,
                "dataset": "internal maintained list (non-exhaustive)",
            },
            "source": None,
            "confidence": "medium" if is_disposable else "low",
        }
    )

    # Optional HIBP lookup, only when an API key is explicitly configured.
    settings = get_settings()
    if settings.HIBP_API_KEY:
        try:
            hibp = hibp_lookup(email, settings.HIBP_API_KEY)
        except Exception as exc:  # pragma: no cover - defensive
            hibp = {"error": str(exc)}
        if hibp:
            findings.append(
                {
                    "module": "email",
                    "target": email,
                    "result_data": hibp,
                    "source": "https://haveibeenpwned.com/",
                    "confidence": "high",
                }
            )

    return findings


__all__ = ["run", "DISPOSABLE_DOMAINS"]
