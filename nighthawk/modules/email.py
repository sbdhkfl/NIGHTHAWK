"""Email intelligence using non-invasive, public domain signals.

No mailbox login, SMTP recipient probing, account enumeration, or password
discovery is performed. HIBP is queried only when the user configures an API key.
"""
from __future__ import annotations

from typing import Any

import dns.resolver

from nighthawk.core.config import get_settings
from nighthawk.core.validation import validate_email
from nighthawk.integrations.hibp import hibp_lookup
from nighthawk.integrations.public_footprint import collect_public_search_findings

DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "temp-mail.org", "dispostable.com", "maildrop.cc", "yopmail.com",
    "tempmailo.com", "getnada.com",
})
_PROVIDER_HINTS = (
    (("google.com", "googlemail.com"), "Google Workspace / Gmail"),
    (("outlook.com", "protection.outlook.com", "hotmail.com"), "Microsoft mail"),
    (("yahoodns.net", "yahoo.com"), "Yahoo Mail"),
    (("zoho.com", "zohomail.com"), "Zoho Mail"),
    (("icloud.com", "apple.com"), "Apple iCloud Mail"),
    (("protonmail.ch", "protonmail.com"), "Proton Mail"),
)


def _resolve_records(name: str, record_type: str) -> list[str]:
    """Synchronous DNS lookup with bounded resolver lifetime."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(name, record_type, raise_on_no_answer=False)
        return [str(item).strip('"') for item in answers]
    except Exception:
        return []


def _provider_hint(mx_records: list[str]) -> str | None:
    hosts = " ".join(mx_records).lower()
    for patterns, label in _PROVIDER_HINTS:
        if any(pattern in hosts for pattern in patterns):
            return label
    return "Other / custom mail infrastructure" if mx_records else None


def run(email: str, session=None) -> list[dict[str, Any]]:
    """Run technical checks for an email address."""
    email = validate_email(email)
    _, domain = email.rsplit("@", 1)
    findings: list[dict[str, Any]] = [{
        "module": "email", "target": email,
        "result_data": {"syntax_valid": True, "domain": domain},
        "source": None, "confidence": "high",
    }]

    mx_records = _resolve_records(domain, "MX")
    findings.append({
        "module": "email", "target": email,
        "result_data": {
            "mx_records": mx_records, "has_mx": bool(mx_records),
            "mail_provider_hint": _provider_hint(mx_records),
            "message": "MX records discovered" if mx_records else "No MX records discovered",
            "limitation": "MX records show domain mail routing, not whether this mailbox exists.",
        },
        "source": f"dns://{domain}", "confidence": "high" if mx_records else "medium",
    })

    is_disposable = domain in DISPOSABLE_DOMAINS
    findings.append({
        "module": "email", "target": email,
        "result_data": {
            "suspected_disposable": is_disposable,
            "dataset": "internal maintained list (non-exhaustive)",
        },
        "source": None, "confidence": "medium" if is_disposable else "low",
    })

    root_txt = _resolve_records(domain, "TXT")
    spf = [record for record in root_txt if record.lower().startswith("v=spf1")]
    dmarc_records = _resolve_records(f"_dmarc.{domain}", "TXT")
    dmarc = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    findings.append({
        "module": "email", "target": email,
        "result_data": {
            "spf_records": spf, "spf_present": bool(spf),
            "dmarc_records": dmarc, "dmarc_present": bool(dmarc),
            "note": "SPF and DMARC describe domain email-authentication policy; absence is not proof of fraud.",
        },
        "source": f"dns://{domain}", "confidence": "high",
    })

    settings = get_settings()
    if settings.HIBP_API_KEY:
        try:
            hibp = hibp_lookup(email, settings.HIBP_API_KEY)
        except Exception:
            hibp = {"error": "Breach-status provider request failed"}
        if hibp:
            findings.append({
                "module": "email", "target": email,
                "result_data": {
                    **hibp,
                    "interpretation": "A breach match does not prove current account access or compromise.",
                },
                "source": "https://haveibeenpwned.com/", "confidence": "high",
            })
    else:
        findings.append({
            "module": "email", "target": email,
            "result_data": {
                "breach_check": "not_run",
                "reason": "Configure HIBP_API_KEY to enable the authorized breach-status provider.",
            },
            "source": "https://haveibeenpwned.com/", "confidence": "none",
        })
    findings.extend(collect_public_search_findings(
        email, "email", f'"{email}"'
    ))
    return findings


__all__ = ["run", "DISPOSABLE_DOMAINS"]
