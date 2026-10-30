"""Phone-number metadata checks.

Reports numbering-plan metadata only. It does not identify subscribers, locate
devices, query private records, or attempt messaging/calling.
"""
from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberType


def run(value: str, session=None) -> list[dict[str, Any]]:
    raw = value.strip()
    if not raw or len(raw) > 40:
        raise ValueError("phone number is required and must be at most 40 characters")
    try:
        parsed = phonenumbers.parse(raw, None)
    except NumberParseException as exc:
        raise ValueError("use an international phone number with country calling code, e.g. +14155552671") from exc

    possible = phonenumbers.is_possible_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    kind = phonenumbers.number_type(parsed)
    type_names = {
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal_number",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }
    return [{
        "module": "phone",
        "target": raw,
        "result_data": {
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_calling_code": parsed.country_code,
            "numbering_region": phonenumbers.region_code_for_number(parsed),
            "possible": possible,
            "valid_numbering_plan_number": valid,
            "number_type": type_names.get(kind, "unknown"),
            "metadata_note": "Numbering-plan metadata only; it does not identify the subscriber or prove that the number is currently assigned.",
        },
        "source": "https://github.com/google/libphonenumber",
        "confidence": "high" if valid else "low",
    }]


__all__ = ["run"]
