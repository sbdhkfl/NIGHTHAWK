# Expanded intelligence modules

## Phone-number metadata

Use an international number, including its country calling code:

```bash
nighthawk phone +14155552671
```

NIGHTHAWK uses Google's libphonenumber metadata to report formatting,
calling code, numbering region, possible/valid numbering-plan status, and
number type. This is not subscriber lookup: it does not reveal a person's
name, address, live location, or whether the number is currently assigned.

## Optional IP reputation

Set `ABUSEIPDB_API_KEY` in your local `.env` to enable a reputation check
for public IP investigations. When configured, the queried IP is sent to
AbuseIPDB. The report contains a limited set of aggregate fields such as
abuse-confidence score, country code, ISP/usage type, and report counts.
Without the key, the integration is skipped. Reputation scores are signals,
not proof of malicious activity.

## Scope and reliability

NIGHTHAWK combines public technical sources; it cannot discover "everything"
about an email, IP, or phone number. Providers can have incomplete or stale
records. Network ownership and approximate country metadata do not identify
an individual or exact physical location. Never use findings as the sole basis
for consequential decisions.
