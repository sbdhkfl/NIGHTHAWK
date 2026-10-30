# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.0   | :white_check_mark: |

## Reporting a vulnerability

Please disclose security issues responsibly. Open a GitHub issue or contact the
repository maintainers. Do not post exploit code or credentials in public issues.

## Design boundaries (read before use)

NIGHTHAWK OSINT is an **open-source intelligence** framework. It is explicitly
not designed for, and must not be used for:

- Credential theft or password cracking
- Unauthorized access to accounts or systems
- Phishing or social engineering
- Malware development or distribution
- Intrusive port or vulnerability scanning
- Bypassing authentication, CAPTCHAs or access controls
- Private-data extraction beyond what is publicly published

Operational safeguards:

- API keys are loaded from environment variables only and are never logged.
- The dashboard binds to localhost (127.0.0.1) by default.
- All dashboard output is HTML-escaped; retrieved content is treated as untrusted.
- Private, loopback, multicast and reserved IP addresses are rejected for
  external intelligence lookups.
- No precise physical geolocation is claimed from IP addresses.
- Images are never uploaded to external services.

Users are responsible for complying with applicable laws and website terms of
service. Target only assets you own or have explicit permission to investigate.
