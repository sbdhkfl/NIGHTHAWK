# Usage — NIGHTHAWK OSINT

## Terminal interface

```bash
nighthawk --help

# Username intelligence
nighthawk username octocat

# Domain intelligence (DNS + RDAP)
nighthawk domain example.com

# DNS only
nighthawk dns example.com

# Subdomains via Certificate Transparency
nighthawk subdomains example.com

# IP intelligence (public IPs only)
nighthawk ip 8.8.8.8

# Email intelligence
nighthawk email researcher@example.com

# Image EXIF metadata (local file only)
nighthawk image ./photo.jpg

# Public search (requires configured provider keys)
nighthawk search "public cybersecurity research"

# Dashboard
nighthawk dashboard

# Investigation management
nighthawk investigations list
nighthawk investigations view <id>

# Reports
nighthawk report export <id> --format json --output report
nighthawk report export <id> --format csv
nighthawk report export <id> --format html
```

## Web dashboard

```bash
nighthawk dashboard
```

Open http://127.0.0.1:8000.

1. Create an investigation (give it a name).
2. Add targets or run modules against targets directly.
3. View findings with confidence labels and source URLs.
4. Add notes, view the relationship graph, export JSON/CSV/HTML reports.

## Confidence labels

- **Verified fact (high)** — directly observed, low inference (e.g. DNS record).
- **Observation (medium)** — sourced from a public registry or CT log.
- **Unverified lead (low)** — HTTP profile checks; an account may or may not exist.
- **No data (none)** — nothing discovered.

HTTP 200 on a profile page is never treated as proof of account existence.
