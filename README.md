# NIGHTHAWK OSINT

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

See the public footprint.

A modular, cross-platform Open-Source Intelligence (OSINT) gathering and investigation
framework with a professional terminal interface and a modern web dashboard.

## Features

- **Username intelligence** — checks public profile URLs (GitHub, GitLab, Reddit, Pinterest,
  Medium, Hacker News, Keybase) with cautious classification; HTTP 200 is never treated as
  proof of account existence.
- **Domain intelligence** — DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) plus RDAP
  registration lookup.
- **Subdomain intelligence** — passive discovery via Certificate Transparency (crt.sh).
- **IP intelligence** — RDAP registration, network range, reverse DNS, and optional AbuseIPDB aggregate reputation; public IPs only.
- **Phone metadata** — international formatting, numbering-plan validity, calling code, region, and number type; no subscriber identification.
- **Defensive vulnerability intelligence** — CVE lookups against CISA's Known Exploited Vulnerabilities catalog; no host scanning or exploitation.
- **Email intelligence** — syntax, MX, SPF, DMARC, provider hints, disposable-domain detection, optional Have I
  Been Pwned lookup with a user-provided API key.
- **Image intelligence** — EXIF metadata (camera, timestamps, GPS) from local images.
- **Public search intelligence** — provider-based search (Brave Search, Tavily) via API keys.
- **Investigation engine** — create, name, target, run modules, save and reopen
  investigations, add notes, export reports.
- **Web dashboard** — FastAPI + Jinja2 + HTMX, responsive, localhost by default.
- **Terminal interface** — Typer + Rich CLI with ASCII logo and tables.
- **Reports** — JSON, CSV, HTML with findings, sources, confidence labels and limitations.
- **Storage** — SQLite via SQLAlchemy; JSON/CSV/HTML exports.

No credentials, no password cracking, no scraping, no exploits, no private data.

## Installation

### Requirements

Python 3.11+ (tested on 3.11, 3.12, 3.13).

### Windows

```powershell
# Clone the repository
git clone https://github.com/sbdhkfl/NIGHTHAWK.git
cd NIGHTHAWK

# Create a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Optional: dashboard dependencies
pip install "fastapi>=0.111.0" "uvicorn[standard]>=0.30.0" "jinja2>=3.1.0" "python-multipart>=0.0.9"

# Verify
nighthawk --help
```

### Linux (Ubuntu / Debian / Kali)

```bash
git clone https://github.com/sbdhkfl/NIGHTHAWK.git
cd NIGHTHAWK

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Dashboard dependencies
pip install "fastapi>=0.111.0" "uvicorn[standard]>=0.30.0" "jinja2>=3.1.0" "python-multipart>=0.0.9"

# Verify
nighthawk --help
```

### Docker

```bash
docker compose up --build
# Dashboard: http://127.0.0.1:8000
```

## Configuration

Copy `.env.example` to `.env` and adjust:

```
NIGHTHAWK_HOST=127.0.0.1
NIGHTHAWK_PORT=8000
BRAVE_SEARCH_API_KEY=...
TAVILY_API_KEY=...
HIBP_API_KEY=...
ABUSEIPDB_API_KEY=...
```

API keys are optional. The framework works without them; provider-backed modules simply
return "no providers configured". Keys are loaded from environment variables only — never
hardcoded, never committed.

## Usage

### Terminal interface

```bash
nighthawk --help

nighthawk username octocat
nighthawk domain example.com
nighthawk dns example.com
nighthawk subdomains example.com
nighthawk ip 8.8.8.8
nighthawk email researcher@example.com
nighthawk phone +14155552671
nighthawk cve CVE-2024-12345
nighthawk image ./photo.jpg
nighthawk search "public cybersecurity research"

nighthawk dashboard
nighthawk investigations list
nighthawk report export 1 --format json --output report
```

### Web dashboard

```bash
nighthawk dashboard
```

Then open http://127.0.0.1:8000. The dashboard binds to localhost by default.

### Modules

See `docs/MODULES.md` for per-module details, sources and limitations.

### Reports

```bash
nighthawk report export <id> --format json
nighthawk report export <id> --format csv
nighthawk report export <id> --format html
```

Reports distinguish verified facts (high confidence), observations (medium),
unverified leads (low) and no-data results (none).

## Project structure

See `docs/ARCHITECTURE.md`.

## Privacy and safety limitations

NIGHTHAWK OSINT collects publicly available information only and enforces:

- No credential theft, password cracking, phishing or malware.
- No unauthorized account access or authentication bypass.
- No intrusive port scanning or exploit execution.
- No bypassing CAPTCHAs, logins or access restrictions.
- Private/loopback/multicast IPs are rejected for external lookups.
- No precise geolocation is claimed from IP addresses.
- Images are never uploaded to external services.
- Email addresses are never sent externally without an explicitly configured HIBP key.
- Dashboard binds to localhost by default; all outputs are HTML-escaped.

Read `docs/USAGE.md` and `SECURITY.md` before running against third parties.

## Screenshots

<!-- Add screenshots here before publishing -->
- [ ] Terminal interface
- [ ] Web dashboard overview
- [ ] Investigation detail page
- [ ] Relationship graph

## License

MIT License. See `LICENSE`.

## Contributing

See `CONTRIBUTING.md`.

## Security policy

See `SECURITY.md`.
