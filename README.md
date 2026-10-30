# NIGHTHAWK OSINT

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**See the public footprint.**

NIGHTHAWK is a modular OSINT and personal digital-footprint investigation framework with a simple terminal interface.

## What it can investigate

- **Email:** one simple command for technical mail-domain checks and API-free public-reference search links across social, developer, professional, forums and gaming categories. Review links manually; they do not verify registrations.
- **Username:** possible matching public profiles on supported platforms. A match is a lead, not proof that you own or logged into an account.
- **Domain / URL:** DNS and RDAP information; `nighthawk url https://example.com/path` extracts the hostname and investigates the domain without crawling the page.
- **Subdomains:** passive Certificate Transparency discovery.
- **IP address:** public IP registration, network range, organization and reverse DNS. Separate `ip-ports` checks a fixed list of common TCP ports on one RFC1918 private LAN IPv4 address; `lan-devices` reads the local Linux neighbor cache. Neither exploits services.
- **Phone:** international numbering-plan metadata; no subscriber identification or device tracking.
- **Image:** local EXIF metadata, including camera make/model, timestamps and GPS coordinates when embedded.
- **CVE:** lookup in CISA's Known Exploited Vulnerabilities catalog; no scanning or exploitation.
- **Public references:** manual public-search links for email (no API key required); optional automated public-page searches for other identifiers can still use configured providers. Search links are not proof of account registration.
- **Investigations and reports:** save findings locally and export JSON, CSV or HTML.

NIGHTHAWK cannot reveal every website where an email address has logged in. Private login history is held by each service. Public search results are only leads, not proof that an account exists.

## Installation

### Requirements

Python 3.11–3.13 are the documented tested versions. Python 3.14 may work, but is not currently listed as tested.

### Kali / Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/sbdhkfl/NIGHTHAWK.git
cd NIGHTHAWK

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

# Verify the installation and see the commands actually registered
nighthawk --help
```

If your distribution does not provide a compatible Python version, use Python 3.11, 3.12 or 3.13 in a virtual environment. Do not use `sudo pip install` inside Kali's system Python.

### Windows

```powershell
git clone https://github.com/sbdhkfl/NIGHTHAWK.git
cd NIGHTHAWK
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
nighthawk --help
```

### Update an existing clone

```bash
cd ~/NIGHTHAWK
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e .
nighthawk --help
```

## Command reference

Run `nighthawk --help` for the installed command list and `nighthawk COMMAND --help` for command-specific options.

### Individual investigations

```bash
# Public profile checks for a username you are authorized to investigate
nighthawk username YOUR_USERNAME

# Domain registration and DNS
nighthawk domain example.com

# Investigate the domain behind a URL
nighthawk url https://example.com/path

# DNS records only
nighthawk dns example.com

# Passive Certificate Transparency subdomain discovery
nighthawk subdomains example.com

# Public IP registration and reverse-DNS information (no port scan)
nighthawk ip 8.8.8.8

# Check common TCP ports on ONE private LAN IPv4 address you own/administer
nighthawk ip-ports 192.168.1.1 --authorized

# Read devices already present in this Kali computer's neighbor cache
nighthawk lan-devices

# Email-domain checks (use an address you control)
nighthawk email you@example.com

# Phone numbering metadata (use your own/test number)
nighthawk phone +14155552671

# Local image EXIF metadata (use a file you own)
nighthawk image ./photo.jpg

# Public search (requires a configured search provider API key)
nighthawk search "public cybersecurity research"

# CISA KEV catalog lookup (replace with a real CVE identifier)
nighthawk cve CVE-2021-44228
```

The example domain and IP above are documentation/test targets. Only investigate accounts, images, phone numbers and other information you own or are authorized to assess.

### Saved investigations

```bash
# List saved investigations
nighthawk investigations list

# View one investigation (replace 1 with its ID)
nighthawk investigations view 1
```

### Export reports

The CLI defines `report` as a command, not an `export` subcommand. Use:

```bash
# JSON
nighthawk report 1 --format json --output report

# CSV
nighthawk report 1 --format csv --output report

# HTML
nighthawk report 1 --format html --output report
```

The output path is written in the current working directory unless an absolute path is supplied. The command adds the matching file extension when needed.

### Configuration

Copy the example environment file and add only the API keys you choose to use:

```bash
cp .env.example .env
```

Optional variables include:

- `HIBP_API_KEY` — Have I Been Pwned integration.
- `BRAVE_SEARCH_API_KEY` — Brave Search provider.
- `TAVILY_API_KEY` — Tavily search provider.
- `ABUSEIPDB_API_KEY` — aggregate reputation information for public IPs.
- `NIGHTHAWK_ENABLE_PUBLIC_SEARCH=true` — explicitly enable optional automated public searches for non-email modules using configured Brave/Tavily providers. The `email` command creates manual search links locally, and the search engine receives the email only if you open a link.

Keep `.env` private. Never commit API keys or personal investigation data.

## Troubleshooting

**Command not found**
```bash
cd ~/NIGHTHAWK
source .venv/bin/activate
python -m pip install -e .
nighthawk --help
``
