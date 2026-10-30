# NIGHTHAWK OSINT

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**See the public footprint.**

NIGHTHAWK is a modular OSINT and personal digital-footprint investigation framework with a terminal interface and a local web dashboard.

## What it can investigate

- **Email:** technical mail-domain checks plus API-free, category-specific public search links for social media, developer, professional/portfolio, forums/communities, and gaming/streaming. Results must be reviewed manually and do not verify registrations.
- **Username:** possible matching public profiles on supported platforms. A match is a lead, not proof that you own or logged into an account.
- **Domain / URL:** DNS and RDAP information; `nighthawk url https://example.com/path` extracts the hostname and investigates the domain without crawling the page.
- **Subdomains:** passive Certificate Transparency discovery.
- **IP address:** public IP registration, network range, organization and reverse DNS. Separate `ip-ports` checks a fixed list of common TCP ports on one RFC1918 private LAN IPv4 address; `lan-devices` reads the local Linux neighbor cache. Neither exploits services.
- **Phone:** international numbering-plan metadata; no subscriber identification or device tracking.
- **Image:** local EXIF metadata, including camera make/model, timestamps and GPS coordinates when embedded.
- **CVE:** lookup in CISA's Known Exploited Vulnerabilities catalog; no scanning or exploitation.
- **Public references:** manual public-search links for email (no API key required); optional automated public-page searches for other identifiers can still use configured providers. Search links are not proof of account registration.
- **Investigations and reports:** save findings locally and export JSON, CSV or HTML.

NIGHTHAWK cannot reveal every website where an email address has logged in. Private login history is held by each service or may be available in your own browser/password manager. Public account checks can return false positives and false negatives.

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
python -m pip install -e ".[dashboard]"

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
python -m pip install -e ".[dashboard]"
nighthawk --help
```

### Update an existing clone

```bash
cd ~/NIGHTHAWK
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -e .
python -m pip install -e ".[dashboard]"
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

# Generate API-free public search links for an email by category
nighthawk email-public you@example.com

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

### Dashboard

```bash
nighthawk dashboard
```

Open **http://127.0.0.1:8000** on the same computer. The dashboard binds to localhost by default.

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
- `NIGHTHAWK_ENABLE_PUBLIC_SEARCH=true` — explicitly enable optional automated public searches for non-email modules using configured Brave/Tavily providers. The `email-public` command does not use these APIs: it creates manual search links, and the search engine receives the email only if you open a link.

Keep `.env` private. Never commit API keys or personal investigation data.

## Troubleshooting

**Command not found**
```bash
cd ~/NIGHTHAWK
source .venv/bin/activate
python -m pip install -e .
nighthawk --help
``

**Dashboard dependencies missing**
```bash
source .venv/bin/activate
python -m pip install -e ".[dashboard]"
``

**Check a command's actual syntax**
```bash
nighthawk --help
nighthawk email --help
nighthawk report --help
nighthawk investigations --help
``

**Installation/build errors:** use a documented Python version (3.11–3.13), ensure the virtual environment is active, and share the complete error output when requesting help.

## Privacy, accuracy and safety

- Public profile checks are indicative; HTTP 200 is not proof of account ownership.
- Email checks do not verify mailbox access or reveal all services where an address has logged in.
- Image files are processed locally; GPS is reported only when embedded in the file. Images are never uploaded to search providers.
- The `email-public` command generates search links locally without calling an API. If you open a link, the search engine receives the email query. Other optional automated identifier searches send queries to configured third-party providers. Dating and adult-content account discovery is not included.
- `ip-ports` accepts only RFC1918 private IPv4 addresses and requires `--authorized`; it checks a fixed set of common TCP ports. Open ports are exposure signals, not confirmed vulnerabilities.
- `lan-devices` reads only the Kali host's existing ARP/NDP neighbor cache; it may omit devices and is not the router's authoritative client list.
- IP location is not precise geolocation.
- No credential theft, password cracking, phishing, malware, unauthorized login, authentication bypass, intrusive scanning or exploitation.
- Respect provider terms, rate limits, privacy and applicable law.

Read [docs/USAGE.md](docs/USAGE.md), [docs/MODULES.md](docs/MODULES.md) and [SECURITY.md](SECURITY.md).

## License and contributing

Released under the MIT License. See [LICENSE](LICENSE). Contributions, bug reports and improvements are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
