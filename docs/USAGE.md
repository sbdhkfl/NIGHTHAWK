# Usage — NIGHTHAWK OSINT

Activate the virtual environment before running commands:

```bash
cd ~/NIGHTHAWK
source .venv/bin/activate
```

Use `nighthawk --help` to see the commands registered by your installed version. Use `nighthawk COMMAND --help` for command-specific help.

## Individual modules

```bash
# Public username/profile URL checks
nighthawk username YOUR_USERNAME

# Domain DNS and RDAP intelligence
nighthawk domain example.com

# Investigate the domain behind an HTTP or HTTPS URL
nighthawk url https://example.com/path

# DNS records only
nighthawk dns example.com

# Passive subdomain discovery from Certificate Transparency logs
nighthawk subdomains example.com

# Public IP registration and reverse DNS (public IPs only; no port scanning)
nighthawk ip 8.8.8.8

# Generate API-free public search links for an email by category
nighthawk email-public you@example.com

# Check common TCP ports on one private LAN IPv4 device you administer
nighthawk ip-ports 192.168.1.1 --authorized

# Read devices already in this Kali host's ARP/NDP neighbor cache
nighthawk lan-devices

# Email technical checks plus API-free manual public-search links
nighthawk email you@example.com

# Phone numbering metadata; include country calling code
nighthawk phone +14155552671

# Extract metadata from a local image
nighthawk image ./photo.jpg

# Public search; configure a supported provider API key first
nighthawk search "public cybersecurity research"

# Look up a CVE in CISA's Known Exploited Vulnerabilities catalog
nighthawk cve CVE-2021-44228
```

Use your own accounts, contact details and image files, or targets you have permission to investigate. The username module checks public profile pages; it cannot prove that you own an account or reveal every service where you have logged in.

## Saved investigations

Each individual module command creates an investigation automatically.

```bash
# List saved investigations
nighthawk investigations list

# View findings for an investigation ID
nighthawk investigations view 1
```

Replace `1` with an ID shown by the list command.

## Export reports

**Correct syntax:** `report` is a top-level command. There is no `report export` subcommand.

```bash
nighthawk report 1 --format json --output report
nighthawk report 1 --format csv --output report
nighthawk report 1 --format html --output report
```

Replace `1` with the investigation ID. NIGHTHAWK adds the appropriate extension if it is not already present. Files are written relative to the current directory unless you provide an absolute output path.

## Dashboard

Install the optional dashboard dependencies once:

```bash
python -m pip install -e ".[dashboard]"
```

Start the dashboard:

```bash
nighthawk dashboard
```

Open http://127.0.0.1:8000 on the same computer. The dashboard binds to localhost by default.

## Configuration

Optional provider keys are read from environment variables in `.env`. Start from the example file:

```bash
cp .env.example .env
```

Supported optional keys include `HIBP_API_KEY`, `BRAVE_SEARCH_API_KEY`, `TAVILY_API_KEY` and `ABUSEIPDB_API_KEY`. The single `nighthawk email EMAIL` command performs technical mail-domain checks and creates API-free public search links. NIGHTHAWK does not send the email to a search provider; the search engine receives it only if you open a link. Review results manually: they are not proof of registration. Optional automated searches for other modules may still use configured provider keys.

## Troubleshooting

```bash
# Show all registered commands
nighthawk --help

# Show syntax for one command
nighthawk email --help
nighthawk report --help
nighthawk investigations --help

# Reinstall the current checkout into the active virtual environment
python -m pip install -e .
``

If a command fails, copy the complete traceback and the exact command (remove personal information and API keys first).

## Confidence labels

- **High:** directly observed evidence, such as a DNS record.
- **Medium:** evidence from a public registry or Certificate Transparency source.
- **Low:** an unverified lead, such as a possible public profile match.
- **None:** no confidence-bearing evidence was available.

A result count is not a count of confirmed accounts or breaches. Review each finding, source and confidence level before drawing conclusions.


## IP and local network commands

- `nighthawk ip PUBLIC_IP` — public registration, network range and reverse DNS only.
- `nighthawk ip-ports PRIVATE_LAN_IP --authorized` — checks a fixed list of common TCP ports on one RFC1918 private IPv4 address. It does not exploit, authenticate, or test vulnerabilities. An open port is not itself a vulnerability.
- `nighthawk lan-devices` — reads the current Linux ARP/NDP neighbor cache. It is passive and may not list every device connected to the router.

Only use the LAN commands on devices and networks you own or administer.
