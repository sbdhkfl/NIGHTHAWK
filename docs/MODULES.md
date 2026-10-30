# Modules — NIGHTHAWK OSINT

## Public reference discovery (shared integration)

When `NIGHTHAWK_ENABLE_PUBLIC_SEARCH=true` and at least one Brave/Tavily API key is configured, email, username, domain and public-IP modules can search indexed public pages. Email searches run separate social-media, developer, professional/portfolio, forums/communities and gaming/streaming categories. The exact email is sent to the configured provider. Results are marked as low-confidence public references and do not prove registration, identity or account ownership. The feature is disabled by default. Phone lookups remain numbering-plan metadata; image analysis remains local-only EXIF extraction.

## A. Username intelligence (`username`)

Checks a username against public profile URLs:

- GitHub, GitLab, Reddit, Pinterest, Medium, Hacker News, Keybase

Each result records: platform, URL, HTTP status code, final URL (redirects
detected), and a cautious classification (`likely_exists`, `likely_not_exists`,
`inconclusive`, `blocked`, `error`). HTTP 200 is **not** proof of account
existence.

## B. Domain intelligence (`domain`)

DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA. Plus RDAP registration lookup
(registrar, registrant, dates, nameservers when available).

## C. DNS intelligence (`dns`)

Standalone DNS resolution of the same record set as domain intelligence.

## D. Subdomain intelligence (`subdomains`)

Passive discovery via crt.sh Certificate Transparency data. Results are
deduplicated with source (`crt.sh`) and timestamp. Optional DNS resolution per
subdomain. No intrusive scanning.

## E. IP intelligence (`ip`)

IPv4/IPv6 validation. Private, loopback, multicast and reserved addresses are
rejected for external lookups. Public IP lookups return: reverse DNS, RDAP
registration, ASN/network handle, organization, network range
(start/end address, CIDR). Country-level registration info only — no precise
geolocation is claimed.

## F. Email intelligence (`email`)

- Syntax validation
- MX records and cautious mail-provider infrastructure hints
- SPF and DMARC domain authentication records
- Disposable email domain detection (maintained internal list, non-exhaustive)
- Optional Have I Been Pwned breach-status lookup — only when `HIBP_API_KEY` is explicitly set

These checks do not verify that a specific mailbox exists. NIGHTHAWK does not
perform SMTP recipient probing, account enumeration, login attempts, or password
discovery. An HIBP match is not proof of current account compromise.

## G. Image metadata intelligence (`image`)

Extracts EXIF metadata from local images: format, dimensions, camera make/model,
timestamps, GPS coordinates (when present). Images are never uploaded externally.
Uploads are restricted to supported formats and limited to 10 MiB by default.

## H. Public search intelligence (`search`)

Provider-based search via configured API keys:

- Brave Search (`BRAVE_SEARCH_API_KEY`)
- Tavily (`TAVILY_API_KEY`)

No search engine scraping. Results include provider, title, URL, snippet and
search timestamp.


## I. Phone metadata (`phone`)

Accepts international numbers with a country calling code and reports formatting, numbering region, calling code, possible/valid numbering-plan status, and number type. It does not identify subscribers or locate devices.

## J. Optional IP reputation (`ip`)

When `ABUSEIPDB_API_KEY` is configured, public IP investigations query AbuseIPDB for aggregate reputation signals. The queried IP is sent to that provider. Private and non-global IPs remain blocked. Scores are signals, not proof of malicious activity.


## K. Defensive vulnerability intelligence (`kev`)

The `nighthawk cve CVE-2024-12345` command checks a CVE identifier against CISA's public Known Exploited Vulnerabilities catalog. This is catalog intelligence only: NIGHTHAWK does not probe, scan, or exploit hosts.


## L. Private LAN TCP exposure check (`ip-ports`)

Checks a fixed set of common TCP ports on one RFC1918 private IPv4 address.
The CLI requires `--authorized`. It reports open ports and cautious service
exposure notes; it does not fingerprint versions, authenticate, exploit, or
claim that an open port is a confirmed vulnerability. Public IPs and CIDR
ranges are rejected.

## M. Local neighbor inventory (`lan-devices`)

Reads the Linux host's existing ARP/NDP neighbor cache using `ip neigh show`.
This is passive and may omit sleeping or previously unseen devices. It is not
a complete router client list and does not identify device owners.

## N. Categorized email public references (`email-public`)

Searches public indexed pages in social media, developer, professional/portfolio,
forums/communities, and gaming/streaming categories. Requires the explicit
public-search opt-in and a configured Brave or Tavily API key. It does not use
login, password-reset, or account-recovery endpoints and cannot confirm whether
an email is registered with a service.
