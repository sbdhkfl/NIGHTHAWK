# Modules — NIGHTHAWK OSINT

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
