# Email and IP intelligence

NIGHTHAWK gathers technical signals from legitimate public infrastructure sources.
It cannot guarantee that every possible record exists or is publicly accessible.

## Email investigations

Run `nighthawk email user@example.com` or add an email target to an investigation.
The module reports syntax/domain validation, MX records, a cautious mail-provider
hint, SPF and DMARC records, disposable-domain heuristics, and (when explicitly
configured) Have I Been Pwned breach-status information.

Configure `HIBP_API_KEY` in your local environment to enable the breach-status
check. Without it, the report clearly marks the check as not run. A breach match
does not establish current account compromise. MX/SPF/DMARC data describe the
domain's mail infrastructure; they do not prove that a particular mailbox exists.
NIGHTHAWK does not perform SMTP recipient probing, login attempts, password
discovery, or account enumeration.

## IP investigations

Run `nighthawk ip 8.8.8.8` or add a public IP target to an investigation.
The module reports address-family and routability flags, reverse DNS, RDAP
registration, network range, registry/ASN handle where supplied, and organization
metadata where available. Private and non-global IP addresses are not sent to
external providers.

IP registration and network data identify a network allocation/provider, not a
person or exact physical location. Any location data supplied by a provider is
approximate and should not be treated as a home or device location.

## Data quality and privacy

- Findings include source references and confidence labels where applicable.
- Missing results mean a provider returned no usable data; they do not prove
  that an account, host, or record does not exist.
- External providers receive only the query required for the selected module.
- Use these capabilities for your own accounts, systems, and authorized research.
