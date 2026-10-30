"""Shared foundation for NIGHTHAWK intelligence modules.

Provides a reusable async HTTP client with a browser-like user agent, per-host
rate limiting, and SSRF protection (outbound requests are resolved and private/
loopback/resolved-local addresses are rejected).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import dns.resolver
import httpx

from nighthawk.core.config import get_settings
from nighthawk.core.logging import log_request, log_response
from nighthawk.core.rate_limiter import RateLimiter

logger = __import__("logging").getLogger("nighthawk.modules")

# Browser-like, non-identifying user agent. We never pretend to be a specific
# logged-in user.
USER_AGENT = "NIGHTHAWK-OSINT/1.0.0 (+https://example.local/nighthawk)"

# Per-module rate limiters (requests per second).
_RATE_LIMITERS: dict[str, RateLimiter] = {}


def rate_limiter(name: str, rate: float | None = None) -> RateLimiter:
    """Return a cached rate limiter for a module/provider."""
    if name not in _RATE_LIMITERS:
        settings = get_settings()
        _RATE_LIMITERS[name] = RateLimiter(rate if rate is not None else settings.RATE_LIMIT_DEFAULT)
    return _RATE_LIMITERS[name]


def _is_blocked_ip(host: str) -> bool:
    """Return True if ``host`` resolves to a private/loopback/local address."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
        )
    # Resolve hostname and inspect all returned addresses.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True  # Cannot resolve -> treat as unsafe
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_link_local
        ):
            return True
    return False


def assert_outbound_safe(url: str) -> None:
    """Raise ValueError if the URL targets a local/private address (SSRF guard)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme '{parsed.scheme}'")
    if _is_blocked_ip(host):
        raise ValueError(f"refusing to connect to local/private host: {host}")


class HttpClient:
    """Shared async HTTP client with safe defaults."""

    def __init__(self, timeout: float | None = None) -> None:
        settings = get_settings()
        self.timeout = timeout if timeout is not None else settings.HTTP_TIMEOUT
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpClient:
        self._client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            max_redirects=5,
        )
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(
        self, url: str, module: str = "nighthawk", extra_headers: dict[str, str] | None = None
    ) -> httpx.Response:
        assert_outbound_safe(url)
        rate_limiter(module).acquire()
        assert self._client is not None
        log_request(logger, "GET", url, timeout=self.timeout)
        try:
            response = await self._client.get(url, headers=extra_headers or None)
        except httpx.RequestError as exc:
            log_response(logger, "GET", url, None, error=str(exc))
            raise
        log_response(logger, "GET", url, response.status_code)
        return response


def classify_status(status_code: int, final_url: str, requested_url: str) -> str:
    """Cautiously classify an HTTP response for profile-existence checks.

    HTTP 200 is never treated as proof of account existence. Returns one of:
    'likely_exists', 'likely_not_exists', 'inconclusive', 'blocked', 'error'.
    """
    if 400 <= status_code < 500:
        if status_code in (401, 403, 429):
            return "blocked"
        return "likely_not_exists"
    if 500 <= status_code < 600:
        return "inconclusive"
    if status_code == 200:
        return "likely_exists" if final_url == requested_url else "inconclusive"
    if 300 <= status_code < 400:
        return "inconclusive"
    return "inconclusive"


async def resolve_dns(domain: str, record_types: list[str] | None = None) -> dict[str, list[str]]:
    """Resolve DNS records for a domain, returning {type: [values]}."""
    record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results: dict[str, list[str]] = {rt: [] for rt in record_types}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10.0
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            for rdata in answers:
                results[rtype].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            results[rtype] = []
        except Exception:  # pragma: no cover - defensive
            logger.exception("DNS resolution failed for %s %s", domain, rtype)
            results[rtype] = []
    return results
