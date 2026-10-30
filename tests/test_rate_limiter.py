"""Tests for rate limiting."""

import time

from nighthawk.core.rate_limiter import RateLimiter


def test_rate_limiter_blocks_then_refills():
    limiter = RateLimiter(rate_per_second=10.0)
    start = time.monotonic()
    for _ in range(11):
        limiter.acquire()
    elapsed = time.monotonic() - start
    # First 10 are instant; the 11th must wait roughly 0.1s.
    assert elapsed >= 0.09


def test_available_tokens():
    limiter = RateLimiter(rate_per_second=5.0)
    assert limiter.available() <= 5.0
