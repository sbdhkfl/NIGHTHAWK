"""Simple token-bucket rate limiter per provider.

Used to respect per-provider request rates without blocking the whole
application longer than necessary.
"""

from __future__ import annotations

import time
from threading import Lock


class RateLimiter:
    """Token bucket rate limiter (requests per second)."""

    def __init__(self, rate_per_second: float = 1.0) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = rate_per_second
        self.tokens = rate_per_second
        self.last = time.monotonic()
        self._lock = Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                sleep_for = (1.0 - self.tokens) / self.rate
            # Unreachable but keeps type checkers happy about the loop.
            time.sleep(sleep_for)  # pragma: no cover

    def available(self) -> float:
        """Return currently available tokens (non-blocking)."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last = now
            return self.tokens
