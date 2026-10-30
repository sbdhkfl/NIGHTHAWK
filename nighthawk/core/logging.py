"""Structured, secret-safe logging for NIGHTHAWK OSINT.

Network failures and errors are logged without emitting request bodies,
headers that may contain credentials, or API keys.
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler


def get_logger(name: str = "nighthawk") -> logging.Logger:
    """Return a configured logger with Rich console output."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = RichHandler(
        show_time=True,
        show_level=True,
        show_path=False,
        rich_tracebacks=True,
        markup=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_request(logger: logging.Logger, method: str, url: str, timeout: float | None = None) -> None:
    """Log an outgoing request safely (method + URL only, no body/headers)."""
    detail = f" timeout={timeout}s" if timeout is not None else ""
    logger.info("[nighthawk] %s %s%s", method, url, detail)


def log_response(
    logger: logging.Logger,
    method: str,
    url: str,
    status_code: int | None,
    *,
    error: str | None = None,
) -> None:
    """Log an HTTP response safely (status code only)."""
    if error:
        logger.warning("[nighthawk] %s %s -> ERROR: %s", method, url, error)
    else:
        logger.info("[nighthawk] %s %s -> %s", method, url, status_code)
