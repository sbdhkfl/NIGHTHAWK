"""Username intelligence module.

Checks a username against a configurable list of public profile URLs and
cautiously classifies each response. HTTP 200 is never treated as proof of
account existence or identity.
"""

from __future__ import annotations

from typing import Any

from nighthawk.modules.base import HttpClient, classify_status

# Public profile URL templates. Each entry: platform name -> URL template with
# {username} placeholder. Ordered from most to least commonly useful.
PLATFORMS: list[tuple[str, str]] = [
    ("GitHub", "https://github.com/{username}"),
    ("GitLab", "https://gitlab.com/{username}"),
    ("Reddit", "https://www.reddit.com/user/{username}"),
    ("Pinterest", "https://www.pinterest.com/{username}/"),
    ("Medium", "https://medium.com/@{username}"),
    ("Hacker News", "https://news.ycombinator.com/user?id={username}"),
    ("Keybase", "https://keybase.io/{username}"),
]


async def _check_username(username: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    async with HttpClient() as client:
        for platform, template in PLATFORMS:
            url = template.format(username=username)
            try:
                response = await client.get(url, module="username")
                classification = classify_status(
                    response.status_code, str(response.url), url
                )
                result_data: dict[str, Any] = {
                    "platform": platform,
                    "url": url,
                    "status_code": response.status_code,
                    "final_url": str(response.url),
                    "redirected": str(response.url) != url,
                    "classification": classification,
                }
                confidence = (
                    "low"
                    if classification in ("likely_exists", "inconclusive")
                    else "none"
                )
            except Exception as exc:  # network failure - record, don't crash
                result_data = {
                    "platform": platform,
                    "url": url,
                    "error": type(exc).__name__,
                    "classification": "error",
                }
                classification = "error"
                confidence = "none"

            findings.append(
                {
                    "module": "username",
                    "target": username,
                    "result_data": result_data,
                    "source": url if classification != "error" else None,
                    "confidence": confidence,
                }
            )
    return findings


def run(username: str, session=None) -> list[dict[str, Any]]:
    """Run username intelligence checks against public profile URLs.

    Returns a list of finding dicts compatible with the investigation engine.
    ``session`` is accepted for interface consistency and is not used directly
    by this module (the engine persists findings).
    """
    import asyncio

    try:
        return asyncio.run(_check_username(username))
    except RuntimeError:
        # asyncio.run cannot be used when a running loop already exists (e.g.
        # inside an async web handler). Fall back to a fresh loop in a thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _check_username(username))
            return future.result()


__all__ = ["run", "PLATFORMS"]
