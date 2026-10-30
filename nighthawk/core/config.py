"""NIGHTHAWK OSINT configuration.

All settings are read from environment variables (loaded from a `.env` file if
present via python-dotenv when available). Optional API integrations are
disabled by default and require explicit configuration. No secrets are ever
committed or logged.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

try:  # pragma: no cover - optional dependency
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs):  # type: ignore[no-redef]
        return False


# Load .env from the project root if it exists, without overriding existing env.
_load_env_path = Path(__file__).resolve().parents[2] / ".env"
if _load_env_path.exists():
    load_dotenv(_load_env_path, override=False)


class Settings:
    """Application-wide configuration.

    Values are read from environment variables on each instantiation so that
    tests can swap ``NIGHTHAWK_DATABASE_URL`` etc. after import.
    """

    def __init__(self) -> None:
        # --- Database ---
        self.DATABASE_URL: str = os.getenv("NIGHTHAWK_DATABASE_URL", "sqlite:///nighthawk.db")
        self.DATA_DIR: Path = Path(os.getenv("NIGHTHAWK_DATA_DIR", "nighthawk_data"))

        # --- Dashboard ---
        self.HOST: str = os.getenv("NIGHTHAWK_HOST", "127.0.0.1")
        self.PORT: int = int(os.getenv("NIGHTHAWK_PORT", "8000"))
        self.DEBUG: bool = os.getenv("NIGHTHAWK_DEBUG", "false").lower() == "true"

        # --- Optional API keys (never hardcoded) ---
        self.BRAVE_SEARCH_API_KEY: str | None = os.getenv("BRAVE_SEARCH_API_KEY") or None
        self.TAVILY_API_KEY: str | None = os.getenv("TAVILY_API_KEY") or None
        self.HIBP_API_KEY: str | None = os.getenv("HIBP_API_KEY") or None
        self.ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY") or None

        # --- Network / rate limits ---
        self.HTTP_TIMEOUT: float = float(os.getenv("NIGHTHAWK_HTTP_TIMEOUT", "15"))
        self.RATE_LIMIT_DEFAULT: float = float(os.getenv("NIGHTHAWK_RATE_LIMIT_DEFAULT", "1.0"))

        # --- Image upload limits ---
        self.MAX_UPLOAD_BYTES: int = int(os.getenv("NIGHTHAWK_MAX_UPLOAD_BYTES", "10485760"))  # 10 MiB
        self.ALLOWED_IMAGE_EXTENSIONS: frozenset[str] = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff"})


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the settings cache (primarily for tests)."""
    get_settings.cache_clear()  # type: ignore[attr-defined]
