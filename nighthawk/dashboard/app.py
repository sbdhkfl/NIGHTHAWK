"""NIGHTHAWK OSINT web dashboard (FastAPI).

Serves a responsive, cybersecurity-themed dashboard on localhost by default.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from nighthawk.dashboard.routes import router

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

app = FastAPI(
    title="NIGHTHAWK OSINT",
    description="See the public footprint.",
    version="1.0.0",
)

app.include_router(router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def main() -> None:
    """Launch the dashboard with uvicorn, bound to localhost by default."""
    import uvicorn

    from nighthawk.core.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "nighthawk.dashboard.app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
