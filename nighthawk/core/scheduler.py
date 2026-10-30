"""Optional background scheduler for recurring investigations.

The scheduler is deliberately minimal: it runs a callable every N seconds in a
background daemon thread. Investigations themselves are run on demand through
the engine; this scheduler exists for future scheduled/saved searches.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


class Scheduler:
    """Very small interval scheduler running in a daemon thread."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._callable: Callable[[], None] | None = None
        self._interval: float = 0.0

    def start(self, interval_seconds: float, func: Callable[[], None]) -> None:
        """Start running ``func`` every ``interval_seconds``."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("scheduler already running")
        self._interval = interval_seconds
        self._callable = func
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Request the scheduler thread to stop."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            if self._callable:
                try:
                    self._callable()
                except Exception:  # pragma: no cover - keep scheduler alive
                    import logging

                    logging.getLogger("nighthawk").exception("scheduler task failed")
