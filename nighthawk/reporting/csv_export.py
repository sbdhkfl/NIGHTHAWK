"""CSV report export for investigations."""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

from nighthawk.core.database import get_session
from nighthawk.core.models import Investigation


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def export_csv(investigation_id: int, output_path: str | Path) -> Path:
    """Export an investigation's targets and findings to CSV.

    Returns the path to the written file.
    """
    session = get_session()
    try:
        inv = session.query(Investigation).get(investigation_id)
        if not inv:
            raise ValueError(f"investigation {investigation_id} not found")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["nighthawk-osint", "1.0.0", "csv_export", _utcnow_iso()])
            writer.writerow([])
            writer.writerow(["investigation_id", inv.id])
            writer.writerow(["name", inv.name])
            writer.writerow([])
            writer.writerow(["finding_id", "module", "target", "source", "confidence", "collected_at", "result_data"])
            for f in inv.findings:
                writer.writerow(
                    [
                        f.id,
                        f.module,
                        f.target,
                        f.source or "",
                        f.confidence or "",
                        f.collected_at.isoformat() if f.collected_at else "",
                        f.result_data or "",
                    ]
                )
            writer.writerow([])
            writer.writerow(["source_url", "module", "recorded_at"])
            for s in inv.sources:
                writer.writerow(
                    [s.url, s.module or "", s.recorded_at.isoformat() if s.recorded_at else ""]
                )

        return path
    finally:
        session.close()


__all__ = ["export_csv"]
