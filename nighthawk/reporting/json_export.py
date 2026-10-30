"""JSON report export for investigations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nighthawk.core.database import get_session
from nighthawk.core.models import Investigation


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def export_json(investigation_id: int, output_path: str | Path | None = None) -> dict[str, Any]:
    """Export an investigation as a JSON-serializable dict (and optionally to file).

    Returns the report dict.
    """
    session = get_session()
    try:
        inv = session.query(Investigation).get(investigation_id)
        if not inv:
            raise ValueError(f"investigation {investigation_id} not found")

        report: dict[str, Any] = {
            "framework": "NIGHTHAWK OSINT",
            "version": "1.0.0",
            "report_type": "json",
            "generated_at": _utcnow_iso(),
            "investigation": {
                "id": inv.id,
                "name": inv.name,
                "description": inv.description,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
            },
            "targets": [],
            "findings": [],
            "sources": [],
            "notes": [],
        }

        for t in inv.targets:
            report["targets"].append(
                {
                    "id": t.id,
                    "type": t.target_type,
                    "value": t.value,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                }
            )

        for f in inv.findings:
            result_data = {}
            try:
                result_data = json.loads(f.result_data) if f.result_data else {}
            except (ValueError, TypeError):
                result_data = {"raw": f.result_data}
            report["findings"].append(
                {
                    "id": f.id,
                    "module": f.module,
                    "target": f.target,
                    "result_data": result_data,
                    "source": f.source,
                    "confidence": f.confidence,
                    "collected_at": f.collected_at.isoformat() if f.collected_at else None,
                }
            )

        for s in inv.sources:
            report["sources"].append(
                {"url": s.url, "module": s.module, "recorded_at": s.recorded_at.isoformat() if s.recorded_at else None}
            )

        for n in inv.notes:
            report["notes"].append(
                {
                    "content": n.content,
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                }
            )

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

        return report
    finally:
        session.close()


__all__ = ["export_json"]
