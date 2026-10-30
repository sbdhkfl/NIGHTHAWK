"""HTML report export for investigations.

Produces a self-contained, styled HTML report with NIGHTHAWK branding. HTML
output is escaped so retrieved content is never executed.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nighthawk.core.database import get_session
from nighthawk.core.models import Investigation


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _escape(value: Any) -> str:
    return html.escape(str(value) if value is not None else "")


def _classify_label(confidence: str | None) -> str:
    mapping = {
        "high": "Verified fact",
        "medium": "Observation",
        "low": "Unverified lead",
        "none": "No data",
    }
    return mapping.get((confidence or "none").lower(), "Observation")


def export_html(investigation_id: int, output_path: str | Path) -> Path:
    """Export an investigation as a self-contained HTML report.

    Returns the path to the written file.
    """
    session = get_session()
    try:
        inv = session.query(Investigation).get(investigation_id)
        if not inv:
            raise ValueError(f"investigation {investigation_id} not found")

        findings_rows = []
        for f in inv.findings:
            try:
                result_data = json.loads(f.result_data) if f.result_data else {}
            except (ValueError, TypeError):
                result_data = {"raw": f.result_data}
            findings_rows.append(
                f"""<tr>
                <td>{_escape(f.id)}</td>
                <td>{_escape(f.module)}</td>
                <td>{_escape(f.target)}</td>
                <td>{_escape(_classify_label(f.confidence))}</td>
                <td>{_escape(f.source or "-")}</td>
                <td>{_escape(f.collected_at.isoformat() if f.collected_at else "")}</td>
                <td><pre>{_escape(json.dumps(result_data, indent=2, default=str))}</pre></td>
                </tr>"""
            )

        targets_rows = "".join(
            f"<tr><td>{_escape(t.id)}</td><td>{_escape(t.target_type)}</td>"
            f"<td>{_escape(t.value)}</td></tr>" for t in inv.targets
        )
        sources_rows = "".join(
            f"<tr><td>{_escape(s.url)}</td><td>{_escape(s.module or '')}</td></tr>" for s in inv.sources
        )
        notes_rows = "".join(
            f"<tr><td>{_escape(n.content)}</td><td>{_escape(n.created_at.isoformat() if n.created_at else '')}</td></tr>"
            for n in inv.notes
        )

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NIGHTHAWK OSINT — Investigation Report</title>
<style>
  :root {{ --bg: #0f1115; --panel: #161b22; --accent: #39ff14; --muted: #8b949e; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    background: var(--bg); color: #c9d1d9; margin: 0; padding: 24px;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1000px; margin: 0 auto; }}
  header {{
    border-bottom: 2px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px;
  }}
  h1 {{ color: var(--accent); margin: 0; font-size: 1.5rem; letter-spacing: 0.12em; text-transform: uppercase; }}
  .brand {{ color: #c9d1d9; font-size: 0.85rem; margin-top: 6px; }}
  h2 {{ color: var(--accent); font-size: 1rem; border-bottom: 1px solid #21262d; padding-bottom: 6px; margin-top: 24px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; font-size: 0.9rem; }}
  th {{ background: var(--panel); color: var(--accent); }}
  tr:nth-child(even) td {{ background: #161b22; }}
  .muted {{ color: var(--muted); }}
  .notice {{ background: var(--panel); border: 1px solid #30363d; padding: 12px; margin-top: 24px; font-size: 0.9rem; }}
  pre {{ white-space: pre-wrap; word-break: break-all; background: #0d1117; padding: 8px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>NIGHTHAWK OSINT</h1>
    <div class="brand">See the public footprint. · Investigation Report · v1.0.0</div>
  </header>

  <h2>Investigation</h2>
  <table>
    <tr><th style="width:30%">ID</th><td>{_escape(inv.id)}</td></tr>
    <tr><th>Name</th><td>{_escape(inv.name)}</td></tr>
    <tr><th>Description</th><td>{_escape(inv.description or "-")}</td></tr>
    <tr><th>Created</th><td>{_escape(inv.created_at.isoformat() if inv.created_at else "-")}</td></tr>
    <tr><th>Updated</th><td>{_escape(inv.updated_at.isoformat() if inv.updated_at else "-")}</td></tr>
    <tr><th>Generated</th><td>{_escape(_utcnow_iso())}</td></tr>
  </table>

  <h2>Targets ({len(inv.targets)})</h2>
  <table>
    <tr><th>ID</th><th>Type</th><th>Value</th></tr>
    {targets_rows or "<tr><td colspan='3'>No targets</td></tr>"}
  </table>

  <h2>Findings ({len(inv.findings)})</h2>
  <table>
    <tr><th>ID</th><th>Module</th><th>Target</th><th>Classification</th><th>Source</th><th>Collected</th><th>Result Data</th></tr>
    {findings_rows or "<tr><td colspan='7'>No findings</td></tr>"}
  </table>

  <h2>Sources ({len(inv.sources)})</h2>
  <table>
    <tr><th>URL</th><th>Module</th></tr>
    {sources_rows or "<tr><td colspan='2'>No sources</td></tr>"}
  </table>

  <h2>Notes ({len(inv.notes)})</h2>
  <table>
    <tr><th>Content</th><th>Created</th></tr>
    {notes_rows or "<tr><td colspan='2'>No notes</td></tr>"}
  </table>

  <div class="notice">
    <strong>Limitations and uncertainty:</strong> NIGHTHAWK OSINT collects publicly
    available information only. HTTP 200 responses are never treated as proof of
    account existence. Classifications are cautious: <em>Verified fact</em> (high
    confidence), <em>Observation</em> (medium), <em>Unverified lead</em> (low),
    <em>No data</em> (none). No precise physical geolocation is claimed from IP
    addresses. Retrieved content is treated as untrusted data.
  </div>
</div>
</body>
</html>"""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        return path
    finally:
        session.close()


__all__ = ["export_html"]
