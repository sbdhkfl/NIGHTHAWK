# API — NIGHTHAWK OSINT

NIGHTHAWK OSINT exposes functionality through:

1. **The terminal interface** (`nighthawk CLI`) — see `docs/USAGE.md`.
2. **The web dashboard** (`nighthawk dashboard`) — FastAPI + Jinja2 + HTMX at
   http://127.0.0.1:8000 by default.
3. **The Python engine API** — importable as a library.

## Engine API (Python)

```python
from nighthawk.core.engine import Engine

engine = Engine()
inv = engine.create_investigation("Example recon")
engine.run_module(inv.id, "domain", "example.com", "domain")
summary = engine.investigation_summary(inv.id)
```

From the summary you get targets, findings (module, target, result_data,
source, confidence, collected_at), sources and notes.

Reports:

```python
from nighthawk.reporting import export_json, export_csv, export_html
export_json(inv.id, "report.json")
export_csv(inv.id, "report.csv")
export_html(inv.id, "report.html")
```

## Dashboard routes

- `GET /` — overview
- `GET /investigations` — list
- `GET /investigations/new` — new form
- `POST /investigations` — create
- `GET /investigations/{id}` — detail
- `POST /investigations/{id}/run` — run modules (HTMX)
- `POST /investigations/{id}/module` — single module run (HTMX)
- `POST /investigations/{id}/notes` — add note (HTMX)
- `POST /investigations/{id}/image` — upload image (HTMX)
- `GET /investigations/{id}/export/{json|csv|html}` — export
- `GET /investigations/{id}/graph` — relationship graph page
- `GET /investigations/{id}/graph/data` — graph JSON (nodes/edges)
- `POST /investigations/{id}/delete` — delete

All state-changing dashboard endpoints are protected by a per-session CSRF
token cookie. The dashboard binds to localhost by default.

## Optional provider configuration

- `BRAVE_SEARCH_API_KEY` — Brave Search
- `TAVILY_API_KEY` — Tavily
- `HIBP_API_KEY` — Have I Been Pwned

Read from environment variables; never hardcoded.
