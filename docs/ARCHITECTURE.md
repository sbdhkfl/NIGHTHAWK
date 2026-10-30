# Architecture — NIGHTHAWK OSINT

## Layers

```
CLI (Typer/Rich) ────┐
                     ├─► Engine (nighthawk.core.engine)
Dashboard (FastAPI) ─┘                         │
                                               ▼
                                    Intelligence modules (nighthawk.modules)
                                    Integrations   (nighthawk.integrations)
                                               │
                                               ▼
                                       SQLite (SQLAlchemy)
```

## Core

- `core/config.py` — environment-based settings (`.env` supported).
- `core/database.py` — SQLAlchemy engine, session, `init_db()`.
- `core/models.py` — Investigation, Target, Finding, Source, Note, ActivityLog.
- `core/engine.py` — investigation lifecycle, module registry, CRUD.
- `core/validation.py` — target validators (username, domain, IP, email, image).
- `core/rate_limiter.py` — per-provider token bucket.
- `core/logging.py` — secret-safe structured logging.
- `core/scheduler.py` — minimal interval scheduler.

## Modules

Each module exposes `run(target, session) -> list[finding dict]`:

- `username.py` — public profile checks via shared HttpClient.
- `domain.py` / `dns.py` — DNS via dnspython + RDAP.
- `subdomains.py` — crt.sh CT logs.
- `ip_intel.py` — RDAP + reverse DNS; public IPs only.
- `email.py` — syntax/MX/disposable/optional HIBP.
- `image_metadata.py` — Pillow EXIF extraction (local files).
- `search.py` — provider-based search.

## Integrations

- `rdap.py` — public RDAP lookup (domain + IP).
- `crtsh.py` — Certificate Transparency query helper.
- `hibp.py` — Have I Been Pwned (API key required).
- `search_providers.py` — Brave Search, Tavily.

## Reporting

- `reporting/json_export.py`, `csv_export.py`, `html_report.py`.

## Dashboard

- `dashboard/app.py` — FastAPI app, uvicorn entry (localhost default).
- `dashboard/routes.py` — routes, CSRF protection, HTMX partials, graph data.
- `dashboard/templates/` — Jinja2 templates (base, pages, partials).
- `dashboard/static/` — CSS, JS.

## Security

- SSRF guard: outbound HTTP limited to http/https, private/local hosts refused.
- Input validation at trust boundaries.
- HTML escaping everywhere.
- CSRF tokens on state-changing POSTs.
- No secrets in logs; no hardcoded keys.

## Data retention

Investigations, findings, sources, notes and activity logs are stored locally in
SQLite. There is no built-in retention policy; delete investigations with the
CLI or dashboard to remove their data.
