"""NIGHTHAWK OSINT dashboard routes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from nighthawk.core.config import get_settings
from nighthawk.core.engine import Engine, EngineError
from nighthawk.core.logging import get_logger
from nighthawk.reporting import export_csv, export_html, export_json

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

router = APIRouter()
logger = get_logger("nighthawk.dashboard")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


_engine_instance: Engine | None = None


def _engine() -> Engine:
    """Return a shared engine instance across requests."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = Engine()
    return _engine_instance


def _render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    context.setdefault("request", request)
    context.setdefault("version", "1.0.0")
    context.setdefault("csrf_token", request.cookies.get("nighthawk_csrf", ""))
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def _csrf_token(request: Request) -> str:
    """Simple per-session CSRF token stored in a signed cookie."""
    import hashlib
    import hmac
    import os

    secret = get_settings().HOST.encode() + b"nighthawk-csrf"
    token = request.cookies.get("nighthawk_csrf")
    if not token:
        token = os.urandom(16).hex()
    # Bind token to a session-ish value; cookie only.
    signature = hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{token}.{signature}"


def _set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie("nighthawk_csrf", token, httponly=True, samesite="lax")


def _verify_csrf(request: Request, csrf_token: str | None = Form(None)) -> None:
    cookie_token = request.cookies.get("nighthawk_csrf")
    if not cookie_token or not csrf_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if cookie_token != csrf_token:
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #


@router.get("/", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    engine = _engine()
    invs = engine.list_investigations()
    total_findings = 0
    for inv in invs:
        total_findings += len(inv.findings)
    modules = [
        {"name": "username", "label": "Username Intel"},
        {"name": "domain", "label": "Domain Intel"},
        {"name": "dns", "label": "DNS Intel"},
        {"name": "subdomains", "label": "Subdomain Intel"},
        {"name": "ip", "label": "IP Intel"},
        {"name": "email", "label": "Email Intel"},
        {"name": "image", "label": "Image Intel"},
        {"name": "search", "label": "Search Intel"},
    ]
    recent = []
    for inv in invs[:5]:
        recent.append(
            {
                "id": inv.id,
                "name": inv.name,
                "targets": [t.value for t in inv.targets[:3]],
                "updated": inv.updated_at.strftime("%Y-%m-%d %H:%M"),
            }
        )
    response = _render(
        request,
        "index.html",
        investigations=invs,
        investigation_count=len(invs),
        finding_count=total_findings,
        modules=modules,
        recent=recent,
    )
    _set_csrf_cookie(response, _csrf_token(request))
    return response


# --------------------------------------------------------------------------- #
# Investigations list
# --------------------------------------------------------------------------- #


@router.get("/investigations", response_class=HTMLResponse)
def investigations_list(request: Request) -> HTMLResponse:
    engine = _engine()
    invs = engine.list_investigations()
    response = _render(request, "investigations.html", investigations=invs)
    _set_csrf_cookie(response, _csrf_token(request))
    return response


# --------------------------------------------------------------------------- #
# New investigation
# --------------------------------------------------------------------------- #


@router.get("/investigations/new", response_class=HTMLResponse)
def new_investigation(request: Request) -> HTMLResponse:
    response = _render(request, "new_investigation.html")
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.post("/investigations", response_class=HTMLResponse)
def create_investigation(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    csrf_token: str | None = Form(None),
) -> HTMLResponse:
    _verify_csrf(request, csrf_token)
    engine = _engine()
    try:
        inv = engine.create_investigation(name.strip(), description.strip() or None)
    except EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return RedirectResponse(url=f"/investigations/{inv.id}", status_code=303)


# --------------------------------------------------------------------------- #
# Investigation detail
# --------------------------------------------------------------------------- #


@router.get("/investigations/{investigation_id}", response_class=HTMLResponse)
def investigation_detail(request: Request, investigation_id: int) -> HTMLResponse:
    engine = _engine()
    summary = engine.investigation_summary(investigation_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Investigation not found")
    response = _render(
        request,
        "investigation.html",
        investigation=summary,
    )
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.post("/investigations/{investigation_id}/run", response_class=HTMLResponse)
async def run_investigation(
    request: Request,
    investigation_id: int,
    modules: str = Form(""),
    csrf_token: str | None = Form(None),
) -> HTMLResponse:
    _verify_csrf(request, csrf_token)
    engine = _engine()
    summary = engine.investigation_summary(investigation_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Investigation not found")

    selected = [m.strip() for m in modules.split(",") if m.strip()]
    if not selected:
        selected = ["username", "domain", "dns", "ip", "email", "search"]

    targets = [{"type": t["type"], "value": t["value"]} for t in summary["targets"]]
    all_results: dict[str, Any] = {}
    for target in targets:
        for module in selected:
            # Skip image module for non-image targets; it is run via its own endpoint.
            if module == "image" and target["type"] != "image":
                continue
            try:
                found = await run_in_threadpool(
                    engine.run_module,
                    investigation_id,
                    target["type"],
                    target["value"],
                    module,
                )
            except EngineError:
                continue
            except Exception:  # pragma: no cover - defensive
                logger.exception("module %s failed", module)
                continue
            all_results.setdefault(f"{target['type']}:{target['value']}", []).extend(found)

    response = _render(
        request,
        "partials/results_table.html",
        results=all_results,
    )
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.post("/investigations/{investigation_id}/module", response_class=HTMLResponse)
async def run_single_module(
    request: Request,
    investigation_id: int,
    module: str = Form(...),
    target: str = Form(...),
    target_type: str = Form(...),
    csrf_token: str | None = Form(None),
) -> HTMLResponse:
    """Run a single module against a single target (HTMX progressive results)."""
    _verify_csrf(request, csrf_token)
    engine = _engine()
    try:
        findings = await run_in_threadpool(
            engine.run_module, investigation_id, target_type, target, module
        )
    except EngineError as exc:
        return HTMLResponse(f"<div class='error'>{str(exc)}</div>", status_code=400)
    response = _render(
        request,
        "partials/module_result.html",
        module=module,
        target=target,
        findings=findings,
    )
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.post("/investigations/{investigation_id}/notes", response_class=HTMLResponse)
def add_note(
    request: Request,
    investigation_id: int,
    content: str = Form(...),
    csrf_token: str | None = Form(None),
) -> HTMLResponse:
    _verify_csrf(request, csrf_token)
    engine = _engine()
    try:
        note = engine.add_note(investigation_id, content)
    except EngineError as exc:
        return HTMLResponse(f"<div class='error'>{str(exc)}</div>", status_code=400)
    response = _render(request, "partials/note.html", note=note)
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.post("/investigations/{investigation_id}/delete", response_class=HTMLResponse)
def delete_investigation(request: Request, investigation_id: int) -> HTMLResponse:
    engine = _engine()
    ok = engine.delete_investigation(investigation_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Investigation not found")
    response = RedirectResponse(url="/investigations", status_code=303)
    _set_csrf_cookie(response, _csrf_token(request))
    return response


# --------------------------------------------------------------------------- #
# Image upload
# --------------------------------------------------------------------------- #


@router.post("/investigations/{investigation_id}/image", response_class=HTMLResponse)
async def upload_image(
    request: Request,
    investigation_id: int,
    file: UploadFile = File(...),  # type: ignore[name-defined]
    csrf_token: str | None = Form(None),
) -> HTMLResponse:
    _verify_csrf(request, csrf_token)
    engine = _engine()
    settings = get_settings()
    data_dir = settings.DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    contents = file.file.read()
    if len(contents) > settings.MAX_UPLOAD_BYTES:
        return HTMLResponse("<div class='error'>File too large.</div>", status_code=400)

    # Sanitize filename.
    safe_name = Path(file.filename or "image.jpg").name
    from nighthawk.core.validation import validate_image_filename

    try:
        validate_image_filename(safe_name)
    except Exception:
        return HTMLResponse("<div class='error'>Unsupported image format.</div>", status_code=400)

    dest = data_dir / safe_name
    dest.write_bytes(contents)

    try:
        findings = await run_in_threadpool(engine.run_module, investigation_id, "image", str(dest), "image")
    except Exception as exc:  # pragma: no cover - defensive
        return HTMLResponse(f"<div class='error'>Failed to process image: {exc}</div>", status_code=400)

    response = _render(
        request,
        "partials/module_result.html",
        module="image_metadata",
        target=safe_name,
        findings=findings,
    )
    _set_csrf_cookie(response, _csrf_token(request))
    return response


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #


@router.get("/investigations/{investigation_id}/export/{fmt}")
def export_report(request: Request, investigation_id: int, fmt: str) -> Response:
    engine = _engine()
    if not engine.get_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found")

    from nighthawk.core.config import get_settings

    data_dir = get_settings().DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path = data_dir / f"investigation_{investigation_id}.json"
        export_json(investigation_id, path)
        media = "application/json"
    elif fmt == "csv":
        path = data_dir / f"investigation_{investigation_id}.csv"
        export_csv(investigation_id, path)
        media = "text/csv"
    elif fmt == "html":
        path = data_dir / f"investigation_{investigation_id}.html"
        export_html(investigation_id, path)
        media = "text/html"
    else:
        raise HTTPException(status_code=400, detail="Unknown format")

    return Response(
        content=path.read_bytes(),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


# --------------------------------------------------------------------------- #
# Relationship graph
# --------------------------------------------------------------------------- #


@router.get("/investigations/{investigation_id}/graph", response_class=HTMLResponse)
def graph_page(request: Request, investigation_id: int) -> HTMLResponse:
    engine = _engine()
    summary = engine.investigation_summary(investigation_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Investigation not found")
    response = _render(request, "graph.html", investigation=summary)
    _set_csrf_cookie(response, _csrf_token(request))
    return response


@router.get("/investigations/{investigation_id}/graph/data")
def graph_data(investigation_id: int) -> dict[str, Any]:
    """Return nodes/edges built only from collected evidence."""
    engine = _engine()
    summary = engine.investigation_summary(investigation_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Investigation not found")

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def add_node(entity_id: str, label: str, kind: str) -> None:
        nodes.setdefault(entity_id, {"id": entity_id, "label": label, "type": kind})

    def add_edge(src: str, dst: str, rel: str) -> None:
        if src == dst:
            return
        edges.append({"source": src, "target": dst, "relation": rel})

    for t in summary["targets"]:
        add_node(f"target:{t['value']}", t["value"], t["type"])

    for f in summary["findings"]:
        data = f["result_data"] if isinstance(f["result_data"], dict) else {}
        target = f["target"]
        module = f["module"]

        if module == "username":
            add_node(f"username:{target}", target, "username")
            add_edge(f"target:{target}", f"username:{target}", "checked-on")
            # source URL as evidence node
            if f.get("source"):
                add_node(f"source:{f['source']}", f["source"], "source")
                add_edge(f"username:{target}", f"source:{f['source']}", "profile-url")

        elif module in ("domain", "dns"):
            add_node(f"domain:{target}", target, "domain")
            if f.get("source"):
                add_node(f"source:{f['source']}", f["source"], "source")
                add_edge(f"domain:{target}", f"source:{f['source']}", "resolved-from")
            dns = data.get("dns", {})
            for ip in dns.get("A", []) + dns.get("AAAA", []):
                add_node(f"ip:{ip}", ip, "ip")
                add_edge(f"domain:{target}", f"ip:{ip}", "resolves-to")
            for mx in dns.get("MX", []):
                add_node(f"domain:{mx}", mx, "domain")
                add_edge(f"domain:{target}", f"domain:{mx}", "mx-record")
            for ns in dns.get("NS", []):
                add_node(f"domain:{ns}", ns, "domain")
                add_edge(f"domain:{target}", f"domain:{ns}", "nameserver")

        elif module == "subdomains":
            sub = data.get("subdomain")
            if sub:
                add_node(f"subdomain:{sub}", sub, "subdomain")
                add_edge(f"subdomain:{sub}", f"domain:{target}", "subdomain-of")
                for ip in data.get("resolved", {}).get("A", []) + data.get("resolved", {}).get("AAAA", []):
                    add_node(f"ip:{ip}", ip, "ip")
                    add_edge(f"subdomain:{sub}", f"ip:{ip}", "resolves-to")

        elif module == "ip":
            add_node(f"ip:{target}", target, "ip")
            for ptr in data.get("reverse_dns", []):
                add_node(f"domain:{ptr}", ptr, "domain")
                add_edge(f"ip:{target}", f"domain:{ptr}", "reverse-dns")

        elif module == "email":
            add_node(f"email:{target}", target, "email")
            domain_part = target.rsplit("@", 1)[-1] if "@" in target else ""
            if domain_part:
                add_node(f"domain:{domain_part}", domain_part, "domain")
                add_edge(f"email:{target}", f"domain:{domain_part}", "domain-of")

        elif module == "image_metadata":
            add_node(f"image:{target}", target, "image")
            if f.get("source"):
                add_node(f"source:{f['source']}", f["source"], "source")
                add_edge(f"image:{target}", f"source:{f['source']}", "local-file")

        elif module == "search":
            if f.get("source"):
                add_node(f"source:{f['source']}", f["source"], "source")
                add_edge(f"target:{target}", f"source:{f['source']}", "search-result")

    return {"nodes": list(nodes.values()), "edges": edges}
