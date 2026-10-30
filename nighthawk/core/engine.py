"""Central investigation engine.

The engine owns the lifecycle of an investigation: create, add targets, run
modules against targets, persist findings/sources/notes/activity, and export
reports. It is intentionally independent of the CLI and dashboard so both
interfaces share the same underlying modules and database.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Callable
from typing import Any

from nighthawk.core.database import get_session, init_db
from nighthawk.core.logging import get_logger
from nighthawk.core.models import (
    ActivityLog,
    Finding,
    Investigation,
    Note,
    Source,
    Target,
)
from nighthawk.core.validation import (
    validate_cve,
    validate_domain,
    validate_email,
    validate_image_filename,
    validate_ip,
    validate_phone,
    validate_username,
)

logger = get_logger("nighthawk.engine")


class EngineError(RuntimeError):
    """Raised when the engine cannot complete an operation."""


# Module registry: name -> (validator, run function)
# Each run function signature: (target_value: str, session) -> list[dict]
# Each dict has keys: module, target, result_data (dict), source (str|None),
# confidence (str|None).
MODULE_REGISTRY: dict[str, tuple[Callable, Callable]] = {}


def register_module(name: str, validator, runner) -> None:
    """Register an intelligence module with the engine."""
    MODULE_REGISTRY[name] = (validator, runner)


# Import-time registration happens below after module definitions are imported.
# We import the runner functions explicitly to avoid circularity.


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


def _log_activity(session, investigation_id: int, action: str, detail: str | None = None) -> None:
    session.add(ActivityLog(investigation_id=investigation_id, action=action, detail=detail))


class Engine:
    """Central investigation engine."""

    def __init__(self, database_url: str | None = None) -> None:
        if database_url:
            # Allow overriding the database URL for tests.
            import os

            os.environ["NIGHTHAWK_DATABASE_URL"] = database_url
            from nighthawk.core.config import reset_settings_cache

            reset_settings_cache()
        init_db()
        self._register_modules()

    # ------------------------------------------------------------------ #
    # Investigation lifecycle
    # ------------------------------------------------------------------ #
    def create_investigation(self, name: str, description: str | None = None) -> Investigation:
        if not name or not name.strip():
            raise EngineError("investigation name is required")
        session = get_session()
        try:
            inv = Investigation(name=name.strip(), description=description)
            session.add(inv)
            session.commit()
            session.refresh(inv)
            _log_activity(session, inv.id, "created", f"name='{inv.name}'")
            session.commit()
            logger.info("created investigation %s (%s)", inv.id, inv.name)
            return inv
        finally:
            session.close()

    def list_investigations(self) -> list[Investigation]:
        session = get_session()
        try:
            return session.query(Investigation).order_by(Investigation.updated_at.desc()).all()
        finally:
            session.close()

    def get_investigation(self, investigation_id: int) -> Investigation | None:
        session = get_session()
        try:
            return session.query(Investigation).get(investigation_id)
        finally:
            session.close()

    def delete_investigation(self, investigation_id: int) -> bool:
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                return False
            session.delete(inv)
            session.commit()
            logger.info("deleted investigation %s", investigation_id)
            return True
        finally:
            session.close()

    def add_note(self, investigation_id: int, content: str) -> Note:
        if not content or not content.strip():
            raise EngineError("note content is required")
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                raise EngineError(f"investigation {investigation_id} not found")
            note = Note(investigation_id=investigation_id, content=content.strip())
            session.add(note)
            _log_activity(session, investigation_id, "note_added")
            session.commit()
            session.refresh(note)
            return note
        finally:
            session.close()

    # ------------------------------------------------------------------ #
    # Targets and module execution
    # ------------------------------------------------------------------ #
    def add_target(self, investigation_id: int, target_type: str, value: str) -> Target:
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                raise EngineError(f"investigation {investigation_id} not found")
            validator = _VALIDATORS.get(target_type)
            if validator:
                value = validator(value)
            target = Target(investigation_id=investigation_id, target_type=target_type, value=value)
            session.add(target)
            _log_activity(session, investigation_id, "target_added", f"{target_type}={value}")
            session.commit()
            session.refresh(target)
            return target
        finally:
            session.close()

    def run_module(
        self,
        investigation_id: int,
        target_type: str,
        target_value: str,
        module_name: str,
    ) -> list[dict[str, Any]]:
        """Run a single module against a target and persist findings."""
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                raise EngineError(f"investigation {investigation_id} not found")

            if module_name not in MODULE_REGISTRY:
                raise EngineError(f"unknown module '{module_name}'")
            validator, runner = MODULE_REGISTRY[module_name]
            if validator:
                target_value = validator(target_value)

            results = runner(target_value, session)

            # Every finding references a persisted Target row. CLI module runs
            # may start directly without calling add_target(), so create or
            # reuse that row here.
            target_record = (
                session.query(Target)
                .filter_by(
                    investigation_id=investigation_id,
                    target_type=target_type,
                    value=target_value,
                )
                .first()
            )
            if target_record is None:
                target_record = Target(
                    investigation_id=investigation_id,
                    target_type=target_type,
                    value=target_value,
                )
                session.add(target_record)
                session.flush()

            findings_out: list[dict[str, Any]] = []
            for result in results:
                finding = Finding(
                    investigation_id=investigation_id,
                    target_id=target_record.id,
                    module=result.get("module", module_name),
                    target=result.get("target", target_value),
                    result_data=json.dumps(result.get("result_data", {}), default=str),
                    source=result.get("source"),
                    confidence=result.get("confidence"),
                )
                session.add(finding)
                session.flush()
                if result.get("source"):
                    session.add(
                        Source(
                            investigation_id=investigation_id,
                            url=result["source"],
                            module=result.get("module", module_name),
                        )
                    )
                findings_out.append(
                    {
                        "id": finding.id,
                        "module": finding.module,
                        "target": finding.target,
                        "result_data": result.get("result_data", {}),
                        "source": finding.source,
                        "confidence": finding.confidence,
                        "collected_at": finding.collected_at.isoformat(),
                    }
                )

            _log_activity(
                session,
                investigation_id,
                "module_run",
                f"module={module_name} target={target_value} findings={len(findings_out)}",
            )
            session.commit()
            logger.info(
                "module %s against %s in investigation %s: %s findings",
                module_name, target_value, investigation_id, len(findings_out),
            )
            return findings_out
        finally:
            session.close()

    def run_investigation(
        self,
        investigation_id: int,
        module_names: list[str] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Run selected modules against all targets of an investigation."""
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                raise EngineError(f"investigation {investigation_id} not found")
            targets = session.query(Target).filter_by(investigation_id=investigation_id).all()
        finally:
            session.close()

        if not targets:
            return {}

        modules_to_run = module_names or list(MODULE_REGISTRY.keys())
        results: dict[str, list[dict[str, Any]]] = {}
        for target in targets:
            for module_name in modules_to_run:
                # Skip obviously incompatible module/target combos gracefully.
                try:
                    found = self.run_module(
                        investigation_id, target.target_type, target.value, module_name
                    )
                except EngineError:
                    # Module not applicable to this target type; skip quietly.
                    continue
                except Exception:  # pragma: no cover - defensive
                    logger.exception("module %s failed for %s", module_name, target.value)
                    continue
                results.setdefault(f"{target.target_type}:{target.value}", []).extend(found)
        return results

    # ------------------------------------------------------------------ #
    # Findings / sources for reporting
    # ------------------------------------------------------------------ #
    def get_findings(self, investigation_id: int) -> list[Finding]:
        session = get_session()
        try:
            return (
                session.query(Finding)
                .filter_by(investigation_id=investigation_id)
                .order_by(Finding.collected_at.desc())
                .all()
            )
        finally:
            session.close()

    def get_sources(self, investigation_id: int) -> list[Source]:
        session = get_session()
        try:
            return (
                session.query(Source)
                .filter_by(investigation_id=investigation_id)
                .order_by(Source.recorded_at.desc())
                .all()
            )
        finally:
            session.close()

    def get_notes(self, investigation_id: int) -> list[Note]:
        session = get_session()
        try:
            return (
                session.query(Note)
                .filter_by(investigation_id=investigation_id)
                .order_by(Note.created_at.desc())
                .all()
            )
        finally:
            session.close()

    def investigation_summary(self, investigation_id: int) -> dict[str, Any] | None:
        session = get_session()
        try:
            inv = session.query(Investigation).get(investigation_id)
            if not inv:
                return None
            findings = self.get_findings(investigation_id)
            targets = session.query(Target).filter_by(investigation_id=investigation_id).all()
            notes = self.get_notes(investigation_id)
            sources = self.get_sources(investigation_id)
            return {
                "id": inv.id,
                "name": inv.name,
                "description": inv.description,
                "created_at": inv.created_at.isoformat(),
                "updated_at": inv.updated_at.isoformat(),
                "target_count": len(targets),
                "finding_count": len(findings),
                "note_count": len(notes),
                "source_count": len(sources),
                "targets": [
                    {"id": t.id, "type": t.target_type, "value": t.value} for t in targets
                ],
                "findings": [
                    {
                        "id": f.id,
                        "module": f.module,
                        "target": f.target,
                        "result_data": json.loads(f.result_data) if f.result_data else {},
                        "source": f.source,
                        "confidence": f.confidence,
                        "collected_at": f.collected_at.isoformat(),
                    }
                    for f in findings
                ],
                "notes": [{"content": n.content, "created_at": n.created_at.isoformat()} for n in notes],
                "sources": [{"url": s.url, "module": s.module} for s in sources],
            }
        finally:
            session.close()

    # ------------------------------------------------------------------ #
    # Module registration
    # ------------------------------------------------------------------ #
    def _register_modules(self) -> None:
        from nighthawk.modules.dns import run as dns_run
        from nighthawk.modules.domain import run as domain_run
        from nighthawk.modules.email import run as email_run
        from nighthawk.modules.image_metadata import run as image_run
        from nighthawk.modules.ip_intel import run as ip_run
        from nighthawk.modules.kev import run as kev_run
        from nighthawk.modules.phone import run as phone_run
        from nighthawk.modules.search import run as search_run
        from nighthawk.modules.subdomains import run as subdomains_run
        from nighthawk.modules.username import run as username_run

        register_module("username", validate_username, username_run)
        register_module("domain", validate_domain, domain_run)
        register_module("dns", validate_domain, dns_run)
        register_module("subdomains", validate_domain, subdomains_run)
        register_module("ip", validate_ip, ip_run)
        register_module("phone", validate_phone, phone_run)
        register_module("kev", validate_cve, kev_run)
        register_module("email", validate_email, email_run)
        register_module("image", validate_image_filename, image_run)
        register_module("search", lambda v: v, search_run)


_VALIDATORS: dict[str, callable] = {
    "username": validate_username,
    "domain": validate_domain,
    "ip": validate_ip,
    "phone": validate_phone,
    "cve": validate_cve,
    "email": validate_email,
    "image": validate_image_filename,
}
