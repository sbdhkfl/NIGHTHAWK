"""Tests for the web dashboard routes."""

from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nighthawk.dashboard.app import app


class FakeTarget:
    def __init__(self, id_, type_, value):
        self.id = id_
        self.target_type = type_
        self.value = value


class FakeInv:
    def __init__(self, id_, name="Test"):
        self.id = id_
        self.name = name
        self.description = "a description"
        self.targets = [FakeTarget(1, "domain", "example.com")]
        self.findings = []
        self.sources = []
        self.notes = []
        from datetime import datetime

        self.updated_at = datetime.now(UTC)


class FakeEngine:
    def __init__(self, *args, **kwargs):
        self.invs = {1: FakeInv(1)}
        self._next = 2

    def list_investigations(self):
        return list(self.invs.values())

    def create_investigation(self, name, description=None):
        inv = FakeInv(self._next, name)
        inv.description = description
        self.invs[self._next] = inv
        self._next += 1
        return inv

    def get_investigation(self, id_):
        return self.invs.get(int(id_))

    def investigation_summary(self, id_):
        inv = self.get_investigation(id_)
        if not inv:
            return None
        return {
            "id": inv.id,
            "name": inv.name,
            "description": inv.description,
            "target_count": len(inv.targets),
            "finding_count": len(inv.findings),
            "source_count": len(inv.sources),
            "note_count": len(inv.notes),
            "targets": [
                {"id": t.id, "type": t.target_type, "value": t.value} for t in inv.targets
            ],
            "findings": [],
            "notes": [],
            "sources": [],
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": inv.updated_at.isoformat(),
        }

    def run_module(self, *args, **kwargs):
        return []

    def add_note(self, inv_id, content):
        class Note:
            def __init__(self, content: str, created_at: str) -> None:
                self.content = content
                self.created_at = created_at

        return Note(content, "2026-01-01T00:00:00+00:00")

    def delete_investigation(self, id_):
        return self.invs.pop(int(id_), None) is not None


@pytest.fixture
def client(temp_db):
    with patch("nighthawk.dashboard.routes.Engine", FakeEngine):
        with patch("nighthawk.dashboard.routes.export_json") as ej, \
             patch("nighthawk.dashboard.routes.export_csv") as ec, \
             patch("nighthawk.dashboard.routes.export_html") as eh:
            def _fake_export(inv_id, path):
                Path(path).write_text("{}")
                return path
            ej.side_effect = _fake_export
            ec.side_effect = _fake_export
            eh.side_effect = _fake_export
            yield TestClient(app)


def _csrf(client):
    client.get("/")
    return client.cookies.get("nighthawk_csrf")


def test_overview(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"NIGHTHAWK OSINT" in r.content
    assert b"Investigations" in r.content


def test_investigations_list(client):
    r = client.get("/investigations")
    assert r.status_code == 200


def test_create_investigation(client):
    token = _csrf(client)
    r = client.post(
        "/investigations",
        data={"name": "My Recon", "description": "desc", "csrf_token": token},
    )
    assert r.status_code in (200, 303)


def test_create_investigation_csrf_rejected(client):
    r = client.post("/investigations", data={"name": "x"})
    assert r.status_code == 403


def test_investigation_detail(client):
    r = client.get("/investigations/1")
    assert r.status_code == 200
    assert b"Test" in r.content


def test_run_module_partial(client):
    token = _csrf(client)
    r = client.post(
        "/investigations/1/run",
        data={"modules": "domain", "csrf_token": token},
    )
    assert r.status_code == 200


def test_add_note(client):
    token = _csrf(client)
    r = client.post(
        "/investigations/1/notes",
        data={"content": "remember this", "csrf_token": token},
    )
    assert r.status_code == 200
    assert b"remember this" in r.content


def test_upload_image(client, tmp_path):
    token = _csrf(client)
    img = tmp_path / "photo.jpg"
    img.write_bytes(b"\xff\xd8\xff\xe0fakejpeg")
    r = client.post(
        "/investigations/1/image",
        data={"csrf_token": token},
        files={"file": ("photo.jpg", img.read_bytes(), "image/jpeg")},
    )
    assert r.status_code == 200


def test_upload_unsupported_format(client):
    token = _csrf(client)
    r = client.post(
        "/investigations/1/image",
        data={"csrf_token": token},
        files={"file": ("evil.sh", b"x", "text/plain")},
    )
    assert r.status_code == 400


def test_export_json(client):
    r = client.get("/investigations/1/export/json")
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")


def test_delete_investigation(client):
    token = _csrf(client)
    r = client.post(
        "/investigations/1/delete", data={"csrf_token": token}
    )
    assert r.status_code in (200, 303)


def test_graph_data(client, routes_module):
    routes_module._engine_instance = None
    r = client.get("/investigations/1/graph/data")
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data and "edges" in data


def test_graph_page(client, routes_module):
    routes_module._engine_instance = None
    r = client.get("/investigations/1/graph")
    assert r.status_code == 200


@pytest.fixture
def routes_module():
    import nighthawk.dashboard.routes as routes

    return routes
