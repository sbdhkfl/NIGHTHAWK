"""Tests for report generation."""

import json

from nighthawk.core.engine import Engine
from nighthawk.reporting import export_csv, export_html, export_json


def test_export_json(temp_db):
    engine = Engine()
    inv = engine.create_investigation("Report Test")
    engine.add_target(inv.id, "domain", "example.com")
    path = f"{temp_db}.json"
    report = export_json(inv.id, path)
    assert report["framework"] == "NIGHTHAWK OSINT"
    assert report["investigation"]["name"] == "Report Test"
    assert len(report["targets"]) == 1
    data = json.loads(open(path).read())
    assert data["investigation"]["id"] == inv.id


def test_export_csv(temp_db):
    engine = Engine()
    inv = engine.create_investigation("CSV Test")
    path = export_csv(inv.id, f"{temp_db}.csv")
    text = open(path).read()
    assert "nighthawk-osint" in text
    assert "CSV Test" in text


def test_export_html(temp_db):
    engine = Engine()
    inv = engine.create_investigation("HTML Test")
    path = export_html(inv.id, f"{temp_db}.html")
    text = open(path).read()
    assert "NIGHTHAWK OSINT" in text
    assert "HTML Test" in text
    assert "Limitations and uncertainty" in text
