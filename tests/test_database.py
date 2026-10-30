"""Tests for database operations and the investigation engine."""

from nighthawk.core.engine import Engine, EngineError


def test_create_and_list_investigation(temp_db):
    engine = Engine()
    inv = engine.create_investigation("Test Investigation", "desc")
    assert inv.id == 1
    assert inv.name == "Test Investigation"

    all_invs = engine.list_investigations()
    assert len(all_invs) == 1
    assert all_invs[0].id == 1

    got = engine.get_investigation(1)
    assert got is not None
    assert got.name == "Test Investigation"


def test_add_target_and_run_module(temp_db):
    engine = Engine()
    inv = engine.create_investigation("T")
    target = engine.add_target(inv.id, "domain", "example.com")
    assert target.id == 1
    assert target.value == "example.com"

    summary = engine.investigation_summary(inv.id)
    assert summary["target_count"] == 1


def test_add_note(temp_db):
    engine = Engine()
    inv = engine.create_investigation("T")
    note = engine.add_note(inv.id, "remember this")
    assert note.content == "remember this"
    notes = engine.get_notes(inv.id)
    assert len(notes) == 1


def test_delete_investigation_cascades(temp_db):
    engine = Engine()
    inv = engine.create_investigation("T")
    engine.add_target(inv.id, "domain", "example.com")
    engine.add_note(inv.id, "note")
    assert engine.get_investigation(inv.id) is not None
    assert engine.delete_investigation(inv.id) is True
    assert engine.get_investigation(inv.id) is None
    assert engine.delete_investigation(999) is False


def test_engine_unknown_module(temp_db):
    engine = Engine()
    inv = engine.create_investigation("T")
    try:
        engine.run_module(inv.id, "domain", "example.com", "nope")
        raise AssertionError("expected EngineError")
    except EngineError as exc:
        assert "unknown module" in str(exc).lower()
