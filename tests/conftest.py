"""Pytest fixtures for NIGHTHAWK OSINT tests."""

import os
import tempfile

import pytest

from nighthawk.core.config import reset_settings_cache


@pytest.fixture
def temp_db():
    """Provide a temporary SQLite database for engine tests."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    data_dir = tempfile.mkdtemp()
    os.environ["NIGHTHAWK_DATABASE_URL"] = f"sqlite:///{path}"
    os.environ["NIGHTHAWK_DATA_DIR"] = data_dir
    reset_settings_cache()
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass
    reset_settings_cache()
