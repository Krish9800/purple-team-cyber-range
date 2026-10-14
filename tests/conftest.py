"""Pytest fixtures and configuration for Purple-Team Cyber Range."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from purple_range.config.settings import Settings


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Provide a temporary database file path and clean up after test."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir) / "test_purple_range.db"


@pytest.fixture
def test_settings(temp_db_path: Path) -> Settings:
    """Provide a test Settings instance with isolated database path."""
    return Settings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
        correlation_window_seconds=60,
        emulation_timeout_seconds=10,
    )
