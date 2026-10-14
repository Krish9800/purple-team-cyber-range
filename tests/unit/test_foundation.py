"""Unit tests for Phase 1 Foundation & Settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from purple_range import __version__
from purple_range.config.settings import Settings, get_settings


def test_package_version() -> None:
    """Verify package version is defined."""
    assert __version__ == "0.1.0"


def test_default_settings() -> None:
    """Verify default settings values aligned with purple-team range requirements."""
    settings = Settings()
    assert settings.app_name == "Purple-Team Cyber Range"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.correlation_window_seconds == 120
    assert settings.emulation_timeout_seconds == 30


def test_cached_settings() -> None:
    """Verify get_settings returns cached singleton."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_custom_settings(test_settings: Settings, temp_db_path: Path) -> None:
    """Verify test_settings override."""
    assert test_settings.environment == "testing"
    assert test_settings.debug is True
    assert test_settings.db_path == temp_db_path
    assert test_settings.correlation_window_seconds == 60


def test_settings_validation_errors() -> None:
    """Verify validation boundaries on timeout and port."""
    with pytest.raises(ValidationError):
        Settings(correlation_window_seconds=1)

    with pytest.raises(ValidationError):
        Settings(api_port=22)


def test_settings_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variable prefix overrides."""
    monkeypatch.setenv("PURPLE_APP_NAME", "Adversary Simulation Lab")
    monkeypatch.setenv("PURPLE_CORRELATION_WINDOW_SECONDS", "300")
    settings = Settings()
    assert settings.app_name == "Adversary Simulation Lab"
    assert settings.correlation_window_seconds == 300
