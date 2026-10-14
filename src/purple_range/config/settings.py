"""Configuration settings for Purple-Team Cyber Range."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Purple-Team Cyber Range runtime configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="PURPLE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Platform Settings
    app_name: str = Field(
        default="Purple-Team Cyber Range",
        description="Application title",
    )
    environment: Literal["development", "staging", "production", "testing"] = Field(
        default="development",
        description="Deployment runtime environment",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode and verbose telemetry output",
    )

    # Persistence Configuration (SQLite WAL Mode)
    db_path: Path = Field(
        default=Path("data/purple_range.db"),
        description="Path to SQLite database file",
    )
    db_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Database transaction timeout in seconds",
    )

    # Detection Verification Parameters
    correlation_window_seconds: int = Field(
        default=120,
        ge=5,
        le=3600,
        description="Time tolerance window to correlate blue team alerts with red executions",
    )
    emulation_timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Max runtime allowed for an atomic emulation step before timeout",
    )

    # API Server Configuration
    api_host: str = Field(
        default="127.0.0.1",
        description="Host interface for FastAPI REST server",
    )
    api_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="Port for FastAPI REST server",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
