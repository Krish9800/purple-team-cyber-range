"""FastAPI application factory for Purple-Team Cyber Range REST Control Plane."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from purple_range import __version__
from purple_range.api.routes import (
    advisor,
    campaigns,
    health,
    playbooks,
    reports,
    techniques,
    telemetry,
)
from purple_range.config.settings import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure FastAPI application instance with security headers and routers."""
    active_settings = settings or get_settings()

    app = FastAPI(
        title=active_settings.app_name,
        version=__version__,
        description=(
            "Purple-Team Cyber Range REST Control Plane: "
            "Adversary Emulation, Detection Verification, and ATT&CK Gap Analysis."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount health endpoint at root and v1
    app.include_router(health.router)

    # Mount API v1 endpoints
    api_v1_prefix = "/api/v1"
    app.include_router(health.router, prefix=api_v1_prefix)
    app.include_router(techniques.router, prefix=api_v1_prefix)
    app.include_router(playbooks.router, prefix=api_v1_prefix)
    app.include_router(campaigns.router, prefix=api_v1_prefix)
    app.include_router(telemetry.router, prefix=api_v1_prefix)
    app.include_router(reports.router, prefix=api_v1_prefix)
    app.include_router(advisor.router, prefix=api_v1_prefix)

    return app


app = create_app()
