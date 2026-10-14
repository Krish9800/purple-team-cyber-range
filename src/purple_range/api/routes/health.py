"""Health check and platform status routes."""

from fastapi import APIRouter, Depends

from purple_range import __version__
from purple_range.api.deps import get_db_manager
from purple_range.api.schemas import HealthResponse
from purple_range.config.settings import Settings, get_settings
from purple_range.db.connection import DatabaseManager

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health(
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db_manager),
) -> HealthResponse:
    """Return platform operational status and connected database state."""
    db_status = "connected"
    try:
        with db.connection() as conn:
            conn.execute("SELECT 1;").fetchone()
    except Exception:
        db_status = "unhealthy"

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        app_name=settings.app_name,
        version=__version__,
        environment=settings.environment,
        database=db_status,
    )
