"""FastAPI dependency injection providers."""

from functools import lru_cache

from fastapi import Depends

from purple_range.config.settings import Settings, get_settings
from purple_range.db.connection import DatabaseManager
from purple_range.db.repository import PurpleRangeRepository
from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.orchestrator.service import CampaignOrchestrator


def get_db_manager(settings: Settings = Depends(get_settings)) -> DatabaseManager:
    """Provide DatabaseManager instance for request context."""
    manager = DatabaseManager(settings.db_path, timeout_seconds=settings.db_timeout_seconds)
    repo = PurpleRangeRepository(manager)
    repo.initialize_schema()
    return manager


def get_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> PurpleRangeRepository:
    """Provide PurpleRangeRepository instance."""
    return PurpleRangeRepository(db_manager)


@lru_cache(maxsize=1)
def get_technique_registry() -> TechniqueRegistry:
    """Provide singleton MITRE technique catalog."""
    return TechniqueRegistry()


def get_orchestrator(
    repo: PurpleRangeRepository = Depends(get_repository),
    registry: TechniqueRegistry = Depends(get_technique_registry),
) -> CampaignOrchestrator:
    """Provide CampaignOrchestrator instance."""
    return CampaignOrchestrator(repository=repo, registry=registry)
