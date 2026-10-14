"""MITRE ATT&CK technique catalog endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query

from purple_range.api.deps import get_technique_registry
from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.models.enums import MitreTactic
from purple_range.models.technique import MitreTechnique

router = APIRouter(prefix="/techniques", tags=["Techniques"])


@router.get("", response_model=list[MitreTechnique])
def list_techniques(
    tactic: MitreTactic | None = Query(default=None, description="Filter by MITRE tactic"),
    registry: TechniqueRegistry = Depends(get_technique_registry),
) -> list[MitreTechnique]:
    """List registered adversary techniques mapped to MITRE ATT&CK."""
    if tactic:
        return registry.filter_by_tactic(tactic)
    return registry.list_all()


@router.get("/{technique_id}", response_model=MitreTechnique)
def get_technique(
    technique_id: str,
    registry: TechniqueRegistry = Depends(get_technique_registry),
) -> MitreTechnique:
    """Retrieve detailed definition and safe command template for a specific technique."""
    tech = registry.get(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")
    return tech
