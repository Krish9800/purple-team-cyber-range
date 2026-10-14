"""Attack scenario playbook endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from purple_range.api.deps import get_repository
from purple_range.api.schemas import PlaybookCreateRequest
from purple_range.db.repository import PurpleRangeRepository
from purple_range.models.campaign import CampaignPlaybook

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


@router.get("", response_model=list[CampaignPlaybook])
def list_playbooks(repo: PurpleRangeRepository = Depends(get_repository)) -> list[CampaignPlaybook]:
    """List all available scenario playbooks."""
    return repo.list_playbooks()


@router.post("", response_model=CampaignPlaybook, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: PlaybookCreateRequest,
    repo: PurpleRangeRepository = Depends(get_repository),
) -> CampaignPlaybook:
    """Register a new adversary emulation scenario playbook."""
    playbook = payload.to_playbook()
    repo.save_playbook(playbook)
    return playbook


@router.get("/{playbook_id}", response_model=CampaignPlaybook)
def get_playbook(
    playbook_id: str,
    repo: PurpleRangeRepository = Depends(get_repository),
) -> CampaignPlaybook:
    """Fetch details of an attack scenario playbook."""
    pb = repo.get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")
    return pb
