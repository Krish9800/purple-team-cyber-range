"""Campaign drill execution and history endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from purple_range.api.deps import get_orchestrator, get_repository
from purple_range.api.schemas import CampaignRunRequest, CampaignRunResponse
from purple_range.db.repository import PurpleRangeRepository
from purple_range.models.campaign import PurpleCampaign
from purple_range.orchestrator.service import CampaignOrchestrator

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.post("/run", response_model=CampaignRunResponse, status_code=status.HTTP_200_OK)
async def run_campaign(
    payload: CampaignRunRequest,
    orchestrator: CampaignOrchestrator = Depends(get_orchestrator),
) -> CampaignRunResponse:
    """Execute purple-team adversary emulation scenario and evaluate detection coverage."""
    try:
        campaign, heatmap, sigma_rules = await orchestrator.async_run_campaign(
            name=payload.name,
            technique_ids=payload.technique_ids,
            playbook_id=payload.playbook_id,
            operator=payload.operator,
            target_host=payload.target_host,
        )
        return CampaignRunResponse(
            campaign=campaign,
            heatmap=heatmap,
            sigma_rules=sigma_rules,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


@router.get("", response_model=list[PurpleCampaign])
def list_campaigns(
    repo: PurpleRangeRepository = Depends(get_repository),
) -> list[PurpleCampaign]:
    """List historical purple team campaigns with high-level coverage metrics."""
    return repo.list_campaigns()


@router.get("/{campaign_id}", response_model=PurpleCampaign)
def get_campaign(
    campaign_id: str,
    repo: PurpleRangeRepository = Depends(get_repository),
) -> PurpleCampaign:
    """Fetch complete details, emulation steps, and detection evidence for a campaign."""
    camp = repo.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    return camp
