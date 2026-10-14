"""ATT&CK matrix heatmap and gap analysis reporting endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from purple_range.analytics.reporter import HeatmapReporter
from purple_range.api.deps import get_repository
from purple_range.db.repository import PurpleRangeRepository
from purple_range.models.heatmap import PurpleMatrixHeatmap

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/heatmap", response_model=PurpleMatrixHeatmap)
def get_matrix_heatmap(
    campaign_id: str | None = Query(default=None, description="Optional specific campaign ID"),
    repo: PurpleRangeRepository = Depends(get_repository),
) -> PurpleMatrixHeatmap:
    """Retrieve computed ATT&CK matrix heatmap with DCR and tactic summaries."""
    heatmap = repo.get_latest_heatmap(campaign_id=campaign_id)
    if not heatmap:
        raise HTTPException(
            status_code=404,
            detail="No matrix heatmap available. Execute an emulation drill first.",
        )
    return heatmap


@router.get("/summary", response_class=PlainTextResponse)
def get_markdown_summary(
    campaign_id: str | None = Query(default=None, description="Optional specific campaign ID"),
    repo: PurpleRangeRepository = Depends(get_repository),
) -> str:
    """Export GitHub-flavored markdown summary of detection verification findings."""
    heatmap = repo.get_latest_heatmap(campaign_id=campaign_id)
    if not heatmap:
        raise HTTPException(
            status_code=404,
            detail="No report available to summarize. Run a campaign first.",
        )
    return HeatmapReporter.generate_markdown_summary(heatmap)
