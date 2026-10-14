"""Detection tuning and remediation Sigma rule endpoints."""

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from purple_range.advisor.advisor import DetectionTuningAdvisor
from purple_range.api.deps import get_repository
from purple_range.db.repository import PurpleRangeRepository
from purple_range.models.sigma import SigmaRule

router = APIRouter(prefix="/advisor", tags=["Detection Advisor"])


@router.get("/sigma", response_model=list[SigmaRule])
def list_sigma_rules(
    repo: PurpleRangeRepository = Depends(get_repository),
) -> list[SigmaRule]:
    """List all synthesized Sigma remediation rules generated for defensive blind spots."""
    return repo.list_sigma_rules()


@router.get("/sigma/export", response_class=PlainTextResponse)
def export_sigma_yaml(
    repo: PurpleRangeRepository = Depends(get_repository),
) -> str:
    """Export all synthesized Sigma rules as a consolidated multi-document YAML stream."""
    rules = repo.list_sigma_rules()
    return DetectionTuningAdvisor.export_rules_bundle(rules)
