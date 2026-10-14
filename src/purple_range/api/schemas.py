"""Request and response schemas for FastAPI endpoints."""

from typing import Any

from pydantic import BaseModel, Field

from purple_range.models.campaign import CampaignPlaybook, PurpleCampaign
from purple_range.models.enums import TechniqueSeverity
from purple_range.models.heatmap import PurpleMatrixHeatmap
from purple_range.models.sigma import SigmaRule


class HealthResponse(BaseModel):
    """System health check response."""

    status: str = "ok"
    app_name: str
    version: str
    environment: str
    database: str


class CampaignRunRequest(BaseModel):
    """Payload to initiate a purple team emulation drill."""

    name: str = Field(..., min_length=2, max_length=128, description="Campaign run name")
    playbook_id: str | None = Field(default=None, description="Preset playbook ID")
    technique_ids: list[str] | None = Field(default=None, description="Custom technique list")
    operator: str = Field(default="purple_operator", description="Operator identity")
    target_host: str = Field(default="localhost", description="Target host where emulations run")


class CampaignRunResponse(BaseModel):
    """Results of a completed purple team emulation drill."""

    campaign: PurpleCampaign
    heatmap: PurpleMatrixHeatmap
    sigma_rules: list[SigmaRule]


class AlertIngestRequest(BaseModel):
    """Defensive telemetry alert ingestion schema."""

    sensor_name: str = Field(..., min_length=1)
    host: str = Field(default="localhost")
    alert_signature: str = Field(..., min_length=2)
    technique_id: str | None = None
    severity: TechniqueSeverity = TechniqueSeverity.MEDIUM
    command_line: str | None = None
    process_name: str | None = None
    process_pid: int | None = None
    raw_log: dict[str, Any] = Field(default_factory=dict)


class PlaybookCreateRequest(BaseModel):
    """Schema for registering a new attack scenario playbook."""

    playbook_id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field(..., min_length=5)
    technique_ids: list[str] = Field(..., min_length=1)
    author: str = Field(default="Security Engineer")

    def to_playbook(self) -> CampaignPlaybook:
        """Convert request to CampaignPlaybook domain model."""
        return CampaignPlaybook(
            playbook_id=self.playbook_id,
            name=self.name,
            description=self.description,
            technique_ids=self.technique_ids,
            author=self.author,
        )
