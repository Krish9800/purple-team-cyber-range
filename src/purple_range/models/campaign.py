"""Purple team campaign and playbook models."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from purple_range.models.detection import DetectionEvidence
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import EmulationStatus


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_uuid() -> str:
    return str(uuid4())


class CampaignPlaybook(BaseModel):
    """Reusable attack scenario template chaining multiple MITRE techniques."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    playbook_id: str = Field(..., description="Playbook key (e.g. ransomware-chain)")
    name: str = Field(..., min_length=2, max_length=128, description="Playbook title")
    description: str = Field(..., min_length=5, description="Operational scenario summary")
    technique_ids: list[str] = Field(
        ...,
        min_length=1,
        description="Ordered sequence of MITRE ATT&CK technique IDs",
    )
    author: str = Field(
        default="Purple Team Cyber Range",
        description="Scenario playbook author",
    )


class PurpleCampaign(BaseModel):
    """Execution instance of an end-to-end purple-team adversary emulation scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str = Field(
        default_factory=_default_uuid,
        description="Unique campaign execution ID",
    )
    name: str = Field(..., min_length=2, max_length=128, description="Campaign descriptive name")
    playbook_id: str | None = Field(
        default=None,
        description="Associated playbook ID if templated",
    )
    status: EmulationStatus = Field(
        default=EmulationStatus.PENDING,
        description="Overall campaign state",
    )
    operator: str = Field(default="operator", description="Purple team operator handle")
    started_at: datetime = Field(
        default_factory=_utc_now,
        description="Campaign start timestamp",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Campaign completion timestamp",
    )
    emulation_steps: list[EmulationStep] = Field(
        default_factory=list,
        description="List of executed emulation steps",
    )
    evidences: list[DetectionEvidence] = Field(
        default_factory=list,
        description="List of detection evaluation evidences",
    )
    total_techniques: int = Field(default=0, ge=0, description="Total techniques executed")
    detected_count: int = Field(default=0, ge=0, description="Number of detected techniques")
    blocked_count: int = Field(default=0, ge=0, description="Number of blocked techniques")
    missed_count: int = Field(default=0, ge=0, description="Number of missed techniques")
    detection_coverage_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Detection Coverage Rate percentage (DCR)",
    )
    mean_alert_latency_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Average detection alert latency in seconds",
    )
