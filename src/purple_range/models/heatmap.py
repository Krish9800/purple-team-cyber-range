"""MITRE ATT&CK Purple Team Heatmap and Gap Analysis models."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from purple_range.models.enums import DetectionVerdict, MitreTactic


def _utc_now() -> datetime:
    return datetime.now(UTC)


class TechniqueCoverageCell(BaseModel):
    """Matrix cell reflecting detection status for a single MITRE ATT&CK technique."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(..., description="MITRE Technique ID (e.g. T1087)")
    technique_name: str = Field(..., description="Technique display name")
    tactic: MitreTactic = Field(..., description="MITRE Tactic category")
    verdict: DetectionVerdict = Field(..., description="Latest evaluation outcome")
    execution_count: int = Field(default=1, ge=1, description="Times technique was executed")
    avg_latency_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Average alert latency for this technique",
    )
    last_tested: datetime = Field(
        default_factory=_utc_now,
        description="Timestamp of most recent execution",
    )


class TacticSummary(BaseModel):
    """Aggregated statistics for a specific MITRE ATT&CK tactic."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tactic: MitreTactic = Field(..., description="Tactic category")
    total_tested: int = Field(default=0, ge=0)
    detected: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    missed: int = Field(default=0, ge=0)
    coverage_rate: float = Field(default=0.0, ge=0.0, le=100.0)


class PurpleMatrixHeatmap(BaseModel):
    """ATT&CK Matrix Heatmap with coverage analysis and tactic breakdown."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str | None = Field(default=None, description="Campaign ID or None for global")
    generated_at: datetime = Field(
        default_factory=_utc_now,
        description="Report generation timestamp",
    )
    total_techniques: int = Field(default=0, ge=0, description="Total unique techniques evaluated")
    detected_count: int = Field(default=0, ge=0, description="Total detected techniques")
    blocked_count: int = Field(default=0, ge=0, description="Total blocked techniques")
    missed_count: int = Field(default=0, ge=0, description="Total missed techniques")
    detection_coverage_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Overall Detection Coverage Rate (%)",
    )
    tactic_summaries: dict[str, TacticSummary] = Field(
        default_factory=dict,
        description="Per-tactic breakdown of detection statistics",
    )
    cells: list[TechniqueCoverageCell] = Field(
        default_factory=list,
        description="All individual technique cells in the matrix",
    )
    blind_spots: list[str] = Field(
        default_factory=list,
        description="Technique IDs categorized as MISSED (blind spots)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context or filtering options",
    )
