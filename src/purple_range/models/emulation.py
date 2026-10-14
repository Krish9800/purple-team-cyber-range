"""Adversary emulation step and execution models."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from purple_range.models.enums import EmulationStatus, MitreTactic


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_uuid() -> str:
    return str(uuid4())


class EmulationStep(BaseModel):
    """Record of a single adversary technique execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str = Field(
        default_factory=_default_uuid,
        description="Unique execution identifier",
    )
    campaign_id: str = Field(..., description="Associated campaign identifier")
    technique_id: str = Field(..., description="MITRE ATT&CK technique code")
    technique_name: str = Field(..., description="Technique display name")
    tactic: MitreTactic = Field(..., description="MITRE ATT&CK tactic")
    target_host: str = Field(default="localhost", description="Target host where executed")
    command_executed: str = Field(..., description="Actual command executed")
    stdout: str = Field(default="", description="Execution standard output")
    stderr: str = Field(default="", description="Execution standard error")
    exit_code: int = Field(default=0, description="Process return code")
    status: EmulationStatus = Field(
        default=EmulationStatus.PENDING,
        description="Current execution state",
    )
    process_pid: int | None = Field(default=None, description="System process ID")
    started_at: datetime = Field(default_factory=_utc_now, description="Execution start timestamp")
    completed_at: datetime | None = Field(
        default=None,
        description="Execution completion timestamp",
    )
    duration_ms: float = Field(
        default=0.0, ge=0.0, description="Execution duration in milliseconds"
    )
    cleanup_executed: bool = Field(
        default=False,
        description="Indicates whether cleanup command was run",
    )
    error_message: str | None = Field(
        default=None,
        description="Detailed failure message if status is FAILED",
    )
