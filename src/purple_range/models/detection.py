"""Detection telemetry and evidence verification models."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from purple_range.models.enums import DetectionVerdict, TechniqueSeverity


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_uuid() -> str:
    return str(uuid4())


class DetectionAlert(BaseModel):
    """Normalized security alert emitted by defensive sensors (SIEM, EDR, Sysmon, Auditd)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str = Field(
        default_factory=_default_uuid,
        description="Unique alert identifier",
    )
    sensor_name: str = Field(
        ...,
        min_length=1,
        description="Originating sensor (e.g. sysmon, auditd, edr, suricata)",
    )
    technique_id: str | None = Field(
        default=None,
        description="Optional MITRE ATT&CK technique code attributed by sensor",
    )
    timestamp: datetime = Field(
        default_factory=_utc_now,
        description="Alert creation timestamp",
    )
    host: str = Field(default="localhost", description="Monitored target host")
    process_name: str | None = Field(default=None, description="Reported process executable name")
    process_pid: int | None = Field(default=None, description="Reported process PID")
    command_line: str | None = Field(default=None, description="Observed process command line")
    alert_signature: str = Field(
        ...,
        min_length=2,
        description="Alert rule title or detection signature",
    )
    severity: TechniqueSeverity = Field(
        default=TechniqueSeverity.MEDIUM,
        description="Alert severity",
    )
    raw_log: dict[str, Any] = Field(
        default_factory=dict,
        description="Underlying raw security event payload",
    )


class DetectionEvidence(BaseModel):
    """Correlation proof matching red-team emulation step with blue-team alerts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(
        default_factory=_default_uuid,
        description="Unique evidence record ID",
    )
    execution_id: str = Field(..., description="Target emulation execution ID")
    technique_id: str = Field(..., description="Target MITRE technique ID")
    verdict: DetectionVerdict = Field(..., description="Outcome classification")
    matched_alerts: list[DetectionAlert] = Field(
        default_factory=list,
        description="Correlated defensive alerts",
    )
    detection_latency_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Latency between red execution and first matching alert",
    )
    matched_at: datetime = Field(
        default_factory=_utc_now,
        description="Correlation timestamp",
    )
    notes: str = Field(default="", description="Analyst or evaluator notes")
