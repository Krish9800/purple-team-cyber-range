"""MITRE ATT&CK technique definition models."""

from pydantic import BaseModel, ConfigDict, Field

from purple_range.models.enums import DataSource, MitreTactic, Platform, TechniqueSeverity


class MitreTechnique(BaseModel):
    """Definition of an adversary technique mapped to MITRE ATT&CK."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK Technique ID (e.g. T1087, T1003.001)",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    name: str = Field(..., min_length=2, max_length=128, description="Technique display name")
    tactic: MitreTactic = Field(..., description="MITRE ATT&CK tactic category")
    severity: TechniqueSeverity = Field(
        default=TechniqueSeverity.MEDIUM,
        description="Severity classification",
    )
    platform: Platform = Field(
        default=Platform.LINUX,
        description="Applicable operating system platform",
    )
    description: str = Field(..., min_length=5, description="Technical summary of technique")
    command_template: str = Field(
        ...,
        min_length=1,
        description="Safe atomic shell command or script template",
    )
    cleanup_command: str | None = Field(
        default=None,
        description="Idempotent cleanup command to revert system state",
    )
    data_sources: list[DataSource] = Field(
        default_factory=list,
        description="Telemetry data sources required for detection",
    )
    parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Tunable parameters for the command template",
    )
    safe_payload: bool = Field(
        default=True,
        description="Guarantees payload containment with non-destructive operations",
    )
