"""Sigma detection rule models for tuning recommendations."""

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _default_uuid() -> str:
    return str(uuid4())


class SigmaRule(BaseModel):
    """Specification of a synthesized Sigma detection rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        default_factory=_default_uuid,
        description="Unique Sigma rule UUID",
    )
    title: str = Field(..., min_length=3, max_length=128, description="Sigma rule title")
    status: str = Field(default="experimental", description="Rule lifecycle status")
    description: str = Field(..., min_length=5, description="Rule description and rationale")
    references: list[str] = Field(default_factory=list, description="MITRE and advisory references")
    author: str = Field(
        default="Purple-Team Detection Tuning Advisor",
        description="Rule author or generator",
    )
    date: str = Field(..., description="Creation date string in YYYY-MM-DD")
    modified: str | None = Field(default=None, description="Modification date string")
    logsource: dict[str, str] = Field(
        ...,
        description="Logsource definition (e.g. category, product, service)",
    )
    detection: dict[str, Any] = Field(
        ...,
        description="Detection search patterns, selections, and condition",
    )
    condition: str = Field(default="selection", description="Logic expression for condition")
    falsepositives: list[str] = Field(
        default_factory=list,
        description="Known legitimate admin activity false positives",
    )
    level: str = Field(
        default="medium",
        description="Severity level (low, medium, high, critical)",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags including MITRE ATT&CK technique and tactic IDs",
    )

    def to_yaml(self) -> str:
        """Render standard Sigma YAML format without external heavy yaml libraries."""
        lines = [
            f"title: {self.title}",
            f"id: {self.id}",
            f"status: {self.status}",
            f"description: {self.description}",
            f"author: {self.author}",
            f"date: {self.date}",
        ]
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"    - {ref}")
        lines.append("tags:")
        for tag in self.tags:
            lines.append(f"    - {tag}")
        lines.append("logsource:")
        for k, v in self.logsource.items():
            lines.append(f"    {k}: {v}")
        lines.append("detection:")
        for k, v in self.detection.items():
            if isinstance(v, dict):
                lines.append(f"    {k}:")
                for sub_k, sub_v in v.items():
                    if isinstance(sub_v, list):
                        lines.append(f"        {sub_k}:")
                        for item in sub_v:
                            lines.append(f"            - '{item}'")
                    else:
                        lines.append(f"        {sub_k}: '{sub_v}'")
            elif isinstance(v, list):
                lines.append(f"    {k}:")
                for item in v:
                    lines.append(f"        - '{item}'")
            else:
                lines.append(f"    {k}: '{v}'")
        lines.append(f"    condition: {self.condition}")
        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"    - '{fp}'")
        lines.append(f"level: {self.level}")
        return "\n".join(lines) + "\n"
