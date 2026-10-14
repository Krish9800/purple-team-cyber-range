"""Automated Sigma detection rule tuning recommender for defensive gaps."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import TechniqueSeverity
from purple_range.models.heatmap import PurpleMatrixHeatmap
from purple_range.models.sigma import SigmaRule
from purple_range.models.technique import MitreTechnique


class DetectionTuningAdvisor:
    """Synthesizes standardized Sigma detection rules for missed adversary techniques."""

    def __init__(self, author: str = "Purple-Team Detection Tuning Advisor") -> None:
        self.author = author

    def map_severity_level(self, severity: TechniqueSeverity) -> str:
        """Map technique severity to Sigma rule alert level."""
        mapping = {
            TechniqueSeverity.INFORMATIONAL: "informational",
            TechniqueSeverity.LOW: "low",
            TechniqueSeverity.MEDIUM: "medium",
            TechniqueSeverity.HIGH: "high",
            TechniqueSeverity.CRITICAL: "critical",
        }
        return mapping.get(severity, "medium")

    def format_mitre_reference(self, technique_id: str) -> str:
        """Construct official MITRE ATT&CK reference URL."""
        parts = technique_id.split(".")
        if len(parts) == 2:
            return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
        return f"https://attack.mitre.org/techniques/{parts[0]}/"

    def recommend_rule(
        self, technique: MitreTechnique, step: EmulationStep | None = None
    ) -> SigmaRule:
        """Generate tailored Sigma rule for a missed technique and optional execution telemetry."""
        date_str = datetime.now(UTC).strftime("%Y-%m-%d")
        tech_id_lower = technique.technique_id.lower()
        tactic_lower = technique.tactic.value.lower()
        ref_url = self.format_mitre_reference(technique.technique_id)

        tags = [
            f"attack.{tactic_lower}",
            f"attack.{tech_id_lower}",
        ]

        detection_logic: dict[str, Any]
        false_positives: list[str]

        # Specialize rule detection logic based on technique
        if technique.technique_id.startswith("T1087"):
            title = f"Suspicious Local Account Discovery ({technique.technique_id})"
            description = (
                f"Detects command execution attempting local account enumeration "
                f"as observed during adversary emulation of {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "Image|endswith": ["/cat", "/getent", "/id", "/whoami"],
                    "CommandLine|contains": ["/etc/passwd", "whoami", "id -u"],
                }
            }
            false_positives = ["System administration audits", "User onboarding scripts"]

        elif technique.technique_id.startswith("T1046"):
            title = f"Network Service Discovery Activity ({technique.technique_id})"
            description = (
                f"Detects local network socket or port enumeration commands "
                f"matching adversary tradecraft in {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "Image|endswith": ["/ss", "/netstat", "/nmap"],
                    "CommandLine|contains": ["-tulpn", "-tuln", "-sT", "-sS"],
                }
            }
            false_positives = ["Legitimate network troubleshooting by administrators"]

        elif technique.technique_id.startswith("T1003"):
            title = f"Credential Access: Sensitive File / Memory Read ({technique.technique_id})"
            description = (
                f"Detects unauthorized access attempts to /etc/shadow or credential databases "
                f"associated with {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "CommandLine|contains": ["/etc/shadow", "/etc/gshadow", "mimikatz"],
                }
            }
            false_positives = ["Automated security compliance verification agents"]

        elif technique.technique_id.startswith("T1547"):
            title = f"Persistence: Autostart File Modification ({technique.technique_id})"
            description = (
                f"Detects file creations or modifications in autostart execution paths "
                f"mapping to {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "CommandLine|contains": [".purple_autostart", "cron.d", "init.d", "systemd"],
                }
            }
            false_positives = ["Software package installation and system updates"]

        elif technique.technique_id.startswith("T1548"):
            title = f"Privilege Escalation: Sudo Abuse / Inspect ({technique.technique_id})"
            description = (
                f"Detects anomalous or unauthenticated sudo checks reflecting {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "Image|endswith": "/sudo",
                    "CommandLine|contains": ["-l", "-n -l", "--list"],
                }
            }
            false_positives = ["Helpdesk or admin privilege verification"]

        elif technique.technique_id.startswith("T1070"):
            title = f"Defense Evasion: Indicator File Removal ({technique.technique_id})"
            description = (
                f"Detects file or log deletion activity attempting defense evasion "
                f"under {technique.name}."
            )
            detection_logic = {
                "selection": {
                    "Image|endswith": ["/rm", "/shred", "/truncate"],
                    "CommandLine|contains": ["-f", "-rf", ".log", ".purple_"],
                }
            }
            false_positives = ["Log rotation daemons (logrotate)", "Temporary file cleanup jobs"]

        else:
            # Fallback dynamic synthesis based on technique commands and step telemetry
            title = f"Adversary Emulation Detection: {technique.name} ({technique.technique_id})"
            description = (
                f"Remediation rule for unmonitored MITRE ATT&CK technique {technique.technique_id}."
            )
            cmd = step.command_executed if step else technique.command_template
            first_token = cmd.split()[0].replace("/", "") if cmd.strip() else "bash"
            detection_logic = {
                "selection": {
                    "Image|endswith": f"/{first_token}",
                    "CommandLine|contains": cmd[:40].strip(),
                }
            }
            false_positives = ["Authorized IT automation scripts"]

        return SigmaRule(
            id=str(uuid4()),
            title=title,
            status="experimental",
            description=description,
            references=[ref_url],
            author=self.author,
            date=date_str,
            logsource={"category": "process_creation", "product": technique.platform.value},
            detection=detection_logic,
            condition="selection",
            falsepositives=false_positives,
            level=self.map_severity_level(technique.severity),
            tags=tags,
        )

    def recommend_for_heatmap(
        self, heatmap: PurpleMatrixHeatmap, registry: TechniqueRegistry
    ) -> list[SigmaRule]:
        """Generate remediation Sigma rules for all identified blind spots in a heatmap."""
        rules: list[SigmaRule] = []
        for blind_tech_id in heatmap.blind_spots:
            tech = registry.get(blind_tech_id)
            if tech:
                rule = self.recommend_rule(technique=tech)
                rules.append(rule)
        return rules

    @classmethod
    def export_rules_bundle(cls, rules: list[SigmaRule]) -> str:
        """Serialize a list of Sigma rules into a multi-document YAML stream."""
        if not rules:
            return ""
        return "\n---\n".join(r.to_yaml() for r in rules)
