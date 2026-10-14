"""Campaign Orchestrator chaining adversary techniques and executing purple drills."""

from datetime import UTC, datetime
from uuid import uuid4

from purple_range.advisor.advisor import DetectionTuningAdvisor
from purple_range.analytics.engine import GapAnalysisEngine
from purple_range.db.repository import PurpleRangeRepository
from purple_range.detection.evaluator import DetectionCoverageEvaluator
from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.emulation.runner import AdversaryEmulationEngine
from purple_range.models.campaign import CampaignPlaybook, PurpleCampaign
from purple_range.models.enums import EmulationStatus
from purple_range.models.heatmap import PurpleMatrixHeatmap
from purple_range.models.sigma import SigmaRule

DEFAULT_PLAYBOOKS: list[CampaignPlaybook] = [
    CampaignPlaybook(
        playbook_id="ransomware-killchain",
        name="Ransomware Kill Chain",
        description=(
            "Emulates local discovery, privilege escalation, and defense evasion indicators."
        ),
        technique_ids=["T1087.001", "T1548.003", "T1070.004"],
        author="Purple-Team Range Core",
    ),
    CampaignPlaybook(
        playbook_id="apt-recon-persistence",
        name="APT Discovery & Persistence Chain",
        description="Emulates network enumeration, credential hunting, and autostart persistence.",
        technique_ids=["T1046", "T1003.008", "T1547.001"],
        author="Purple-Team Range Core",
    ),
]


class CampaignOrchestrator:
    """Coordinates red-team emulation, blue-team detection verification, and gap reporting."""

    def __init__(
        self,
        repository: PurpleRangeRepository,
        registry: TechniqueRegistry | None = None,
        emulation_engine: AdversaryEmulationEngine | None = None,
        evaluator: DetectionCoverageEvaluator | None = None,
        analytics_engine: GapAnalysisEngine | None = None,
        advisor: DetectionTuningAdvisor | None = None,
    ) -> None:
        self.repo = repository
        self.registry = registry or TechniqueRegistry()
        self.emulation_engine = emulation_engine or AdversaryEmulationEngine()
        self.evaluator = evaluator or DetectionCoverageEvaluator()
        self.analytics_engine = analytics_engine or GapAnalysisEngine()
        self.advisor = advisor or DetectionTuningAdvisor()
        self._seed_default_playbooks()

    def _seed_default_playbooks(self) -> None:
        """Seed default playbooks if not already present in repository."""
        for pb in DEFAULT_PLAYBOOKS:
            if not self.repo.get_playbook(pb.playbook_id):
                self.repo.save_playbook(pb)

    async def async_run_campaign(
        self,
        name: str,
        technique_ids: list[str] | None = None,
        playbook_id: str | None = None,
        operator: str = "purple_operator",
        target_host: str = "localhost",
    ) -> tuple[PurpleCampaign, PurpleMatrixHeatmap, list[SigmaRule]]:
        """Execute an automated adversary scenario playbook, evaluate telemetry, and tune rules."""
        # 1. Resolve technique sequence
        if playbook_id:
            pb = self.repo.get_playbook(playbook_id)
            if not pb:
                raise ValueError(f"Playbook '{playbook_id}' not found")
            seq = pb.technique_ids
            actual_playbook_id: str | None = playbook_id
        elif technique_ids:
            seq = technique_ids
            actual_playbook_id = None
        else:
            raise ValueError("Either playbook_id or technique_ids must be provided")

        campaign_id = str(uuid4())
        started_at = datetime.now(UTC)

        campaign = PurpleCampaign(
            campaign_id=campaign_id,
            name=name,
            playbook_id=actual_playbook_id,
            status=EmulationStatus.RUNNING,
            operator=operator,
            started_at=started_at,
        )
        self.repo.save_campaign(campaign)

        # 2. Execute adversary emulation steps sequentially
        executed_steps = []
        for tid in seq:
            tech = self.registry.get(tid)
            if not tech:
                continue
            step = await self.emulation_engine.async_execute_technique(
                technique=tech,
                campaign_id=campaign_id,
                target_host=target_host,
            )
            self.repo.save_emulation_step(step)
            executed_steps.append(step)

        # 3. Synchronize stored detection alerts into evaluator
        stored_alerts = self.repo.list_alerts(limit=500)
        self.evaluator.clear_alerts()
        for alert in stored_alerts:
            self.evaluator.ingest_alert(alert)

        # 4. Evaluate detection outcomes
        evidences = self.evaluator.evaluate_campaign_steps(executed_steps)
        for ev in evidences:
            self.repo.save_evidence(ev)

        # 5. Compute metrics & generate ATT&CK Heatmap
        heatmap = self.analytics_engine.generate_heatmap(
            steps=executed_steps,
            evidences=evidences,
            campaign_id=campaign_id,
        )
        self.repo.save_heatmap(heatmap)

        # 6. Generate remediation Sigma rules for defensive blind spots
        remediation_rules = self.advisor.recommend_for_heatmap(heatmap, self.registry)
        for rule in remediation_rules:
            self.repo.save_sigma_rule(rule)

        # 7. Finalize campaign record
        completed_at = datetime.now(UTC)
        valid_latencies = [
            e.detection_latency_seconds
            for e in evidences
            if e.detection_latency_seconds is not None
        ]
        mean_latency = (
            round(sum(valid_latencies) / len(valid_latencies), 3) if valid_latencies else 0.0
        )

        final_campaign = PurpleCampaign(
            campaign_id=campaign_id,
            name=name,
            playbook_id=actual_playbook_id,
            status=EmulationStatus.COMPLETED,
            operator=operator,
            started_at=started_at,
            completed_at=completed_at,
            emulation_steps=executed_steps,
            evidences=evidences,
            total_techniques=heatmap.total_techniques,
            detected_count=heatmap.detected_count,
            blocked_count=heatmap.blocked_count,
            missed_count=heatmap.missed_count,
            detection_coverage_rate=heatmap.detection_coverage_rate,
            mean_alert_latency_seconds=mean_latency,
        )
        self.repo.save_campaign(final_campaign)

        return final_campaign, heatmap, remediation_rules
