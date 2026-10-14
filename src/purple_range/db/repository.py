"""Repository for persisting purple-team campaigns, steps, alerts, and heatmaps in SQLite."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from purple_range.db.connection import DatabaseManager
from purple_range.db.schema import SCHEMA_DDL
from purple_range.models.campaign import CampaignPlaybook, PurpleCampaign
from purple_range.models.detection import DetectionAlert, DetectionEvidence
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import (
    DetectionVerdict,
    EmulationStatus,
    MitreTactic,
    TechniqueSeverity,
)
from purple_range.models.heatmap import (
    PurpleMatrixHeatmap,
    TacticSummary,
    TechniqueCoverageCell,
)
from purple_range.models.sigma import SigmaRule


def _parse_iso(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        return datetime.now(UTC)


class PurpleRangeRepository:
    """ACID data access object managing SQLite persistence with WAL mode."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db = db_manager

    def initialize_schema(self) -> None:
        """Create database tables and performance indices if they do not exist."""
        with self.db.connection() as conn:
            conn.executescript(SCHEMA_DDL)

    # --- Playbooks ---
    def save_playbook(self, playbook: CampaignPlaybook) -> None:
        """Persist or update campaign playbook template."""
        now_str = datetime.now(UTC).isoformat()
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO playbooks (
                    playbook_id, name, description, technique_ids_json, author, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(playbook_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    technique_ids_json = excluded.technique_ids_json,
                    author = excluded.author;
                """,
                (
                    playbook.playbook_id,
                    playbook.name,
                    playbook.description,
                    json.dumps(playbook.technique_ids),
                    playbook.author,
                    now_str,
                ),
            )

    def get_playbook(self, playbook_id: str) -> CampaignPlaybook | None:
        """Fetch playbook by unique ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE playbook_id = ?;", (playbook_id,)
            ).fetchone()
            if not row:
                return None
            return CampaignPlaybook(
                playbook_id=str(row["playbook_id"]),
                name=str(row["name"]),
                description=str(row["description"]),
                technique_ids=json.loads(str(row["technique_ids_json"])),
                author=str(row["author"]),
            )

    def list_playbooks(self) -> list[CampaignPlaybook]:
        """List all registered campaign playbooks."""
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM playbooks ORDER BY name;").fetchall()
            return [
                CampaignPlaybook(
                    playbook_id=str(r["playbook_id"]),
                    name=str(r["name"]),
                    description=str(r["description"]),
                    technique_ids=json.loads(str(r["technique_ids_json"])),
                    author=str(r["author"]),
                )
                for r in rows
            ]

    # --- Campaigns ---
    def save_campaign(self, campaign: PurpleCampaign) -> None:
        """Persist or update a purple team campaign execution."""
        started_str = campaign.started_at.isoformat()
        completed_str = campaign.completed_at.isoformat() if campaign.completed_at else None

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO campaigns (
                    campaign_id, name, playbook_id, status, operator,
                    started_at, completed_at, total_techniques, detected_count,
                    blocked_count, missed_count, detection_coverage_rate,
                    mean_alert_latency_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    total_techniques = excluded.total_techniques,
                    detected_count = excluded.detected_count,
                    blocked_count = excluded.blocked_count,
                    missed_count = excluded.missed_count,
                    detection_coverage_rate = excluded.detection_coverage_rate,
                    mean_alert_latency_seconds = excluded.mean_alert_latency_seconds;
                """,
                (
                    campaign.campaign_id,
                    campaign.name,
                    campaign.playbook_id,
                    campaign.status.value,
                    campaign.operator,
                    started_str,
                    completed_str,
                    campaign.total_techniques,
                    campaign.detected_count,
                    campaign.blocked_count,
                    campaign.missed_count,
                    campaign.detection_coverage_rate,
                    campaign.mean_alert_latency_seconds,
                ),
            )

        # Save child steps and evidences if present
        for step in campaign.emulation_steps:
            self.save_emulation_step(step)
        for ev in campaign.evidences:
            self.save_evidence(ev)

    def get_campaign(self, campaign_id: str) -> PurpleCampaign | None:
        """Retrieve campaign by ID including its steps and detection evidences."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE campaign_id = ?;", (campaign_id,)
            ).fetchone()
            if not row:
                return None

            started_at = _parse_iso(str(row["started_at"])) or datetime.now(UTC)
            completed_at = _parse_iso(row["completed_at"])

            steps = self.get_steps_for_campaign(campaign_id)
            evidences = self.get_evidences_for_campaign(campaign_id)

            return PurpleCampaign(
                campaign_id=str(row["campaign_id"]),
                name=str(row["name"]),
                playbook_id=str(row["playbook_id"]) if row["playbook_id"] else None,
                status=EmulationStatus(str(row["status"])),
                operator=str(row["operator"]),
                started_at=started_at,
                completed_at=completed_at,
                emulation_steps=steps,
                evidences=evidences,
                total_techniques=int(row["total_techniques"]),
                detected_count=int(row["detected_count"]),
                blocked_count=int(row["blocked_count"]),
                missed_count=int(row["missed_count"]),
                detection_coverage_rate=float(row["detection_coverage_rate"]),
                mean_alert_latency_seconds=float(row["mean_alert_latency_seconds"]),
            )

    def list_campaigns(self) -> list[PurpleCampaign]:
        """List summary of all campaigns ordered by start date descending."""
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM campaigns ORDER BY started_at DESC;").fetchall()
            result: list[PurpleCampaign] = []
            for r in rows:
                c_id = str(r["campaign_id"])
                started_at = _parse_iso(str(r["started_at"])) or datetime.now(UTC)
                completed_at = _parse_iso(r["completed_at"])
                result.append(
                    PurpleCampaign(
                        campaign_id=c_id,
                        name=str(r["name"]),
                        playbook_id=str(r["playbook_id"]) if r["playbook_id"] else None,
                        status=EmulationStatus(str(r["status"])),
                        operator=str(r["operator"]),
                        started_at=started_at,
                        completed_at=completed_at,
                        total_techniques=int(r["total_techniques"]),
                        detected_count=int(r["detected_count"]),
                        blocked_count=int(r["blocked_count"]),
                        missed_count=int(r["missed_count"]),
                        detection_coverage_rate=float(r["detection_coverage_rate"]),
                        mean_alert_latency_seconds=float(r["mean_alert_latency_seconds"]),
                    )
                )
            return result

    # --- Emulation Steps ---
    def save_emulation_step(self, step: EmulationStep) -> None:
        """Persist an atomic emulation execution step."""
        started_str = step.started_at.isoformat()
        completed_str = step.completed_at.isoformat() if step.completed_at else None

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO emulation_steps (
                    execution_id, campaign_id, technique_id, technique_name,
                    tactic, target_host, command_executed, stdout, stderr,
                    exit_code, status, process_pid, started_at, completed_at,
                    duration_ms, cleanup_executed, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(execution_id) DO UPDATE SET
                    stdout = excluded.stdout,
                    stderr = excluded.stderr,
                    exit_code = excluded.exit_code,
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    duration_ms = excluded.duration_ms,
                    cleanup_executed = excluded.cleanup_executed,
                    error_message = excluded.error_message;
                """,
                (
                    step.execution_id,
                    step.campaign_id,
                    step.technique_id,
                    step.technique_name,
                    step.tactic.value,
                    step.target_host,
                    step.command_executed,
                    step.stdout,
                    step.stderr,
                    step.exit_code,
                    step.status.value,
                    step.process_pid,
                    started_str,
                    completed_str,
                    step.duration_ms,
                    1 if step.cleanup_executed else 0,
                    step.error_message,
                ),
            )

    def get_steps_for_campaign(self, campaign_id: str) -> list[EmulationStep]:
        """Fetch all emulation steps belonging to a specific campaign."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM emulation_steps WHERE campaign_id = ? ORDER BY started_at ASC;",
                (campaign_id,),
            ).fetchall()
            steps: list[EmulationStep] = []
            for r in rows:
                started_at = _parse_iso(str(r["started_at"])) or datetime.now(UTC)
                completed_at = _parse_iso(r["completed_at"])
                steps.append(
                    EmulationStep(
                        execution_id=str(r["execution_id"]),
                        campaign_id=str(r["campaign_id"]),
                        technique_id=str(r["technique_id"]),
                        technique_name=str(r["technique_name"]),
                        tactic=MitreTactic(str(r["tactic"])),
                        target_host=str(r["target_host"]),
                        command_executed=str(r["command_executed"]),
                        stdout=str(r["stdout"]),
                        stderr=str(r["stderr"]),
                        exit_code=int(r["exit_code"]),
                        status=EmulationStatus(str(r["status"])),
                        process_pid=int(r["process_pid"]) if r["process_pid"] is not None else None,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=float(r["duration_ms"]),
                        cleanup_executed=bool(r["cleanup_executed"]),
                        error_message=str(r["error_message"]) if r["error_message"] else None,
                    )
                )
            return steps

    # --- Detection Alerts ---
    def save_alert(self, alert: DetectionAlert) -> None:
        """Persist a normalized defensive detection alert."""
        ts_str = alert.timestamp.isoformat()
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO detection_alerts (
                    alert_id, sensor_name, technique_id, timestamp, host,
                    process_name, process_pid, command_line, alert_signature,
                    severity, raw_log_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO NOTHING;
                """,
                (
                    alert.alert_id,
                    alert.sensor_name,
                    alert.technique_id,
                    ts_str,
                    alert.host,
                    alert.process_name,
                    alert.process_pid,
                    alert.command_line,
                    alert.alert_signature,
                    alert.severity.value,
                    json.dumps(alert.raw_log),
                ),
            )

    def list_alerts(self, limit: int = 100) -> list[DetectionAlert]:
        """List recent detection alerts."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM detection_alerts ORDER BY timestamp DESC LIMIT ?;",
                (limit,),
            ).fetchall()
            alerts: list[DetectionAlert] = []
            for r in rows:
                ts = _parse_iso(str(r["timestamp"])) or datetime.now(UTC)
                raw = json.loads(str(r["raw_log_json"])) if r["raw_log_json"] else {}
                alerts.append(
                    DetectionAlert(
                        alert_id=str(r["alert_id"]),
                        sensor_name=str(r["sensor_name"]),
                        technique_id=str(r["technique_id"]) if r["technique_id"] else None,
                        timestamp=ts,
                        host=str(r["host"]),
                        process_name=str(r["process_name"]) if r["process_name"] else None,
                        process_pid=int(r["process_pid"]) if r["process_pid"] is not None else None,
                        command_line=str(r["command_line"]) if r["command_line"] else None,
                        alert_signature=str(r["alert_signature"]),
                        severity=TechniqueSeverity(str(r["severity"])),
                        raw_log=raw,
                    )
                )
            return alerts

    # --- Detection Evidences ---
    def save_evidence(self, evidence: DetectionEvidence) -> None:
        """Persist a detection correlation evidence record."""
        matched_str = evidence.matched_at.isoformat()
        matched_alerts_dict = [a.model_dump(mode="json") for a in evidence.matched_alerts]

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO detection_evidences (
                    evidence_id, execution_id, technique_id, verdict,
                    matched_alerts_json, detection_latency_seconds,
                    matched_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    verdict = excluded.verdict,
                    matched_alerts_json = excluded.matched_alerts_json,
                    detection_latency_seconds = excluded.detection_latency_seconds,
                    notes = excluded.notes;
                """,
                (
                    evidence.evidence_id,
                    evidence.execution_id,
                    evidence.technique_id,
                    evidence.verdict.value,
                    json.dumps(matched_alerts_dict),
                    evidence.detection_latency_seconds,
                    matched_str,
                    evidence.notes,
                ),
            )

    def get_evidences_for_campaign(self, campaign_id: str) -> list[DetectionEvidence]:
        """Fetch all detection evidences matching steps of a specific campaign."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT e.* FROM detection_evidences e
                JOIN emulation_steps s ON e.execution_id = s.execution_id
                WHERE s.campaign_id = ?
                ORDER BY e.matched_at ASC;
                """,
                (campaign_id,),
            ).fetchall()
            evidences: list[DetectionEvidence] = []
            for r in rows:
                matched_at = _parse_iso(str(r["matched_at"])) or datetime.now(UTC)
                alerts_data = json.loads(str(r["matched_alerts_json"]))
                matched_alerts = [DetectionAlert(**a) for a in alerts_data]
                evidences.append(
                    DetectionEvidence(
                        evidence_id=str(r["evidence_id"]),
                        execution_id=str(r["execution_id"]),
                        technique_id=str(r["technique_id"]),
                        verdict=DetectionVerdict(str(r["verdict"])),
                        matched_alerts=matched_alerts,
                        detection_latency_seconds=(
                            float(r["detection_latency_seconds"])
                            if r["detection_latency_seconds"] is not None
                            else None
                        ),
                        matched_at=matched_at,
                        notes=str(r["notes"]),
                    )
                )
            return evidences

    # --- Heatmaps ---
    def save_heatmap(self, heatmap: PurpleMatrixHeatmap) -> None:
        """Persist a calculated ATT&CK matrix heatmap."""
        report_id = str(uuid4())
        gen_str = heatmap.generated_at.isoformat()
        tactic_dict = {k: v.model_dump(mode="json") for k, v in heatmap.tactic_summaries.items()}
        cells_dict = [c.model_dump(mode="json") for c in heatmap.cells]

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO matrix_heatmaps (
                    report_id, campaign_id, generated_at, total_techniques,
                    detected_count, blocked_count, missed_count,
                    detection_coverage_rate, tactic_summaries_json,
                    cells_json, blind_spots_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    report_id,
                    heatmap.campaign_id,
                    gen_str,
                    heatmap.total_techniques,
                    heatmap.detected_count,
                    heatmap.blocked_count,
                    heatmap.missed_count,
                    heatmap.detection_coverage_rate,
                    json.dumps(tactic_dict),
                    json.dumps(cells_dict),
                    json.dumps(heatmap.blind_spots),
                    json.dumps(heatmap.metadata),
                ),
            )

    def get_latest_heatmap(self, campaign_id: str | None = None) -> PurpleMatrixHeatmap | None:
        """Fetch the most recently computed matrix heatmap."""
        with self.db.connection() as conn:
            if campaign_id:
                row = conn.execute(
                    """
                    SELECT * FROM matrix_heatmaps
                    WHERE campaign_id = ?
                    ORDER BY generated_at DESC LIMIT 1;
                    """,
                    (campaign_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM matrix_heatmaps ORDER BY generated_at DESC LIMIT 1;"
                ).fetchone()

            if not row:
                return None

            gen_at = _parse_iso(str(row["generated_at"])) or datetime.now(UTC)
            tactic_data: dict[str, Any] = json.loads(str(row["tactic_summaries_json"]))
            cells_data: list[dict[str, Any]] = json.loads(str(row["cells_json"]))

            tactic_summaries = {k: TacticSummary(**v) for k, v in tactic_data.items()}
            cells = [TechniqueCoverageCell(**c) for c in cells_data]

            return PurpleMatrixHeatmap(
                campaign_id=str(row["campaign_id"]) if row["campaign_id"] else None,
                generated_at=gen_at,
                total_techniques=int(row["total_techniques"]),
                detected_count=int(row["detected_count"]),
                blocked_count=int(row["blocked_count"]),
                missed_count=int(row["missed_count"]),
                detection_coverage_rate=float(row["detection_coverage_rate"]),
                tactic_summaries=tactic_summaries,
                cells=cells,
                blind_spots=json.loads(str(row["blind_spots_json"])),
                metadata=json.loads(str(row["metadata_json"])),
            )

    # --- Sigma Rules ---
    def save_sigma_rule(self, rule: SigmaRule, technique_id: str | None = None) -> None:
        """Persist a synthesized Sigma detection rule."""
        yaml_content = rule.to_yaml()
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO sigma_rules (
                    rule_id, technique_id, title, status, description,
                    author, date, level, logsource_json, detection_json,
                    condition, falsepositives_json, tags_json, references_json,
                    yaml_content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    title = excluded.title,
                    description = excluded.description,
                    yaml_content = excluded.yaml_content;
                """,
                (
                    rule.id,
                    technique_id,
                    rule.title,
                    rule.status,
                    rule.description,
                    rule.author,
                    rule.date,
                    rule.level,
                    json.dumps(rule.logsource),
                    json.dumps(rule.detection),
                    rule.condition,
                    json.dumps(rule.falsepositives),
                    json.dumps(rule.tags),
                    json.dumps(rule.references),
                    yaml_content,
                ),
            )

    def list_sigma_rules(self) -> list[SigmaRule]:
        """Fetch all stored Sigma detection rules."""
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM sigma_rules ORDER BY date DESC;").fetchall()
            rules: list[SigmaRule] = []
            for r in rows:
                rules.append(
                    SigmaRule(
                        id=str(r["rule_id"]),
                        title=str(r["title"]),
                        status=str(r["status"]),
                        description=str(r["description"]),
                        author=str(r["author"]),
                        date=str(r["date"]),
                        level=str(r["level"]),
                        logsource=json.loads(str(r["logsource_json"])),
                        detection=json.loads(str(r["detection_json"])),
                        condition=str(r["condition"]),
                        falsepositives=json.loads(str(r["falsepositives_json"])),
                        tags=json.loads(str(r["tags_json"])),
                        references=json.loads(str(r["references_json"])),
                    )
                )
            return rules
