"""Detection Coverage Evaluator classifying technique verdicts into DETECTED, BLOCKED, MISSED."""

from datetime import UTC, datetime
from typing import Any

from purple_range.detection.correlator import DetectionCorrelator
from purple_range.detection.normalizer import AlertNormalizer
from purple_range.models.detection import DetectionAlert, DetectionEvidence
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import DetectionVerdict

PREVENTION_KEYWORDS: tuple[str, ...] = (
    "permission denied",
    "eacces",
    "blocked",
    "prevented",
    "access denied",
    "operation not permitted",
)


class DetectionCoverageEvaluator:
    """Ingests security telemetry and classifies detection coverage for red team steps."""

    def __init__(
        self,
        correlation_window_seconds: int = 120,
        correlator: DetectionCorrelator | None = None,
    ) -> None:
        self.correlation_window_seconds = correlation_window_seconds
        self.correlator = correlator or DetectionCorrelator(
            correlation_window_seconds=correlation_window_seconds
        )
        self._alerts: list[DetectionAlert] = []

    def ingest_alert(self, alert: DetectionAlert) -> None:
        """Register a normalized detection alert in evaluator memory."""
        self._alerts.append(alert)

    def ingest_raw_log(self, raw: dict[str, Any], sensor_name: str) -> DetectionAlert:
        """Normalize raw security log dictionary and register it."""
        alert = AlertNormalizer.normalize_raw_log(raw, sensor_name)
        self.ingest_alert(alert)
        return alert

    def get_alerts(self) -> list[DetectionAlert]:
        """Return all registered alerts."""
        return list(self._alerts)

    def clear_alerts(self) -> None:
        """Flush in-memory alert buffer."""
        self._alerts.clear()

    def is_prevented_or_blocked(
        self, step: EmulationStep, matched_alerts: list[DetectionAlert]
    ) -> bool:
        """Determine if an execution was blocked by OS permissions or defensive controls."""
        # 1. Check defensive sensor prevention signals
        for alert in matched_alerts:
            sig = alert.alert_signature.lower()
            if any(term in sig for term in ("block", "prevent", "quarantine", "deny")):
                return True

        # 2. Check execution exit codes combined with access denial/prevention output
        if step.exit_code != 0:
            out_lower = f"{step.stdout} {step.stderr}".lower()
            if any(term in out_lower for term in PREVENTION_KEYWORDS):
                return True

        return False

    def evaluate_step(self, step: EmulationStep) -> DetectionEvidence:
        """Correlate step against telemetry and evaluate verdict: DETECTED, BLOCKED, or MISSED."""
        matched: list[DetectionAlert] = []
        for alert in self._alerts:
            if self.correlator.correlate(step, alert):
                matched.append(alert)

        # Sort chronologically
        matched.sort(key=lambda a: a.timestamp)

        # Classify verdict
        if self.is_prevented_or_blocked(step, matched):
            verdict = DetectionVerdict.BLOCKED
            latency = (
                self.correlator.calculate_latency_seconds(step, matched[0]) if matched else 0.0
            )
            notes = "Adversary technique execution prevented/blocked by system security controls"
        elif matched:
            verdict = DetectionVerdict.DETECTED
            latency = self.correlator.calculate_latency_seconds(step, matched[0])
            notes = (
                f"Correlated with {len(matched)} detection alert(s) from {matched[0].sensor_name}"
            )
        else:
            verdict = DetectionVerdict.MISSED
            latency = None
            notes = "Zero defensive alerts observed within correlation tolerance window"

        return DetectionEvidence(
            execution_id=step.execution_id,
            technique_id=step.technique_id,
            verdict=verdict,
            matched_alerts=matched,
            detection_latency_seconds=latency,
            matched_at=datetime.now(UTC),
            notes=notes,
        )

    def evaluate_campaign_steps(self, steps: list[EmulationStep]) -> list[DetectionEvidence]:
        """Batch evaluate detection outcomes for all steps in a campaign."""
        return [self.evaluate_step(step) for step in steps]

    @staticmethod
    def calculate_dcr(evidences: list[DetectionEvidence]) -> float:
        """Calculate Detection Coverage Rate (DCR) percentage."""
        if not evidences:
            return 0.0
        covered = sum(
            1
            for ev in evidences
            if ev.verdict in (DetectionVerdict.DETECTED, DetectionVerdict.BLOCKED)
        )
        return round((covered / len(evidences)) * 100.0, 2)
