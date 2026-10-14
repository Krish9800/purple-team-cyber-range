"""Temporal and attribute correlation for red emulation steps and defensive alerts."""

from datetime import timedelta

from purple_range.models.detection import DetectionAlert
from purple_range.models.emulation import EmulationStep


class DetectionCorrelator:
    """Evaluates whether a defensive security alert correlates with an emulation step."""

    def __init__(
        self,
        correlation_window_seconds: int = 120,
        clock_skew_tolerance_seconds: float = 2.0,
    ) -> None:
        self.correlation_window_seconds = correlation_window_seconds
        self.clock_skew_tolerance_seconds = clock_skew_tolerance_seconds

    def is_temporally_correlated(self, step: EmulationStep, alert: DetectionAlert) -> bool:
        """Verify alert timestamp falls within emulation window with tolerance."""
        start_bound = step.started_at - timedelta(seconds=self.clock_skew_tolerance_seconds)
        end_time = step.completed_at or step.started_at
        end_bound = end_time + timedelta(seconds=float(self.correlation_window_seconds))
        return start_bound <= alert.timestamp <= end_bound

    def is_host_correlated(self, step: EmulationStep, alert: DetectionAlert) -> bool:
        """Verify alert originated on target host where technique executed."""
        local_aliases = {"localhost", "127.0.0.1", "::1"}
        step_host = step.target_host.lower()
        alert_host = alert.host.lower()

        if step_host == alert_host:
            return True
        return bool(step_host in local_aliases and alert_host in local_aliases)

    def is_attribute_correlated(self, step: EmulationStep, alert: DetectionAlert) -> bool:
        """Check for MITRE technique code, PID, process name, or command substring correlation."""
        # 1. Technique ID match
        if alert.technique_id:
            cleaned_alert_tech = alert.technique_id.upper().strip()
            cleaned_step_tech = step.technique_id.upper().strip()
            if (
                cleaned_alert_tech == cleaned_step_tech
                or cleaned_step_tech.startswith(cleaned_alert_tech)
                or cleaned_alert_tech.startswith(cleaned_step_tech)
            ):
                return True

        # 2. Process PID match
        if (
            step.process_pid is not None
            and alert.process_pid is not None
            and step.process_pid == alert.process_pid
        ):
            return True

        # 3. Command line match
        cmd_exec = step.command_executed.lower()
        if alert.command_line:
            alert_cmd = alert.command_line.lower()
            if cmd_exec in alert_cmd or alert_cmd in cmd_exec:
                return True
            tokens = [t.strip("-") for t in cmd_exec.split() if len(t.strip("-")) >= 2]
            if any(t in alert_cmd for t in tokens):
                return True

        # 4. Signature contains technique name or ID
        sig_lower = alert.alert_signature.lower()
        return bool(
            step.technique_id.lower() in sig_lower or step.technique_name.lower() in sig_lower
        )

    def correlate(self, step: EmulationStep, alert: DetectionAlert) -> bool:
        """Check if alert matches step across temporal, host, and attribute criteria."""
        if not self.is_temporally_correlated(step, alert):
            return False
        if not self.is_host_correlated(step, alert):
            return False
        return self.is_attribute_correlated(step, alert)

    def calculate_latency_seconds(self, step: EmulationStep, alert: DetectionAlert) -> float:
        """Compute latency from emulation start until alert detection."""
        diff = (alert.timestamp - step.started_at).total_seconds()
        return round(max(0.0, diff), 3)
