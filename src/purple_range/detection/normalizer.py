"""Alert and telemetry normalizer for defensive sensors."""

from datetime import UTC, datetime
from typing import Any

from purple_range.models.detection import DetectionAlert
from purple_range.models.enums import TechniqueSeverity


class AlertNormalizer:
    """Transforms heterogeneous sensor logs into normalized DetectionAlert models."""

    @classmethod
    def normalize_raw_log(cls, raw: dict[str, Any], sensor_name: str) -> DetectionAlert:
        """Parse dictionary event from Sysmon, Auditd, EDR, or SIEM into DetectionAlert."""
        # Extract timestamp
        ts = raw.get("timestamp") or raw.get("@timestamp") or raw.get("time")
        if isinstance(ts, str):
            try:
                # Handle ISO 8601 strings
                event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                event_time = datetime.now(UTC)
        elif isinstance(ts, (int, float)):
            event_time = datetime.fromtimestamp(ts, tz=UTC)
        else:
            event_time = datetime.now(UTC)

        # Host
        host_val = raw.get("host") or raw.get("hostname") or raw.get("computer_name")
        host = str(host_val or "localhost")

        # Process and command telemetry
        proc_name = raw.get("process_name") or raw.get("Image") or raw.get("process")
        proc_pid_raw = raw.get("process_pid") or raw.get("ProcessId") or raw.get("pid")
        is_digit = proc_pid_raw is not None and str(proc_pid_raw).isdigit()
        proc_pid = int(str(proc_pid_raw)) if is_digit else None
        cmdline = raw.get("command_line") or raw.get("CommandLine") or raw.get("cmd")

        # Technique ID
        tech_id = raw.get("technique_id") or raw.get("mitre_id") or raw.get("mitre_technique")
        if tech_id and not str(tech_id).startswith("T"):
            tech_id = f"T{tech_id}"

        # Signature and Severity
        sig = (
            raw.get("alert_signature")
            or raw.get("rule_name")
            or raw.get("signature")
            or raw.get("message")
            or f"{sensor_name.upper()} Security Event"
        )

        sev_raw = str(raw.get("severity", "MEDIUM")).upper()
        severity = TechniqueSeverity.MEDIUM
        for sev in TechniqueSeverity:
            if sev.value == sev_raw:
                severity = sev
                break

        return DetectionAlert(
            sensor_name=sensor_name,
            technique_id=str(tech_id) if tech_id else None,
            timestamp=event_time,
            host=host,
            process_name=str(proc_name) if proc_name else None,
            process_pid=proc_pid,
            command_line=str(cmdline) if cmdline else None,
            alert_signature=str(sig),
            severity=severity,
            raw_log=raw,
        )
