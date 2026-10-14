"""MITRE ATT&CK and Purple Team Enums."""

from enum import StrEnum


class MitreTactic(StrEnum):
    """MITRE ATT&CK Enterprise tactics."""

    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class EmulationStatus(StrEnum):
    """Lifecycle state of an adversary emulation step or campaign."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class DetectionVerdict(StrEnum):
    """Outcome of detection verification for an adversary technique."""

    DETECTED = "DETECTED"
    BLOCKED = "BLOCKED"
    MISSED = "MISSED"


class TechniqueSeverity(StrEnum):
    """Severity classification of an ATT&CK technique."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Platform(StrEnum):
    """Target platform for emulation."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    CROSS_PLATFORM = "cross-platform"


class DataSource(StrEnum):
    """Telemetry data source categories mapped to MITRE ATT&CK."""

    PROCESS_MONITORING = "process_monitoring"
    COMMAND_EXECUTION = "command_execution"
    FILE_MONITORING = "file_monitoring"
    NETWORK_TRAFFIC = "network_traffic"
    REGISTRY_MONITORING = "registry_monitoring"
    AUTHENTICATION_LOGS = "authentication_logs"
    USER_ACCOUNT_TRACKING = "user_account_tracking"
