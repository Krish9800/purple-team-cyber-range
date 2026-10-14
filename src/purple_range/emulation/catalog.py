"""Standard MITRE ATT&CK technique catalog for adversary emulation."""

from purple_range.models.enums import DataSource, MitreTactic, Platform, TechniqueSeverity
from purple_range.models.technique import MitreTechnique

BUILTIN_TECHNIQUES: list[MitreTechnique] = [
    MitreTechnique(
        technique_id="T1087.001",
        name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        severity=TechniqueSeverity.LOW,
        platform=Platform.LINUX,
        description="Adversaries may attempt to get a listing of local system accounts.",
        command_template="id -u && whoami && cat /etc/passwd | head -n 5",
        cleanup_command=None,
        data_sources=[DataSource.PROCESS_MONITORING, DataSource.COMMAND_EXECUTION],
        parameters={},
        safe_payload=True,
    ),
    MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        severity=TechniqueSeverity.LOW,
        platform=Platform.LINUX,
        description="Adversaries may attempt to get a listing of services running on hosts.",
        command_template="ss -tulpn 2>/dev/null || netstat -tuln 2>/dev/null || true",
        cleanup_command=None,
        data_sources=[DataSource.NETWORK_TRAFFIC, DataSource.PROCESS_MONITORING],
        parameters={},
        safe_payload=True,
    ),
    MitreTechnique(
        technique_id="T1003.008",
        name="OS Credential Dumping: /etc/shadow",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        severity=TechniqueSeverity.HIGH,
        platform=Platform.LINUX,
        description=(
            "Adversaries may attempt to dump credentials by reading "
            "the /etc/shadow file or memory caches."
        ),
        command_template=(
            "head -n 2 /etc/shadow 2>&1 || echo 'EACCES: /etc/shadow permission denied'"
        ),
        cleanup_command=None,
        data_sources=[DataSource.FILE_MONITORING, DataSource.PROCESS_MONITORING],
        parameters={},
        safe_payload=True,
    ),
    MitreTechnique(
        technique_id="T1547.001",
        name="Boot or Logon Autostart: Safe Persistence Emulation",
        tactic=MitreTactic.PERSISTENCE,
        severity=TechniqueSeverity.MEDIUM,
        platform=Platform.LINUX,
        description=(
            "Adversaries may achieve persistence by adding executables "
            "or scripts to startup locations."
        ),
        command_template=(
            "echo '#!/bin/sh\\n# Purple Range Test' > /tmp/.purple_autostart_test "
            "&& chmod +x /tmp/.purple_autostart_test"
        ),
        cleanup_command="rm -f /tmp/.purple_autostart_test",
        data_sources=[DataSource.FILE_MONITORING, DataSource.PROCESS_MONITORING],
        parameters={},
        safe_payload=True,
    ),
    MitreTechnique(
        technique_id="T1548.003",
        name="Abuse Elevation Control: Sudo and Sudoers",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        severity=TechniqueSeverity.HIGH,
        platform=Platform.LINUX,
        description=(
            "Adversaries may perform sudo checks or attempt unauthenticated privilege escalation."
        ),
        command_template="sudo -n -l 2>&1 || echo 'sudo: a password is required'",
        cleanup_command=None,
        data_sources=[DataSource.COMMAND_EXECUTION, DataSource.AUTHENTICATION_LOGS],
        parameters={},
        safe_payload=True,
    ),
    MitreTechnique(
        technique_id="T1070.004",
        name="Indicator Removal: File Deletion",
        tactic=MitreTactic.DEFENSE_EVASION,
        severity=TechniqueSeverity.LOW,
        platform=Platform.LINUX,
        description=(
            "Adversaries may delete files left behind by the actions of their malware or tools."
        ),
        command_template="touch /tmp/.purple_evasion_test && rm -f /tmp/.purple_evasion_test",
        cleanup_command="rm -f /tmp/.purple_evasion_test",
        data_sources=[DataSource.FILE_MONITORING, DataSource.PROCESS_MONITORING],
        parameters={},
        safe_payload=True,
    ),
]


class TechniqueRegistry:
    """Registry maintaining available MITRE ATT&CK techniques."""

    def __init__(self, techniques: list[MitreTechnique] | None = None) -> None:
        self._techniques: dict[str, MitreTechnique] = {}
        initial = techniques if techniques is not None else BUILTIN_TECHNIQUES
        for tech in initial:
            self.register(tech)

    def register(self, technique: MitreTechnique) -> None:
        """Register or update an ATT&CK technique."""
        self._techniques[technique.technique_id] = technique

    def get(self, technique_id: str) -> MitreTechnique | None:
        """Retrieve technique by ID."""
        return self._techniques.get(technique_id)

    def list_all(self) -> list[MitreTechnique]:
        """List all registered techniques."""
        return list(self._techniques.values())

    def filter_by_tactic(self, tactic: MitreTactic) -> list[MitreTechnique]:
        """List techniques matching a specific MITRE tactic."""
        return [t for t in self._techniques.values() if t.tactic == tactic]

    def count(self) -> int:
        """Return total registered technique count."""
        return len(self._techniques)
