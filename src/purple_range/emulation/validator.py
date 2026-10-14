"""Safety and containment validation for adversary emulation commands."""

import re

# Blocklist of high-risk destructive commands that are strictly prohibited in the range
DANGEROUS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+/(?:\s|$|\*)"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),  # fork bomb
    re.compile(r">\s*/dev/sd[a-z]"),
    re.compile(r">\s*/dev/nvme"),
    re.compile(r"\bshutdown\b"),
    re.compile(r"\breboot\b"),
    re.compile(r"\binit\s+0\b"),
)


class EmulationSafetyError(Exception):
    """Raised when an emulation command violates range safety containment rules."""


class PreFlightValidator:
    """Validates commands before execution to guarantee safety containment."""

    @classmethod
    def validate_command(cls, command: str) -> None:
        """Inspect command string for dangerous destruction patterns."""
        if not command.strip():
            raise EmulationSafetyError("Emulation command cannot be empty")

        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(command):
                msg = f"Command rejected by PreFlightValidator: unsafe pattern ({pattern.pattern})"
                raise EmulationSafetyError(msg)
