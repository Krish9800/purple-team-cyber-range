"""Adversary Emulation Engine executing safe atomic MITRE ATT&CK technique tests."""

import asyncio
import contextlib
import os
import signal
import subprocess  # nosec B404: Subprocess required for atomic adversary emulation
import time
from datetime import UTC, datetime

from purple_range.emulation.validator import EmulationSafetyError, PreFlightValidator
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import EmulationStatus
from purple_range.models.technique import MitreTechnique


class AdversaryEmulationEngine:
    """Executes atomic adversary emulation steps with containment and telemetry capture."""

    def __init__(self, default_timeout_seconds: int = 30) -> None:
        self.default_timeout_seconds = default_timeout_seconds

    def render_command(
        self, technique: MitreTechnique, custom_params: dict[str, str] | None = None
    ) -> str:
        """Render command template by merging default and custom parameters."""
        params = dict(technique.parameters)
        if custom_params:
            params.update(custom_params)

        command = technique.command_template
        for key, val in params.items():
            command = command.replace(f"{{{key}}}", val)
        return command

    async def async_execute_technique(
        self,
        technique: MitreTechnique,
        campaign_id: str,
        target_host: str = "localhost",
        timeout_seconds: int | None = None,
        custom_params: dict[str, str] | None = None,
    ) -> EmulationStep:
        """Asynchronously execute an adversary technique and capture execution telemetry."""
        timeout = timeout_seconds or self.default_timeout_seconds
        command = self.render_command(technique, custom_params)

        try:
            PreFlightValidator.validate_command(command)
        except EmulationSafetyError as err:
            return EmulationStep(
                campaign_id=campaign_id,
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic=technique.tactic,
                target_host=target_host,
                command_executed=command,
                status=EmulationStatus.FAILED,
                exit_code=126,
                error_message=f"Preflight validation failed: {err}",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )

        started_at = datetime.now(UTC)
        start_clock = time.perf_counter()

        try:
            # Execute command inside bash shell to evaluate pipes safely in cyber range sandbox
            proc = await asyncio.create_subprocess_shell(  # nosec B602: Safe controlled execution
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
                exit_code = proc.returncode if proc.returncode is not None else 0
                status = EmulationStatus.COMPLETED
                error_msg: str | None = None
            except TimeoutError:
                if proc.pid:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        proc.kill()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                stdout_bytes, stderr_bytes = b"", b"Execution timed out"
                exit_code = 124
                status = EmulationStatus.TIMED_OUT
                error_msg = f"Technique execution timed out after {timeout}s"

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            process_pid = proc.pid

        except Exception as exc:
            stdout_str = ""
            stderr_str = str(exc)
            exit_code = 1
            status = EmulationStatus.FAILED
            process_pid = None
            error_msg = str(exc)

        elapsed_ms = (time.perf_counter() - start_clock) * 1000.0
        completed_at = datetime.now(UTC)

        # Trigger cleanup if defined
        cleanup_done = False
        if technique.cleanup_command:
            cleanup_done = await self._async_cleanup(technique.cleanup_command)

        return EmulationStep(
            campaign_id=campaign_id,
            technique_id=technique.technique_id,
            technique_name=technique.name,
            tactic=technique.tactic,
            target_host=target_host,
            command_executed=command,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            status=status,
            process_pid=process_pid,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=round(elapsed_ms, 2),
            cleanup_executed=cleanup_done,
            error_message=error_msg,
        )

    def execute_technique(
        self,
        technique: MitreTechnique,
        campaign_id: str,
        target_host: str = "localhost",
        timeout_seconds: int | None = None,
        custom_params: dict[str, str] | None = None,
    ) -> EmulationStep:
        """Synchronously execute an adversary technique."""
        return asyncio.run(
            self.async_execute_technique(
                technique=technique,
                campaign_id=campaign_id,
                target_host=target_host,
                timeout_seconds=timeout_seconds,
                custom_params=custom_params,
            )
        )

    async def _async_cleanup(self, cleanup_command: str) -> bool:
        """Run technique cleanup command to revert system modifications."""
        try:
            PreFlightValidator.validate_command(cleanup_command)
            proc = await asyncio.create_subprocess_shell(  # nosec B602: Controlled cleanup execution
                cleanup_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10.0)
            return proc.returncode == 0
        except Exception:
            return False
