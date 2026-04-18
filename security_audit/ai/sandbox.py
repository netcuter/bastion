"""
Sandbox — isolated execution environment for PoC actions.

Current backend: subprocess with hard timeout + localhost-only network guard.
Future backend: Docker (interface is stable, swap _run_subprocess → _run_docker).
"""

import shlex
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SandboxResult:
    action: dict
    stdout: str
    stderr: str
    exit_code: int
    elapsed_seconds: float
    timed_out: bool
    error: Optional[str] = None


class NetworkScopeViolation(Exception):
    pass


class Sandbox:
    """
    Executes agent-requested actions in a restricted environment.

    Allowed action types:
      - http_get  : GET request via curl (localhost / allowlist only)
      - http_post : POST request via curl (localhost / allowlist only)
      - shell     : shell command (blocked in non-dry-run unless explicitly enabled)
    """

    def __init__(
        self,
        scope_allowlist: list[str] | None = None,
        timeout_seconds: int = 30,
        dry_run: bool = False,
        allow_shell: bool = False,
    ):
        self.scope_allowlist: list[str] = scope_allowlist or ["localhost", "127.0.0.1"]
        self.timeout = timeout_seconds
        self.dry_run = dry_run
        self.allow_shell = allow_shell

    def execute(self, action: dict) -> SandboxResult:
        """
        Execute an action dict from the attacker agent.

        Expected keys: action_type, target (URL or command), payload (optional).
        """
        start = time.monotonic()
        action_type = action.get("action_type", "").lower()

        if self.dry_run:
            return SandboxResult(
                action=action,
                stdout=f"[dry-run] would execute: {action}",
                stderr="",
                exit_code=0,
                elapsed_seconds=0.0,
                timed_out=False,
            )

        try:
            if action_type in ("http_get", "http_post"):
                return self._run_http(action, action_type, start)
            elif action_type == "shell":
                return self._run_shell(action, start)
            else:
                return SandboxResult(
                    action=action, stdout="", stderr="",
                    exit_code=1, elapsed_seconds=0.0, timed_out=False,
                    error=f"Unknown action_type: {action_type!r}",
                )
        except NetworkScopeViolation as exc:
            return SandboxResult(
                action=action, stdout="", stderr="",
                exit_code=1, elapsed_seconds=time.monotonic() - start,
                timed_out=False, error=f"Scope violation: {exc}",
            )
        except Exception as exc:
            return SandboxResult(
                action=action, stdout="", stderr="",
                exit_code=1, elapsed_seconds=time.monotonic() - start,
                timed_out=False, error=str(exc),
            )

    # ------------------------------------------------------------------

    def _check_scope(self, url: str) -> None:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if not any(allowed in host for allowed in self.scope_allowlist):
            raise NetworkScopeViolation(
                f"{host!r} not in allowlist {self.scope_allowlist}"
            )

    def _run_http(self, action: dict, method: str, start: float) -> SandboxResult:
        target = action.get("target", "")
        self._check_scope(target)

        cmd = ["curl", "-s", "-o", "-", "-w", "\n---EXIT:%{http_code}---", "--max-time", str(self.timeout)]
        if method == "http_post":
            payload = action.get("payload", "")
            cmd += ["-X", "POST", "-d", payload, "-H", "Content-Type: application/x-www-form-urlencoded"]
        cmd.append(target)

        return self._subprocess(cmd, action, start)

    def _run_shell(self, action: dict, start: float) -> SandboxResult:
        if not self.allow_shell:
            return SandboxResult(
                action=action, stdout="", stderr="",
                exit_code=1, elapsed_seconds=0.0, timed_out=False,
                error="Shell execution disabled. Enable with allow_shell=True.",
            )
        cmd = action.get("target", "")
        return self._subprocess(shlex.split(cmd), action, start)

    def _subprocess(self, cmd: list[str], action: dict, start: float) -> SandboxResult:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=self.timeout,
            )
            return SandboxResult(
                action=action,
                stdout=proc.stdout[:8192],
                stderr=proc.stderr[:2048],
                exit_code=proc.returncode,
                elapsed_seconds=time.monotonic() - start,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                action=action, stdout="", stderr="",
                exit_code=-1, elapsed_seconds=self.timeout,
                timed_out=True, error="Sandbox timeout exceeded",
            )
