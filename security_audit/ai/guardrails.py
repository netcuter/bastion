"""
Agent Guardrails Layer

Every autonomous action taken by Bastion's AI agents (exploit agent, DAST
runner, LLM red-team) must pass through GuardrailsEngine before execution.
This implements the human-in-the-loop safety story Terra Security markets.

Risk tiers (ascending danger):
  READ_ONLY      — static analysis, file reads              → auto-approved
  NETWORK_SAFE   — GET requests, OSV API, EPSS lookups      → auto-approved
  NETWORK_WRITE  — POST/PUT, form submission, fuzzing       → HITL approval
  SYSTEM         — subprocess, filesystem writes            → HITL approval
  EXPLOIT        — sends malicious payloads                 → HITL + dry-run
"""

import fcntl
import fnmatch
import hashlib
import json
import select
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional


class ActionRisk(Enum):
    READ_ONLY = "read_only"
    NETWORK_SAFE = "network_safe"
    NETWORK_WRITE = "network_write"
    SYSTEM = "system"
    EXPLOIT = "exploit"


_RISK_ORDER = [
    ActionRisk.READ_ONLY,
    ActionRisk.NETWORK_SAFE,
    ActionRisk.NETWORK_WRITE,
    ActionRisk.SYSTEM,
    ActionRisk.EXPLOIT,
]


@dataclass
class ActionRequest:
    action_type: str            # "http_get" | "http_post" | "subprocess" | "file_write" | …
    risk: ActionRisk
    target: str                 # URL, path, or command
    payload: Optional[str]      # body / args being sent
    rationale: str              # why the agent wants to do this
    agent_id: str               # e.g. "exploit_agent_v1"
    finding_id: Optional[str]   # links back to the triggering static finding
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d

    def fingerprint(self) -> str:
        raw = f"{self.action_type}|{self.target}|{self.payload or ''}|{self.agent_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class GuardrailsPolicy:
    scope_allowlist: List[str] = field(default_factory=list)
    scope_denylist: List[str] = field(default_factory=list)
    rate_limit_per_minute: int = 30
    rate_limit_per_target: int = 5
    dry_run: bool = True
    require_hitl_above: ActionRisk = ActionRisk.NETWORK_SAFE
    max_actions_per_session: int = 100

    @classmethod
    def from_file(cls, path: Path) -> "GuardrailsPolicy":
        with open(path) as f:
            data = json.load(f)
        data["require_hitl_above"] = ActionRisk(
            data.get("require_hitl_above", "network_safe")
        )
        return cls(**data)

    @classmethod
    def from_dict(cls, data: dict) -> "GuardrailsPolicy":
        d = dict(data)
        if "require_hitl_above" in d and isinstance(d["require_hitl_above"], str):
            d["require_hitl_above"] = ActionRisk(d["require_hitl_above"])
        return cls(**d)


@dataclass
class GuardrailsDecision:
    approved: bool
    reason: str
    dry_run: bool = False       # caller MUST simulate if True, not execute


class GuardrailsEngine:
    """
    Central safety gate.  All agent actions must call .check() first.
    """

    HITL_TIMEOUT_SECONDS = 30

    def __init__(
        self,
        policy: GuardrailsPolicy,
        ledger_path: Path,
        *,
        hitl_callback: Optional[Callable[[ActionRequest], bool]] = None,
    ):
        self.policy = policy
        self.ledger_path = ledger_path
        self._hitl_callback = hitl_callback  # override for tests / GUI
        self._action_count = 0
        self._timestamps: List[float] = []          # global rate-limit window
        self._target_counts: Dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, request: ActionRequest) -> GuardrailsDecision:
        # 1. Global session cap
        if self._action_count >= self.policy.max_actions_per_session:
            return GuardrailsDecision(
                approved=False,
                reason=f"Session action cap reached ({self.policy.max_actions_per_session})",
            )

        # 2. Scope check
        if not self._check_scope(request.target):
            return GuardrailsDecision(
                approved=False,
                reason=f"Target out of scope: {request.target}",
            )

        # 3. Rate-limit check
        if not self._check_rate_limit(request.target):
            return GuardrailsDecision(
                approved=False,
                reason=f"Rate limit exceeded for {request.target}",
            )

        # 4. Risk tier routing
        if self._risk_index(request.risk) <= self._risk_index(self.policy.require_hitl_above):
            # Auto-approve
            self._action_count += 1
            return GuardrailsDecision(
                approved=True,
                reason="Auto-approved (within safe risk tier)",
                dry_run=self.policy.dry_run and request.risk == ActionRisk.EXPLOIT,
            )

        # 5. HITL required
        approved = self._prompt_human(request)
        self._action_count += 1
        dry_run = self.policy.dry_run and request.risk == ActionRisk.EXPLOIT

        return GuardrailsDecision(
            approved=approved,
            reason="Human approved" if approved else "Human denied / timeout",
            dry_run=dry_run,
        )

    def record(
        self,
        request: ActionRequest,
        outcome: str,           # "approved" | "denied" | "dry_run" | "error"
        result: Optional[dict] = None,
    ) -> None:
        entry = {
            **request.to_dict(),
            "fingerprint": request.fingerprint(),
            "outcome": outcome,
            "result": result or {},
        }
        # Append-only with advisory file lock
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(json.dumps(entry) + "\n")
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_scope(self, target: str) -> bool:
        for pattern in self.policy.scope_denylist:
            if fnmatch.fnmatch(target, pattern):
                return False
        if not self.policy.scope_allowlist:
            return True
        return any(fnmatch.fnmatch(target, p) for p in self.policy.scope_allowlist)

    def _check_rate_limit(self, target: str) -> bool:
        now = time.time()
        # Prune timestamps older than 60s
        self._timestamps = [t for t in self._timestamps if now - t < 60]

        if len(self._timestamps) >= self.policy.rate_limit_per_minute:
            return False
        if self._target_counts[target] >= self.policy.rate_limit_per_target:
            return False

        self._timestamps.append(now)
        self._target_counts[target] += 1
        return True

    def _prompt_human(self, request: ActionRequest) -> bool:
        if self._hitl_callback is not None:
            return self._hitl_callback(request)

        print(
            f"\n[GUARDRAILS] Action requires approval\n"
            f"  Agent:   {request.agent_id}\n"
            f"  Type:    {request.action_type} ({request.risk.value})\n"
            f"  Target:  {request.target}\n"
            f"  Payload: {(request.payload or '')[:120]}\n"
            f"  Reason:  {request.rationale}\n"
            f"Approve? [y/N] (auto-deny in {self.HITL_TIMEOUT_SECONDS}s): ",
            end="",
            flush=True,
        )

        ready, _, _ = select.select([sys.stdin], [], [], self.HITL_TIMEOUT_SECONDS)
        if not ready:
            print("\n[GUARDRAILS] Timeout — action denied.")
            return False

        answer = sys.stdin.readline().strip().lower()
        approved = answer in ("y", "yes")
        print(f"[GUARDRAILS] {'Approved' if approved else 'Denied'}.")
        return approved

    @staticmethod
    def _risk_index(risk: ActionRisk) -> int:
        return _RISK_ORDER.index(risk)


# ---------------------------------------------------------------------------
# Convenience decorator
# ---------------------------------------------------------------------------

def guarded(risk: ActionRisk, action_type: str = "decorated_call"):
    """
    Wraps a function so every call is gated by a GuardrailsEngine.

    The decorated function's first argument must be a GuardrailsEngine
    instance, or it must be passed as ``guardrails=`` keyword argument.

    Example::

        @guarded(ActionRisk.EXPLOIT, action_type="http_post")
        def send_payload(guardrails: GuardrailsEngine, target: str, payload: str):
            ...
    """

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Extract guardrails from args[0] or kwarg
            engine: Optional[GuardrailsEngine] = kwargs.pop("guardrails", None)
            if engine is None and args and isinstance(args[0], GuardrailsEngine):
                engine, args = args[0], args[1:]

            target = kwargs.get("target", str(args[0]) if args else "unknown")
            payload = kwargs.get("payload", None)

            req = ActionRequest(
                action_type=action_type,
                risk=risk,
                target=target,
                payload=str(payload) if payload else None,
                rationale=f"Decorated call to {fn.__name__}",
                agent_id="guardrails_decorator",
                finding_id=None,
            )

            if engine is None:
                raise ValueError(
                    "GuardrailsEngine must be passed as first arg or `guardrails=` kwarg"
                )

            decision = engine.check(req)
            engine.record(req, "approved" if decision.approved else "denied")

            if not decision.approved:
                raise PermissionError(f"[GUARDRAILS] {decision.reason}")
            if decision.dry_run:
                return {"dry_run": True, "would_call": fn.__name__, "args": args, "kwargs": kwargs}

            return fn(*args, **kwargs)

        wrapper.__wrapped__ = fn
        return wrapper

    return decorator
