"""
ExploitValidator — orchestrates the attacker → sandbox → judge loop.

Pipeline:
  Static Finding
    → reachability filter (caller's responsibility)
    → AttackerAgent.plan()      [guardrail-gated]
    → Sandbox.execute()
    → JudgeAgent.evaluate()
    → ValidationVerdict
"""

import time
from dataclasses import dataclass, field
from typing import Optional

from ..core.scanner import Finding
from .exploit_agent import AttackerAgent, AttackPlan
from .guardrails import GuardrailsEngine
from .judge_agent import JudgeAgent
from .sandbox import Sandbox, SandboxResult


@dataclass
class ValidationVerdict:
    finding_id: str
    status: str                       # CONFIRMED | REFUTED | INDETERMINATE
    confidence: float                 # 0-1
    poc: Optional[str]                # payload used
    evidence: list[dict] = field(default_factory=list)   # HTTP req/res pairs, stdout
    trace: list[dict] = field(default_factory=list)      # agent turn log
    runtime_seconds: float = 0.0
    cost_tokens: int = 0              # placeholder (local LLMs don't report tokens)


class ExploitValidator:
    """
    Runs the two-agent attacker/judge loop for each finding.

    max_turns: attacker re-plans if first attempt is INDETERMINATE.
    """

    def __init__(
        self,
        attacker: AttackerAgent,
        judge: JudgeAgent,
        sandbox: Sandbox,
        guardrails: GuardrailsEngine,
        max_turns: int = 5,
        max_runtime_seconds: int = 120,
    ):
        self.attacker = attacker
        self.judge = judge
        self.sandbox = sandbox
        self.guardrails = guardrails
        self.max_turns = max_turns
        self.max_runtime_seconds = max_runtime_seconds

    def validate(self, finding: Finding, target_url: str = "") -> ValidationVerdict:
        fid = getattr(finding, "id", f"{finding.file_path}:{finding.line_number}")
        finding_summary = (
            f"Type: {finding.scanner}\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"File: {finding.file_path}:{finding.line_number}\n"
            f"Code: {finding.code_snippet}"
        )

        trace: list[dict] = []
        evidence: list[dict] = []
        start = time.monotonic()
        last_status = "INDETERMINATE"
        last_confidence = 0.0
        last_poc: Optional[str] = None

        for turn in range(self.max_turns):
            elapsed = time.monotonic() - start
            if elapsed >= self.max_runtime_seconds:
                trace.append({"turn": turn, "event": "budget_exhausted", "elapsed": elapsed})
                break

            # --- Attacker plans ---
            plan: Optional[AttackPlan] = self.attacker.plan(finding_summary, target_url)
            if plan is None:
                trace.append({"turn": turn, "event": "attacker_blocked_or_failed"})
                last_status = "INDETERMINATE"
                break

            trace.append({
                "turn": turn,
                "event": "attacker_plan",
                "action_type": plan.action_type,
                "target": plan.target,
                "payload": plan.payload,
            })

            # --- Sandbox executes ---
            result: SandboxResult = self.sandbox.execute({
                "action_type": plan.action_type,
                "target": plan.target,
                "payload": plan.payload,
            })

            evidence.append({
                "turn": turn,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "error": result.error,
            })
            trace.append({
                "turn": turn,
                "event": "sandbox_result",
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
            })

            # Record action in ledger
            self.guardrails.record(
                request={"agent_id": self.attacker.agent_id, "action": plan.action_type},
                outcome="executed",
                result={"exit_code": result.exit_code},
            )

            # --- Judge evaluates ---
            verdict = self.judge.evaluate(
                finding_summary=finding_summary,
                poc=f"{plan.action_type} {plan.target} payload={plan.payload}",
                sandbox_stdout=result.stdout,
                sandbox_stderr=result.stderr,
                sandbox_error=result.error,
            )

            last_poc = f"{plan.action_type} {plan.target} payload={plan.payload}"
            last_status = verdict.verdict
            last_confidence = verdict.confidence

            trace.append({
                "turn": turn,
                "event": "judge_verdict",
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "reasoning": verdict.reasoning,
            })

            if verdict.verdict in ("CONFIRMED", "REFUTED"):
                break  # decisive result — stop looping

        return ValidationVerdict(
            finding_id=fid,
            status=last_status,
            confidence=last_confidence,
            poc=last_poc,
            evidence=evidence,
            trace=trace,
            runtime_seconds=time.monotonic() - start,
        )

    def validate_batch(
        self, findings: list[Finding], target_url: str = ""
    ) -> list[ValidationVerdict]:
        return [self.validate(f, target_url) for f in findings]
