"""
JudgeAgent — independent verifier of exploit attempts.

Receives (finding, PoC, sandbox_output) — never the attacker's reasoning —
and emits a structured verdict: CONFIRMED / REFUTED / INDETERMINATE.
"""

from dataclasses import dataclass

from .ai_local import StructuredLLMClient, LLMError

_SYSTEM_PROMPT = """\
You are a verification judge for penetration test results. \
You receive a static finding, the exact proof-of-concept used, \
and the raw sandbox output.

Your job: decide whether the finding is confirmed exploitable.

Rules:
- Do NOT speculate beyond what the sandbox output shows.
- CONFIRMED requires clear evidence of exploitation (error leak, auth bypass, etc.).
- REFUTED means the PoC definitively failed (sanitized, 403, no signal).
- INDETERMINATE when evidence is ambiguous or sandbox errored.
- Output valid JSON matching the required schema exactly.
"""

_VERDICT_SCHEMA = {
    "type": "object",
    "required": ["verdict", "confidence", "reasoning"],
    "properties": {
        "verdict": {"type": "string"},      # CONFIRMED | REFUTED | INDETERMINATE
        "confidence": {"type": "number"},   # 0.0 – 1.0
        "reasoning": {"type": "string"},
        "evidence_quote": {"type": "string"},
    },
}


@dataclass
class JudgeVerdict:
    verdict: str          # CONFIRMED | REFUTED | INDETERMINATE
    confidence: float
    reasoning: str
    evidence_quote: str = ""


class JudgeAgent:
    def __init__(self, llm: StructuredLLMClient, agent_id: str = "judge_v1"):
        self.llm = llm
        self.agent_id = agent_id

    def evaluate(
        self,
        finding_summary: str,
        poc: str,
        sandbox_stdout: str,
        sandbox_stderr: str,
        sandbox_error: str | None,
    ) -> JudgeVerdict:
        """
        Evaluate sandbox output against the original finding.
        The judge sees NO attacker reasoning — only raw I/O.
        """
        user = (
            f"=== STATIC FINDING ===\n{finding_summary}\n\n"
            f"=== POC USED ===\n{poc}\n\n"
            f"=== SANDBOX STDOUT ===\n{sandbox_stdout[:4000]}\n\n"
            f"=== SANDBOX STDERR ===\n{sandbox_stderr[:1000]}\n\n"
        )
        if sandbox_error:
            user += f"=== SANDBOX ERROR ===\n{sandbox_error}\n\n"

        user += "Evaluate and return your verdict JSON."

        try:
            raw = self.llm.complete_json(_SYSTEM_PROMPT, user, _VERDICT_SCHEMA)
        except LLMError:
            return JudgeVerdict(
                verdict="INDETERMINATE",
                confidence=0.0,
                reasoning="Judge LLM call failed.",
            )

        verdict = raw.get("verdict", "INDETERMINATE").upper()
        if verdict not in ("CONFIRMED", "REFUTED", "INDETERMINATE"):
            verdict = "INDETERMINATE"

        confidence = float(raw.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        return JudgeVerdict(
            verdict=verdict,
            confidence=confidence,
            reasoning=raw.get("reasoning", ""),
            evidence_quote=raw.get("evidence_quote", ""),
        )
