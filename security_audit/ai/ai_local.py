"""
StructuredLLMClient — OpenAI-compatible local LLM client (LM Studio, Ollama).

Replaces the old LocalAIAssistant heuristic ("contains 'true'") with
proper JSON schema validation and retry logic.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Optional


class LLMError(Exception):
    pass


class StructuredLLMClient:
    """
    Client for any OpenAI-compatible local inference server.
    Supports structured JSON output with schema validation and retries.
    """

    def __init__(self, server_url: str = "http://localhost:1234", model: str = "auto"):
        self.server_url = server_url.rstrip("/")
        self.model = model
        self._resolved_model: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete_json(
        self,
        system: str,
        user: str,
        schema: dict,
        max_retries: int = 3,
    ) -> dict:
        """
        Call the LLM and return a dict validated against *schema*.
        Retries up to max_retries times on parse/validation failure.
        Raises LLMError if all attempts fail.
        """
        import re

        hint = (
            f"\n\nYou MUST respond with a single JSON object matching this schema:\n"
            f"{json.dumps(schema, indent=2)}\n"
            "No prose, no markdown fences — raw JSON only."
        )
        augmented_user = user + hint

        last_exc: Exception = LLMError("no attempts made")
        for attempt in range(max_retries):
            try:
                raw = self._call(system, augmented_user)
                # Strip markdown fences if present
                raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
                data = json.loads(raw)
                self._validate(data, schema)
                return data
            except Exception as exc:
                last_exc = exc
                augmented_user = (
                    user
                    + hint
                    + f"\n\nPrevious attempt failed: {exc}. Try again."
                )
        raise LLMError(f"complete_json failed after {max_retries} attempts: {last_exc}")

    def complete_text(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Plain text completion, no JSON parsing."""
        return self._call(system, user, max_tokens=max_tokens)

    def test_connection(self) -> bool:
        try:
            self._get_model()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call(self, system: str, user: str, max_tokens: int = 1024) -> str:
        model = self._get_model()
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,
        }).encode()

        req = urllib.request.Request(
            f"{self.server_url}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
            return result["choices"][0]["message"]["content"]
        except urllib.error.URLError as exc:
            raise LLMError(f"Network error: {exc}") from exc
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {exc}") from exc

    def _get_model(self) -> str:
        if self._resolved_model:
            return self._resolved_model
        if self.model != "auto":
            self._resolved_model = self.model
            return self._resolved_model
        try:
            req = urllib.request.Request(f"{self.server_url}/v1/models")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            self._resolved_model = data["data"][0]["id"]
        except Exception:
            self._resolved_model = "local-model"
        return self._resolved_model

    def _validate(self, data: Any, schema: dict) -> None:
        """Minimal schema validation (required keys + type checks)."""
        if not isinstance(data, dict):
            raise ValueError("Response is not a JSON object")
        for key in schema.get("required", []):
            if key not in data:
                raise ValueError(f"Missing required key: {key!r}")
        props = schema.get("properties", {})
        for key, val in data.items():
            if key in props:
                expected_type = props[key].get("type")
                if expected_type == "string" and not isinstance(val, str):
                    raise ValueError(f"Key {key!r} must be a string")
                elif expected_type == "number" and not isinstance(val, (int, float)):
                    raise ValueError(f"Key {key!r} must be a number")
                elif expected_type == "array" and not isinstance(val, list):
                    raise ValueError(f"Key {key!r} must be an array")


# ---------------------------------------------------------------------------
# Backward-compat shim — old code imported LocalAIAssistant
# ---------------------------------------------------------------------------

class LocalAIAssistant(StructuredLLMClient):
    """Deprecated — use StructuredLLMClient directly."""

    _VERIFY_SCHEMA = {
        "type": "object",
        "required": ["verdict", "reason"],
        "properties": {
            "verdict": {"type": "string"},
            "reason": {"type": "string"},
        },
    }

    def verify_finding(self, finding: dict) -> bool:
        system = "You are a security expert specialising in vulnerability analysis."
        user = (
            f"Finding type: {finding.get('type')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Code:\n```\n{finding.get('code')}\n```\n"
            f"Description: {finding.get('description')}\n\n"
            "Is this a real vulnerability or a false positive? "
            'Respond with {"verdict": "TRUE" or "FALSE", "reason": "..."}'
        )
        try:
            result = self.complete_json(system, user, self._VERIFY_SCHEMA)
            return result.get("verdict", "FALSE").upper() == "TRUE"
        except LLMError:
            return True  # fail-safe: treat as real
