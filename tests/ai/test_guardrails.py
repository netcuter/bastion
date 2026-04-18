"""
Tests for security_audit/ai/guardrails.py

Covers:
  1. Scope allowlist/denylist matching
  2. Rate-limit enforcement
  3. HITL prompt (mocked) — approve and deny paths
  4. Action ledger JSONL format
  5. Dry-run flag on EXPLOIT tier
  6. Session cap
  7. @guarded decorator
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from security_audit.ai.guardrails import (
    ActionRequest,
    ActionRisk,
    GuardrailsDecision,
    GuardrailsEngine,
    GuardrailsPolicy,
    guarded,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_ledger(tmp_path):
    return tmp_path / "ledger.jsonl"


def make_engine(
    *,
    allowlist=None,
    denylist=None,
    rate_per_min=30,
    rate_per_target=5,
    dry_run=False,
    hitl_above=ActionRisk.NETWORK_SAFE,
    max_actions=100,
    hitl_callback=None,
    tmp_path=None,
):
    if tmp_path is None:
        tmp_path = Path(tempfile.mkdtemp()) / "ledger.jsonl"
    policy = GuardrailsPolicy(
        scope_allowlist=allowlist or [],
        scope_denylist=denylist or [],
        rate_limit_per_minute=rate_per_min,
        rate_limit_per_target=rate_per_target,
        dry_run=dry_run,
        require_hitl_above=hitl_above,
        max_actions_per_session=max_actions,
    )
    return GuardrailsEngine(policy, tmp_path, hitl_callback=hitl_callback)


def make_request(**kwargs):
    defaults = dict(
        action_type="http_get",
        risk=ActionRisk.NETWORK_SAFE,
        target="http://localhost:5000/test",
        payload=None,
        rationale="unit test",
        agent_id="test_agent",
        finding_id=None,
    )
    defaults.update(kwargs)
    return ActionRequest(**defaults)


# ---------------------------------------------------------------------------
# 1. Scope allowlist / denylist
# ---------------------------------------------------------------------------

class TestScope:
    def test_no_allowlist_permits_anything(self):
        engine = make_engine(denylist=[])
        req = make_request(target="http://anything.example.com/")
        dec = engine.check(req)
        assert dec.approved

    def test_allowlist_blocks_out_of_scope(self):
        engine = make_engine(allowlist=["http://localhost:*"])
        req = make_request(target="http://prod.corp.com/login")
        dec = engine.check(req)
        assert not dec.approved
        assert "scope" in dec.reason.lower()

    def test_allowlist_permits_matching_target(self):
        engine = make_engine(allowlist=["http://localhost:*"])
        req = make_request(target="http://localhost:5000/api/users")
        dec = engine.check(req)
        assert dec.approved

    def test_denylist_blocks_even_if_allowlist_matches(self):
        engine = make_engine(
            allowlist=["*.example.com"],
            denylist=["prod.example.com"],
        )
        req = make_request(target="prod.example.com")
        dec = engine.check(req)
        assert not dec.approved


# ---------------------------------------------------------------------------
# 2. Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_per_minute_global_cap(self):
        engine = make_engine(rate_per_min=3, rate_per_target=999)
        for _ in range(3):
            dec = engine.check(make_request(target="http://localhost/"))
            assert dec.approved
        dec = engine.check(make_request(target="http://localhost/"))
        assert not dec.approved
        assert "rate" in dec.reason.lower()

    def test_per_target_cap(self):
        engine = make_engine(rate_per_min=999, rate_per_target=2)
        target = "http://localhost/vuln"
        for _ in range(2):
            dec = engine.check(make_request(target=target))
            assert dec.approved
        dec = engine.check(make_request(target=target))
        assert not dec.approved

    def test_different_targets_counted_separately(self):
        engine = make_engine(rate_per_min=999, rate_per_target=1)
        assert engine.check(make_request(target="http://localhost/a")).approved
        assert engine.check(make_request(target="http://localhost/b")).approved


# ---------------------------------------------------------------------------
# 3. HITL approval (mocked callback)
# ---------------------------------------------------------------------------

class TestHITL:
    def test_exploit_tier_requires_hitl(self):
        approved_calls = []

        def callback(req):
            approved_calls.append(req)
            return True

        engine = make_engine(
            hitl_above=ActionRisk.NETWORK_SAFE,
            hitl_callback=callback,
            dry_run=False,
        )
        req = make_request(risk=ActionRisk.EXPLOIT, action_type="http_post")
        dec = engine.check(req)
        assert dec.approved
        assert len(approved_calls) == 1

    def test_exploit_tier_denied_by_human(self):
        engine = make_engine(
            hitl_above=ActionRisk.NETWORK_SAFE,
            hitl_callback=lambda _: False,
            dry_run=False,
        )
        req = make_request(risk=ActionRisk.EXPLOIT, action_type="http_post")
        dec = engine.check(req)
        assert not dec.approved

    def test_safe_tier_auto_approved_without_hitl(self):
        called = []
        engine = make_engine(hitl_callback=lambda r: called.append(r) or True)
        req = make_request(risk=ActionRisk.NETWORK_SAFE)
        dec = engine.check(req)
        assert dec.approved
        assert len(called) == 0  # HITL not triggered


# ---------------------------------------------------------------------------
# 4. Action ledger
# ---------------------------------------------------------------------------

class TestLedger:
    def test_record_creates_valid_jsonl(self, tmp_ledger):
        engine = make_engine(tmp_path=tmp_ledger)
        req = make_request()
        engine.record(req, "approved", {"status": 200})
        lines = tmp_ledger.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["outcome"] == "approved"
        assert entry["result"]["status"] == 200
        assert "fingerprint" in entry
        assert "timestamp" in entry

    def test_record_appends_multiple_entries(self, tmp_ledger):
        engine = make_engine(tmp_path=tmp_ledger)
        for i in range(3):
            engine.record(make_request(target=f"http://localhost/{i}"), "approved")
        lines = tmp_ledger.read_text().strip().split("\n")
        assert len(lines) == 3


# ---------------------------------------------------------------------------
# 5. Dry-run flag
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_exploit_with_dry_run_sets_flag(self):
        engine = make_engine(
            dry_run=True,
            hitl_callback=lambda _: True,
        )
        req = make_request(risk=ActionRisk.EXPLOIT, action_type="exploit_payload")
        dec = engine.check(req)
        assert dec.approved
        assert dec.dry_run is True

    def test_safe_action_dry_run_flag_false(self):
        engine = make_engine(dry_run=True)
        req = make_request(risk=ActionRisk.NETWORK_SAFE)
        dec = engine.check(req)
        assert dec.approved
        assert dec.dry_run is False


# ---------------------------------------------------------------------------
# 6. Session cap
# ---------------------------------------------------------------------------

class TestSessionCap:
    def test_session_cap_blocks_after_limit(self):
        engine = make_engine(max_actions=2)
        assert engine.check(make_request()).approved
        assert engine.check(make_request()).approved
        dec = engine.check(make_request())
        assert not dec.approved
        assert "cap" in dec.reason.lower()


# ---------------------------------------------------------------------------
# 7. @guarded decorator
# ---------------------------------------------------------------------------

class TestGuardedDecorator:
    def test_decorator_passes_approved_action(self):
        engine = make_engine()

        @guarded(ActionRisk.NETWORK_SAFE, action_type="http_get")
        def fetch(target: str, payload=None):
            return {"fetched": target}

        result = fetch(guardrails=engine, target="http://localhost/api", payload=None)
        assert result["fetched"] == "http://localhost/api"

    def test_decorator_raises_on_denied(self):
        engine = make_engine(hitl_callback=lambda _: False)

        @guarded(ActionRisk.EXPLOIT, action_type="send_payload")
        def attack(target: str):
            return "executed"

        with pytest.raises(PermissionError):
            attack(guardrails=engine, target="http://localhost/")

    def test_decorator_returns_dry_run_dict(self):
        engine = make_engine(dry_run=True, hitl_callback=lambda _: True)

        @guarded(ActionRisk.EXPLOIT, action_type="exploit")
        def send_exploit(target: str):
            return "real execution"

        result = send_exploit(guardrails=engine, target="http://localhost/")
        assert result.get("dry_run") is True
        assert "would_call" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
