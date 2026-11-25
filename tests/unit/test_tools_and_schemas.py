"""Unit tests for Tool & Interface Design (docstrings, naming, JSON schemas, guided errors, HITL)."""

from __future__ import annotations

import inspect
import re
from types import SimpleNamespace
from typing import Any

import pytest

from app.config.settings import reset_settings_cache
from app.data.synthetic_store import MUTATION_LEDGER
from app.schemas.incidents import export_all_tool_schemas
from app.tools.diagnostics_tools import (
    calculate_blast_radius_estimate,
    correlate_recent_deployments,
    fetch_service_telemetry_anomalies,
    list_verified_healthy_revisions,
    search_verified_runbooks,
)
from app.tools.memory_tools import recall_historical_incident_lessons
from app.tools.remediation_tools import (
    apply_waf_ip_rate_limit,
    canary_rollback_tool,
    execute_canary_traffic_rollback,
    requires_production_rollback_approval,
    send_war_room_incident_update,
    waf_rate_limit_tool,
)

ALL_TOOLS = [
    fetch_service_telemetry_anomalies,
    correlate_recent_deployments,
    search_verified_runbooks,
    list_verified_healthy_revisions,
    calculate_blast_radius_estimate,
    execute_canary_traffic_rollback,
    apply_waf_ip_rate_limit,
    send_war_room_incident_update,
    recall_historical_incident_lessons,
]


class _FakeToolContext:
    """Minimal stand-in for ADK ToolContext capturing state and HITL confirmations."""

    def __init__(self, *, confirmed: bool | None = None) -> None:
        self.state: dict[str, Any] = {}
        self.agent_name = "mitigation_executor"
        self.session = SimpleNamespace(id="sess-test-001")
        self.confirmation_requests: list[dict[str, Any]] = []
        self.tool_confirmation = (
            None if confirmed is None else SimpleNamespace(confirmed=confirmed)
        )

    def request_confirmation(self, *, hint: str, payload: Any = None) -> None:
        self.confirmation_requests.append({"hint": hint, "payload": payload})


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> None:
    MUTATION_LEDGER.reset()
    monkeypatch.setenv("AEGIS_ENV", "test")
    monkeypatch.setenv("AEGIS_OFFLINE_MODE", "true")
    monkeypatch.setenv("AEGIS_CHANGE_FREEZE_ACTIVE", "false")
    reset_settings_cache()


def test_all_tools_have_comprehensive_docstrings_and_specific_names() -> None:
    banned_generic = {"query", "query_db", "update", "update_ticket", "run", "execute"}
    for fn in ALL_TOOLS:
        assert fn.__name__ not in banned_generic
        assert re.fullmatch(r"[a-z]+(?:_[a-z]+){2,}", fn.__name__), (
            f"Tool name '{fn.__name__}' should be descriptive multi-word verb_noun snake_case"
        )
        doc = inspect.getdoc(fn) or ""
        assert "Args:" in doc and "Returns:" in doc, f"{fn.__name__} missing Args/Returns docstring"
        sig = inspect.signature(fn)
        for param_name in sig.parameters:
            if param_name == "tool_context":
                assert "tool_context" not in doc
            else:
                assert f"{param_name}:" in doc, (
                    f"Parameter '{param_name}' missing from {fn.__name__} docstring"
                )


def test_explicit_json_schemas_export_cleanly() -> None:
    schemas = export_all_tool_schemas()
    assert len(schemas) >= 12
    assert "CanaryRollbackRequest" in schemas
    assert "WafRateLimitRequest" in schemas
    assert "RootCauseSynthesis" in schemas
    assert "ToolErrorEnvelope" in schemas
    rollback_props = schemas["CanaryRollbackRequest"]["properties"]
    assert rollback_props["traffic_shift_pct"]["minimum"] == 1
    assert rollback_props["traffic_shift_pct"]["maximum"] == 100


def test_telemetry_tool_scrubs_pii_and_sets_state() -> None:
    ctx = _FakeToolContext()
    res = fetch_service_telemetry_anomalies(
        service_name="checkout-api",
        window_minutes=30,
        incident_id="INC-2026-1042",
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert res["status"] == "success"
    assert res["metrics"]["p99_latency_ms"] == 4820
    assert res["pii_redaction_summary"]["redactions_applied"] >= 4
    joined_logs = " ".join(res["sample_error_logs"])
    assert "alex.rivera@example.com" not in joined_logs
    assert "4111-2222-3333-4444" not in joined_logs
    assert "123-45-6789" not in joined_logs
    assert "eyJhbGciOiJIUzI1NiJ9" not in joined_logs
    assert ctx.state["active_service"] == "checkout-api"


def test_guided_error_handling_for_unknown_service_and_unhealthy_revision() -> None:
    ctx = _FakeToolContext()
    bad_svc = correlate_recent_deployments(service_name="nonexistent-svc", lookback_hours=12)
    assert bad_svc["status"] == "error"
    assert bad_svc["error_code"] == "INVALID_TOOL_ARGUMENTS"
    assert "recovery_instructions" in bad_svc
    assert "checkout-api" in bad_svc["valid_options"]

    unhealthy = execute_canary_traffic_rollback(
        service_name="checkout-api",
        target_revision="checkout-api-v2.3.9",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="Testing guided recovery on schema-incompatible revision.",
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert unhealthy["status"] == "error"
    assert unhealthy["error_code"] == "UNHEALTHY_TARGET_REVISION"
    assert unhealthy["suggested_next_tool"] == "list_verified_healthy_revisions"
    assert "checkout-api-v2.4.0" in unhealthy["valid_options"]

    # Recovery path succeeds in listing valid healthy candidates
    healthy_list = list_verified_healthy_revisions("checkout-api")
    assert healthy_list["status"] == "success"
    assert healthy_list["healthy_rollback_candidates"][0]["revision"] == "checkout-api-v2.4.0"


def test_guided_error_handling_for_broad_waf_cidr_and_change_freeze(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _FakeToolContext(confirmed=True)
    broad_cidr = apply_waf_ip_rate_limit(
        service_name="auth-gateway",
        source_cidr="10.0.0.0/8",
        requests_per_minute=60,
        duration_minutes=60,
        incident_id="INC-2026-1043",
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert broad_cidr["status"] == "error"
    assert broad_cidr["error_code"] == "INVALID_WAF_POLICY_PARAMETERS"
    assert "recovery_instructions" in broad_cidr

    monkeypatch.setenv("AEGIS_CHANGE_FREEZE_ACTIVE", "true")
    reset_settings_cache()
    frozen = execute_canary_traffic_rollback(
        service_name="checkout-api",
        target_revision="checkout-api-v2.4.0",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="Attempting P1 rollback while change freeze is active.",
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert frozen["status"] == "error"
    assert frozen["error_code"] == "CHANGE_FREEZE_BLOCK"
    assert frozen["suggested_next_tool"] == "send_war_room_incident_update"


def test_hitl_confirmation_predicates_and_pause_approve_deny_flow() -> None:
    assert canary_rollback_tool._require_confirmation is requires_production_rollback_approval
    assert waf_rate_limit_tool._require_confirmation is True

    # P1 or >10% or Tier-0 requires approval
    assert requires_production_rollback_approval(
        service_name="checkout-api",
        target_revision="checkout-api-v2.4.0",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="P1 rollback",
    )
    # Tier-1 P2 <=10% shift does NOT require confirmation
    assert not requires_production_rollback_approval(
        service_name="catalog-search",
        target_revision="catalog-search-v1.8.1",
        traffic_shift_pct=5,
        severity="P2",
        incident_id="INC-2026-1044",
        justification="Low-risk 5% canary revert",
    )

    # 1. Unconfirmed P1 rollback pauses and requests HITL confirmation
    pause_ctx = _FakeToolContext(confirmed=None)
    paused = execute_canary_traffic_rollback(
        service_name="checkout-api",
        target_revision="checkout-api-v2.4.0",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="RB-CHK-001 rollback after sync lock contention verified.",
        tool_context=pause_ctx,  # type: ignore[arg-type]
    )
    assert paused["status"] == "awaiting_human_approval"
    assert len(pause_ctx.confirmation_requests) == 1
    assert len(MUTATION_LEDGER.applied_rollbacks) == 0

    # 2. Denied rollback aborts safely
    deny_ctx = _FakeToolContext(confirmed=False)
    denied = execute_canary_traffic_rollback(
        service_name="checkout-api",
        target_revision="checkout-api-v2.4.0",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="RB-CHK-001 rollback after sync lock contention verified.",
        tool_context=deny_ctx,  # type: ignore[arg-type]
    )
    assert denied["status"] == "rejected_by_human"
    assert len(MUTATION_LEDGER.applied_rollbacks) == 0

    # 3. Approved rollback executes and records receipt
    approve_ctx = _FakeToolContext(confirmed=True)
    approved = execute_canary_traffic_rollback(
        service_name="checkout-api",
        target_revision="checkout-api-v2.4.0",
        traffic_shift_pct=25,
        severity="P1",
        incident_id="INC-2026-1042",
        justification="RB-CHK-001 rollback after sync lock contention verified.",
        tool_context=approve_ctx,  # type: ignore[arg-type]
    )
    assert approved["status"] == "success"
    assert approved["human_approved"] is True
    assert len(MUTATION_LEDGER.applied_rollbacks) == 1


def test_blast_radius_runbooks_and_war_room_update() -> None:
    ctx = _FakeToolContext()
    br = calculate_blast_radius_estimate(
        service_name="checkout-api",
        action_type="canary_rollback",
        traffic_shift_pct=25,
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert br["status"] == "success"
    assert br["requires_human_approval"] is True
    assert br["estimated_affected_rps"] == 362

    rb = search_verified_runbooks(
        query="SyncPaymentLockTimeout DB pool exhausted",
        service_name="checkout-api",
        top_k=2,
    )
    assert rb["status"] == "success"
    assert rb["runbooks"][0]["runbook_id"] == "RB-CHK-001"

    update = send_war_room_incident_update(
        incident_id="INC-2026-1042",
        channel="#sre-war-room",
        severity="P1",
        summary="Checkout rollback ready; reported by alex.rivera@example.com on 555-867-5309.",
        tool_context=ctx,  # type: ignore[arg-type]
    )
    assert update["status"] == "success"
    assert "alex.rivera@example.com" not in update["scrubbed_summary"]
    assert "555-867-5309" not in update["scrubbed_summary"]
    assert update["pii_redactions_applied"] >= 2
