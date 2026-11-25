"""High-stakes SRE remediation tools with explicit HITL hooks and guided error recovery."""

from __future__ import annotations

import datetime
from typing import Any

from google.adk.tools import FunctionTool, ToolContext
from pydantic import ValidationError

from app.config.secrets import SecretResolutionError, get_secret_provider
from app.config.settings import get_settings
from app.data.synthetic_store import MUTATION_LEDGER, SERVICES_CATALOG
from app.observability.logging_setup import get_logger
from app.observability.tracing import get_tracer
from app.schemas.incidents import (
    VALID_SERVICES,
    CanaryRollbackRequest,
    ToolErrorEnvelope,
    WafRateLimitRequest,
    WarRoomUpdateRequest,
)
from app.security.pii_redactor import get_pii_redactor

logger = get_logger("remediation_tools")
tracer = get_tracer("aegis_ops.tools.remediation")


def requires_production_rollback_approval(
    service_name: str,
    target_revision: str,
    traffic_shift_pct: int,
    severity: str,
    incident_id: str,
    justification: str,
    **kwargs: Any,
) -> bool:
    """Conditional HITL predicate gating high-stakes production canary rollbacks.

    Returns True (forcing ADK pause & explicit human confirmation) whenever:
    - Incident severity is P0 or P1, OR
    - Proposed traffic shift exceeds 10% of live traffic, OR
    - Target service is a Tier-0 revenue/security/finance service.
    """
    service = SERVICES_CATALOG.get(service_name, {})
    is_tier_zero = str(service.get("tier", "")).startswith("tier-0")
    return severity in {"P0", "P1"} or traffic_shift_pct > 10 or is_tier_zero


def execute_canary_traffic_rollback(
    service_name: str,
    target_revision: str,
    traffic_shift_pct: int,
    severity: str,
    incident_id: str,
    justification: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Execute a canary traffic shift to roll back a degraded service to a verified healthy revision.

    High-stakes production mutation guarded by:
    1. Strict Pydantic validation (service slug, semver revision pattern, 1-100% bounds).
    2. Verified revision health check (rejects unhealthy/schema-incompatible revisions
       with guided recovery instructions pointing to `list_verified_healthy_revisions`).
    3. Change-freeze enforcement (blocks non-P0 mutations during active freeze).
    4. Conditional ADK Human-in-the-Loop confirmation (`require_confirmation` +
       explicit operator approval pause).

    Args:
        service_name: Target production microservice (`checkout-api`,
            `auth-gateway`, `catalog-search`, or `payments-ledger`).
        target_revision: Verified healthy revision formatted as `<service>-vX.Y.Z`
            (e.g., `checkout-api-v2.4.0`).
        traffic_shift_pct: Percentage of live traffic to shift (integer 1 to 100).
        severity: Active incident severity (`P0`, `P1`, `P2`, or `P3`).
        incident_id: Incident ticket ID formatted as `INC-YYYY-NNNN`.
        justification: Grounded technical justification (10 to 500 characters)
            citing telemetry and runbook IDs.

    Returns:
        A JSON-serializable dictionary describing the executed rollback receipt,
        pending HITL confirmation status, or a structured `ToolErrorEnvelope`
        with deterministic `recovery_instructions`.
    """
    with tracer.start_as_current_span("tool.execute_canary_traffic_rollback") as span:
        try:
            validated = CanaryRollbackRequest(
                service_name=service_name,  # type: ignore[arg-type]
                target_revision=target_revision,
                traffic_shift_pct=traffic_shift_pct,
                severity=severity,  # type: ignore[arg-type]
                incident_id=incident_id,
                justification=justification,
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            field_name = ".".join(str(p) for p in first.get("loc", ()))
            return ToolErrorEnvelope(
                error_code="INVALID_ROLLBACK_PARAMETERS",
                message=f"Invalid rollback parameter '{field_name}': {first.get('msg')}",
                recovery_instructions=(
                    "Call list_verified_healthy_revisions(service_name=...) to inspect valid "
                    "revision names and ensure traffic_shift_pct is between 1 and 100."
                ),
                suggested_next_tool="list_verified_healthy_revisions",
                valid_options=list(VALID_SERVICES),
            ).model_dump()

        span.set_attribute("aegis.service_name", validated.service_name)
        span.set_attribute("aegis.target_revision", validated.target_revision)
        span.set_attribute("aegis.traffic_shift_pct", validated.traffic_shift_pct)

        settings = get_settings()
        if settings.change_freeze_active and validated.severity != "P0":
            return ToolErrorEnvelope(
                error_code="CHANGE_FREEZE_BLOCK",
                message=(
                    f"Production change freeze is active; {validated.severity} rollbacks "
                    "require VP/IC override."
                ),
                recovery_instructions=(
                    "Do NOT retry execute_canary_traffic_rollback. Notify the war room "
                    "via send_war_room_incident_update requesting change-freeze exception approval."
                ),
                suggested_next_tool="send_war_room_incident_update",
                valid_options=["#sre-war-room", "#incident-exec-updates", "pagerduty-oncall"],
            ).model_dump()

        service = SERVICES_CATALOG[validated.service_name]
        revisions_by_id = {r["revision"]: r for r in service["revisions"]}
        healthy_ids = [
            r["revision"] for r in service["revisions"] if r["rollback_eligible"]
        ]

        rev = revisions_by_id.get(validated.target_revision)
        if rev is None or not rev["rollback_eligible"]:
            reason = (
                rev["reason"]
                if rev is not None
                else f"Revision '{validated.target_revision}' does not exist for {validated.service_name}."
            )
            return ToolErrorEnvelope(
                error_code="UNHEALTHY_TARGET_REVISION",
                message=f"Cannot roll back to '{validated.target_revision}': {reason}",
                recovery_instructions=(
                    f"Call list_verified_healthy_revisions(service_name='{validated.service_name}') "
                    "and select one of the verified healthy revisions listed in valid_options."
                ),
                suggested_next_tool="list_verified_healthy_revisions",
                valid_options=healthy_ids,
            ).model_dump()

        # Defense-in-depth explicit HITL confirmation inside tool body
        needs_approval = requires_production_rollback_approval(
            service_name=validated.service_name,
            target_revision=validated.target_revision,
            traffic_shift_pct=validated.traffic_shift_pct,
            severity=validated.severity,
            incident_id=validated.incident_id,
            justification=validated.justification,
        )
        confirmation = getattr(tool_context, "tool_confirmation", None)
        if needs_approval and confirmation is None:
            tool_context.request_confirmation(
                hint=(
                    f"APPROVAL REQUIRED: Shift {validated.traffic_shift_pct}% traffic on "
                    f"{validated.service_name} to {validated.target_revision} for "
                    f"{validated.incident_id} ({validated.severity}). Approve?"
                ),
                payload={
                    "incident_id": validated.incident_id,
                    "service_name": validated.service_name,
                    "target_revision": validated.target_revision,
                    "traffic_shift_pct": validated.traffic_shift_pct,
                    "severity": validated.severity,
                    "blast_radius": tool_context.state.get("last_blast_radius"),
                },
            )
            return {
                "status": "awaiting_human_approval",
                "incident_id": validated.incident_id,
                "service_name": validated.service_name,
                "target_revision": validated.target_revision,
                "traffic_shift_pct": validated.traffic_shift_pct,
                "message": (
                    "Execution paused for mandatory Human-in-the-Loop approval. "
                    "Wait for the on-call SRE to confirm before proceeding."
                ),
            }

        if needs_approval and confirmation is not None and not confirmation.confirmed:
            return {
                "status": "rejected_by_human",
                "incident_id": validated.incident_id,
                "service_name": validated.service_name,
                "target_revision": validated.target_revision,
                "message": "Human operator denied the production canary rollback. No changes applied.",
            }

        receipt = {
            "status": "success",
            "action": "canary_traffic_rollback_executed",
            "incident_id": validated.incident_id,
            "service_name": validated.service_name,
            "previous_revision": service["active_revision"],
            "target_revision": validated.target_revision,
            "traffic_shift_pct": validated.traffic_shift_pct,
            "human_approved": needs_approval,
            "executed_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "justification": get_pii_redactor().redact_text(validated.justification),
        }
        MUTATION_LEDGER.applied_rollbacks.append(receipt)
        tool_context.state["last_mitigation_action"] = (
            f"Canary rollback of {validated.service_name} to {validated.target_revision} "
            f"({validated.traffic_shift_pct}%)"
        )
        return receipt


def apply_waf_ip_rate_limit(
    service_name: str,
    source_cidr: str,
    requests_per_minute: int,
    duration_minutes: int,
    incident_id: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Apply a time-bounded Cloud Armor / WAF IP rate-limiting rule behind mandatory HITL approval.

    Protects production edge gateways against credential stuffing or volumetric abuse
    while refusing overly broad CIDR prefixes (< /24) and always requiring explicit
    human operator confirmation.

    Args:
        service_name: Edge service to protect (`checkout-api`, `auth-gateway`,
            `catalog-search`, or `payments-ledger`).
        source_cidr: Narrow IPv4 CIDR block (/24 to /32, e.g., `198.51.100.42/32`).
        requests_per_minute: Allowed requests per minute threshold (10 to 10000).
        duration_minutes: Automatic rule expiration TTL in minutes (5 to 1440).
        incident_id: Incident ticket ID formatted as `INC-YYYY-NNNN`.

    Returns:
        A JSON-serializable dictionary confirming the applied WAF policy,
        pending HITL confirmation status, or a structured `ToolErrorEnvelope`
        guiding CIDR/argument correction.
    """
    with tracer.start_as_current_span("tool.apply_waf_ip_rate_limit") as span:
        try:
            validated = WafRateLimitRequest(
                service_name=service_name,  # type: ignore[arg-type]
                source_cidr=source_cidr,
                requests_per_minute=requests_per_minute,
                duration_minutes=duration_minutes,
                incident_id=incident_id,
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            field_name = ".".join(str(p) for p in first.get("loc", ()))
            return ToolErrorEnvelope(
                error_code="INVALID_WAF_POLICY_PARAMETERS",
                message=f"WAF rule validation failed on '{field_name}': {first.get('msg')}",
                recovery_instructions=(
                    "Ensure source_cidr is a valid IPv4 CIDR narrowed to /24../32 "
                    "(e.g., 198.51.100.42/32 from telemetry) and requests_per_minute is 10..10000."
                ),
                suggested_next_tool="fetch_service_telemetry_anomalies",
                valid_options=list(VALID_SERVICES),
            ).model_dump()

        span.set_attribute("aegis.service_name", validated.service_name)
        span.set_attribute("aegis.waf_cidr", validated.source_cidr)

        confirmation = getattr(tool_context, "tool_confirmation", None)
        if confirmation is None:
            tool_context.request_confirmation(
                hint=(
                    f"APPROVAL REQUIRED: Apply Cloud Armor WAF rate limit ({validated.requests_per_minute} rpm "
                    f"for {validated.duration_minutes}m) on {validated.service_name} blocking "
                    f"{validated.source_cidr} for {validated.incident_id}. Approve?"
                ),
                payload=validated.model_dump(),
            )
            return {
                "status": "awaiting_human_approval",
                "incident_id": validated.incident_id,
                "service_name": validated.service_name,
                "source_cidr": validated.source_cidr,
                "message": "WAF policy paused for mandatory Human-in-the-Loop approval.",
            }

        if not confirmation.confirmed:
            return {
                "status": "rejected_by_human",
                "incident_id": validated.incident_id,
                "service_name": validated.service_name,
                "source_cidr": validated.source_cidr,
                "message": "Human operator denied the WAF rate-limit rule. No changes applied.",
            }

        receipt = {
            "status": "success",
            "action": "waf_ip_rate_limit_applied",
            "incident_id": validated.incident_id,
            "service_name": validated.service_name,
            "source_cidr": validated.source_cidr,
            "requests_per_minute": validated.requests_per_minute,
            "duration_minutes": validated.duration_minutes,
            "human_approved": True,
            "applied_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        MUTATION_LEDGER.applied_waf_rules.append(receipt)
        tool_context.state["last_mitigation_action"] = (
            f"WAF rate limit {validated.requests_per_minute}rpm on {validated.source_cidr} "
            f"for {validated.service_name}"
        )
        return receipt


def send_war_room_incident_update(
    incident_id: str,
    channel: str,
    severity: str,
    summary: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Publish a PII-scrubbed status update to an approved SRE war-room channel.

    Resolves webhook/PagerDuty credentials exclusively via Google Cloud Secret Manager
    (zero hardcoded tokens) and scrubs all PII via Cloud DLP before dispatch.

    Args:
        incident_id: Incident ticket ID formatted as `INC-YYYY-NNNN`.
        channel: Destination channel (one of `#sre-war-room`,
            `#incident-exec-updates`, or `pagerduty-oncall`).
        severity: Incident severity (`P0`, `P1`, `P2`, or `P3`).
        summary: Concise status update (15 to 1200 characters). Any accidental
            PII or token strings are automatically scrubbed before delivery.

    Returns:
        A JSON-serializable dictionary confirming delivery status (`delivered`
        or `recorded_local_audit_mode`), scrubbed summary, and secret resolution
        mode; or a structured `ToolErrorEnvelope` on validation error.
    """
    with tracer.start_as_current_span("tool.send_war_room_incident_update") as span:
        try:
            validated = WarRoomUpdateRequest(
                incident_id=incident_id,
                channel=channel,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                summary=summary,
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            return ToolErrorEnvelope(
                error_code="INVALID_WAR_ROOM_UPDATE",
                message=f"Invalid war-room update payload: {first.get('msg')}",
                recovery_instructions=(
                    "Use an approved channel (#sre-war-room, #incident-exec-updates, or "
                    "pagerduty-oncall), valid INC-YYYY-NNNN ID, and a summary of at least 15 chars."
                ),
                suggested_next_tool="send_war_room_incident_update",
                valid_options=["#sre-war-room", "#incident-exec-updates", "pagerduty-oncall"],
            ).model_dump()

        span.set_attribute("aegis.incident_id", validated.incident_id)
        span.set_attribute("aegis.channel", validated.channel)

        settings = get_settings()
        secret_id = (
            settings.pagerduty_secret_id
            if validated.channel == "pagerduty-oncall"
            else settings.slack_webhook_secret_id
        )
        env_key = (
            "AEGIS_PAGERDUTY_TOKEN"
            if validated.channel == "pagerduty-oncall"
            else "AEGIS_SLACK_WEBHOOK"
        )
        try:
            token = get_secret_provider().get_secret(
                secret_id, env_var_name=env_key, required=False
            )
        except SecretResolutionError:
            return ToolErrorEnvelope(
                error_code="SECRET_MANAGER_UNAVAILABLE",
                message=f"Unable to retrieve Secret Manager credential '{secret_id}'.",
                recovery_instructions=(
                    "Verify the runtime service account holds roles/secretmanager.secretAccessor "
                    "on the notification secret and retry."
                ),
                suggested_next_tool=None,
                valid_options=[],
            ).model_dump()

        redaction = get_pii_redactor().redact_text_with_report(validated.summary)
        delivery_mode = (
            "secret_manager_authenticated" if token else "local_audited_dry_run"
        )
        record = {
            "status": "success",
            "incident_id": validated.incident_id,
            "channel": validated.channel,
            "severity": validated.severity,
            "scrubbed_summary": redaction.redacted_text,
            "pii_redactions_applied": redaction.redaction_count,
            "credential_source": delivery_mode,
            "sent_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        MUTATION_LEDGER.war_room_updates.append(record)
        logger.info(
            "war_room_update_dispatched",
            incident_id=validated.incident_id,
            channel=validated.channel,
            credential_source=delivery_mode,
        )
        return record


# ADK FunctionTool wrappers wiring first-class Human-in-the-Loop confirmation hooks
canary_rollback_tool = FunctionTool(
    func=execute_canary_traffic_rollback,
    require_confirmation=requires_production_rollback_approval,
)

waf_rate_limit_tool = FunctionTool(
    func=apply_waf_ip_rate_limit,
    require_confirmation=True,
)
