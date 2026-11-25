"""Read-only SRE diagnostic tools with strict Pydantic validation and guided error recovery."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext
from pydantic import ValidationError

from app.config.settings import get_settings
from app.data.synthetic_store import SERVICES_CATALOG, search_local_runbooks
from app.observability.tracing import get_tracer
from app.schemas.incidents import (
    VALID_SERVICES,
    BlastRadiusEstimate,
    BlastRadiusQuery,
    DeploymentCorrelationQuery,
    HealthyRevisionsQuery,
    RunbookSearchQuery,
    TelemetryAnomalyQuery,
    ToolErrorEnvelope,
)
from app.security.pii_redactor import get_pii_redactor

tracer = get_tracer("aegis_ops.tools.diagnostics")


def _validation_error_envelope(
    exc: ValidationError, *, suggested_next_tool: str | None = None
) -> dict[str, Any]:
    """Convert Pydantic ValidationError into an actionable LLM recovery envelope."""
    first = exc.errors()[0]
    field_path = ".".join(str(part) for part in first.get("loc", ()))
    reason = first.get("msg", "Invalid parameter value.")
    return ToolErrorEnvelope(
        error_code="INVALID_TOOL_ARGUMENTS",
        message=f"Validation failed for '{field_path}': {reason}",
        recovery_instructions=(
            "Fix the invalid argument value using the schema constraints and retry. "
            f"Valid service names are: {', '.join(VALID_SERVICES)}."
        ),
        suggested_next_tool=suggested_next_tool,
        valid_options=list(VALID_SERVICES),
    ).model_dump()


def fetch_service_telemetry_anomalies(
    service_name: str,
    window_minutes: int,
    incident_id: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Retrieve live telemetry anomalies, SLO error rates, and PII-scrubbed error log samples.

    Queries latency P99 vs. baseline, HTTP 5xx error rates, resource saturation,
    and sample error logs for a NovaShop Cloud microservice. All sample log strings
    are passed through the Cloud DLP / PII redactor prior to returning.

    Args:
        service_name: Exact microservice identifier (one of `checkout-api`,
            `auth-gateway`, `catalog-search`, or `payments-ledger`).
        window_minutes: Lookback aggregation window in minutes (integer 5 to 240).
        incident_id: Active incident ticket formatted as `INC-YYYY-NNNN`
            (e.g., `INC-2026-1042`).

    Returns:
        A JSON-serializable dictionary containing `status`, `incident_id`,
        `service_name`, `severity`, `metrics`, `sample_error_logs` (PII-scrubbed),
        and `pii_redaction_summary`; or a structured `ToolErrorEnvelope` with
        `recovery_instructions` if validation fails.
    """
    with tracer.start_as_current_span("tool.fetch_service_telemetry_anomalies") as span:
        try:
            validated = TelemetryAnomalyQuery(
                service_name=service_name,  # type: ignore[arg-type]
                window_minutes=window_minutes,
                incident_id=incident_id,
            )
        except ValidationError as exc:
            return _validation_error_envelope(
                exc, suggested_next_tool="fetch_service_telemetry_anomalies"
            )

        span.set_attribute("aegis.service_name", validated.service_name)
        span.set_attribute("aegis.incident_id", validated.incident_id)

        service = SERVICES_CATALOG[validated.service_name]
        telemetry = dict(service["telemetry"])
        redactor = get_pii_redactor()

        scrubbed_logs: list[str] = []
        total_redactions = 0
        detected_types: set[str] = set()
        for line in telemetry["sample_error_logs"]:
            report = redactor.redact_text_with_report(line)
            scrubbed_logs.append(report.redacted_text)
            total_redactions += report.redaction_count
            detected_types.update(report.detected_types)

        tool_context.state["active_service"] = validated.service_name
        tool_context.state["active_incident_id"] = validated.incident_id

        return {
            "status": "success",
            "incident_id": validated.incident_id,
            "service_name": validated.service_name,
            "service_tier": service["tier"],
            "window_minutes": validated.window_minutes,
            "severity": telemetry["severity"],
            "active_revision": service["active_revision"],
            "metrics": {
                "p99_latency_ms": telemetry["p99_latency_ms"],
                "baseline_p99_ms": telemetry["baseline_p99_ms"],
                "error_rate_pct": telemetry["error_rate_pct"],
                "baseline_error_rate_pct": telemetry["baseline_error_rate_pct"],
                "cpu_utilization_pct": telemetry["cpu_utilization_pct"],
                "db_connection_pool_pct": telemetry.get("db_connection_pool_pct"),
                "failed_login_rpm": telemetry.get("failed_login_rpm"),
                "suspected_source_cidr": telemetry.get("suspected_source_cidr"),
            },
            "sample_error_logs": scrubbed_logs,
            "pii_redaction_summary": {
                "redactions_applied": total_redactions,
                "detected_info_types": sorted(detected_types),
            },
        }


def correlate_recent_deployments(
    service_name: str,
    lookback_hours: int,
) -> dict[str, Any]:
    """Audit recent release revisions, commit SHAs, and rollout health for a service.

    Compares the active deployment against prior releases to determine whether
    a recent code change correlates with an active production anomaly.

    Args:
        service_name: Exact microservice identifier (`checkout-api`,
            `auth-gateway`, `catalog-search`, or `payments-ledger`).
        lookback_hours: Number of hours of deployment history to inspect (1 to 168).

    Returns:
        A JSON-serializable dictionary with `status`, `service_name`,
        `active_revision`, and `deployments` (list of revisions with commit SHAs,
        summaries, timestamps, and rollback eligibility); or a structured
        `ToolErrorEnvelope` on invalid input.
    """
    with tracer.start_as_current_span("tool.correlate_recent_deployments") as span:
        try:
            validated = DeploymentCorrelationQuery(
                service_name=service_name,  # type: ignore[arg-type]
                lookback_hours=lookback_hours,
            )
        except ValidationError as exc:
            return _validation_error_envelope(
                exc, suggested_next_tool="correlate_recent_deployments"
            )

        span.set_attribute("aegis.service_name", validated.service_name)
        service = SERVICES_CATALOG[validated.service_name]
        return {
            "status": "success",
            "service_name": validated.service_name,
            "lookback_hours": validated.lookback_hours,
            "active_revision": service["active_revision"],
            "deployments": service["revisions"],
        }


def search_verified_runbooks(
    query: str,
    service_name: str,
    top_k: int,
) -> dict[str, Any]:
    """Search grounded SRE incident runbooks via Vertex AI Search with local vector fallback.

    Retrieves verified troubleshooting steps, recommended canary rollback percentages,
    and mandatory HITL policies from the operational knowledge base.

    Args:
        query: Concise symptom or error signature query (3 to 300 characters).
        service_name: Target microservice identifier used to boost service-specific
            runbooks (`checkout-api`, `auth-gateway`, `catalog-search`, or
            `payments-ledger`).
        top_k: Maximum number of runbook results to return (integer 1 to 5).

    Returns:
        A JSON-serializable dictionary with `status`, `retrieval_backend`, and
        `runbooks` (ranked runbook IDs, steps, and HITL policies); or a
        structured `ToolErrorEnvelope` on validation failure.
    """
    with tracer.start_as_current_span("tool.search_verified_runbooks") as span:
        try:
            validated = RunbookSearchQuery(
                query=query,
                service_name=service_name,  # type: ignore[arg-type]
                top_k=top_k,
            )
        except ValidationError as exc:
            return _validation_error_envelope(
                exc, suggested_next_tool="search_verified_runbooks"
            )

        span.set_attribute("aegis.service_name", validated.service_name)
        settings = get_settings()

        # Live Vertex AI Search (Discovery Engine) when configured via Terraform
        if settings.vertex_search_datastore_id:
            try:
                from google.cloud import discoveryengine_v1

                client = discoveryengine_v1.SearchServiceClient()
                serving_config = (
                    f"{settings.vertex_search_datastore_id}/servingConfigs/default_search"
                )
                request = discoveryengine_v1.SearchRequest(
                    serving_config=serving_config,
                    query=f"{validated.service_name} {validated.query}",
                    page_size=validated.top_k,
                )
                response = client.search(request=request)
                docs = []
                for result in response.results:
                    struct_data = dict(result.document.derived_struct_data)
                    docs.append(
                        {
                            "runbook_id": result.document.id,
                            "title": struct_data.get("title", "SRE Runbook"),
                            "snippet": struct_data.get("snippets", []),
                            "source_backend": "vertex_ai_search",
                        }
                    )
                if docs:
                    return {
                        "status": "success",
                        "service_name": validated.service_name,
                        "retrieval_backend": "vertex_ai_search",
                        "runbooks": docs,
                    }
            except Exception:
                # Fall through seamlessly to deterministic local runbook corpus
                pass

        matches = search_local_runbooks(
            query=validated.query,
            service_name=validated.service_name,
            top_k=validated.top_k,
        )
        return {
            "status": "success",
            "service_name": validated.service_name,
            "retrieval_backend": "local_vector_fallback",
            "runbooks": matches,
        }


def list_verified_healthy_revisions(service_name: str) -> dict[str, Any]:
    """List verified healthy, rollback-eligible production revisions for a microservice.

    Must be consulted prior to proposing or executing a canary rollback, or when
    recovering from an `UNHEALTHY_TARGET_REVISION` error.

    Args:
        service_name: Target microservice identifier (`checkout-api`,
            `auth-gateway`, `catalog-search`, or `payments-ledger`).

    Returns:
        A JSON-serializable dictionary listing `active_revision`,
        `healthy_rollback_candidates`, and `ineligible_revisions` with exact
        reasons; or a structured `ToolErrorEnvelope` on invalid service name.
    """
    with tracer.start_as_current_span("tool.list_verified_healthy_revisions") as span:
        try:
            validated = HealthyRevisionsQuery(service_name=service_name)  # type: ignore[arg-type]
        except ValidationError as exc:
            return _validation_error_envelope(
                exc, suggested_next_tool="list_verified_healthy_revisions"
            )

        span.set_attribute("aegis.service_name", validated.service_name)
        service = SERVICES_CATALOG[validated.service_name]
        healthy = [r for r in service["revisions"] if r["rollback_eligible"]]
        ineligible = [r for r in service["revisions"] if not r["rollback_eligible"]]
        return {
            "status": "success",
            "service_name": validated.service_name,
            "active_revision": service["active_revision"],
            "healthy_rollback_candidates": healthy,
            "ineligible_revisions": ineligible,
        }


def calculate_blast_radius_estimate(
    service_name: str,
    action_type: str,
    traffic_shift_pct: int,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Quantify affected RPS, downstream dependencies, risk tier, and HITL requirements.

    Must be invoked before any production-mutating remediation tool so the SRE
    and Human-in-the-Loop confirmation gate have grounded impact metrics.

    Args:
        service_name: Microservice affected by the proposed remediation
            (`checkout-api`, `auth-gateway`, `catalog-search`, or `payments-ledger`).
        action_type: Remediation type (`canary_rollback`, `waf_ip_rate_limit`,
            or `config_flag_revert`).
        traffic_shift_pct: Percentage of live traffic impacted (integer 1 to 100).

    Returns:
        A validated `BlastRadiusEstimate` dictionary containing
        `estimated_affected_rps`, `downstream_dependencies`, `risk_level`,
        `requires_human_approval`, and `policy_note`; or a structured
        `ToolErrorEnvelope` on validation error.
    """
    with tracer.start_as_current_span("tool.calculate_blast_radius_estimate") as span:
        try:
            validated = BlastRadiusQuery(
                service_name=service_name,  # type: ignore[arg-type]
                action_type=action_type,  # type: ignore[arg-type]
                traffic_shift_pct=traffic_shift_pct,
            )
        except ValidationError as exc:
            return _validation_error_envelope(
                exc, suggested_next_tool="calculate_blast_radius_estimate"
            )

        span.set_attribute("aegis.service_name", validated.service_name)
        service = SERVICES_CATALOG[validated.service_name]
        affected_rps = max(
            1, round(service["baseline_rps"] * (validated.traffic_shift_pct / 100.0))
        )
        severity = service["telemetry"]["severity"]

        if validated.action_type == "waf_ip_rate_limit":
            risk_level = "HIGH"
            requires_approval = True
            policy_note = "All production WAF edge modifications require mandatory human confirmation."
        elif severity in {"P0", "P1"} or validated.traffic_shift_pct > 10:
            risk_level = "CRITICAL" if validated.traffic_shift_pct >= 50 else "HIGH"
            requires_approval = True
            policy_note = (
                f"Severity {severity} / {validated.traffic_shift_pct}% shift exceeds autonomous "
                "threshold (>10% or P0/P1); mandatory human confirmation required."
            )
        else:
            risk_level = "LOW" if validated.traffic_shift_pct <= 5 else "MEDIUM"
            requires_approval = False
            policy_note = (
                "Low-risk P2/P3 canary shift <=10% permitted autonomously when no change freeze is active."
            )

        estimate = BlastRadiusEstimate(
            service_name=validated.service_name,
            action_type=validated.action_type,
            traffic_shift_pct=validated.traffic_shift_pct,
            estimated_affected_rps=affected_rps,
            downstream_dependencies=list(service["downstream_dependencies"]),
            risk_level=risk_level,
            requires_human_approval=requires_approval,
            policy_note=policy_note,
        )
        result = estimate.model_dump()
        tool_context.state["last_blast_radius"] = result
        return result
