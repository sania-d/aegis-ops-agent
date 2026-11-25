"""Strict Pydantic v2 schemas constraining LLM tool inputs, outputs, and error recovery."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ServiceName = Literal[
    "checkout-api",
    "auth-gateway",
    "catalog-search",
    "payments-ledger",
]
VALID_SERVICES: tuple[str, ...] = (
    "checkout-api",
    "auth-gateway",
    "catalog-search",
    "payments-ledger",
)

SeverityLevel = Literal["P0", "P1", "P2", "P3"]
ActionType = Literal["canary_rollback", "waf_ip_rate_limit", "config_flag_revert"]

_REVISION_PATTERN = re.compile(r"^[a-z0-9-]+-v\d+\.\d+\.\d+$")
_INCIDENT_ID_PATTERN = re.compile(r"^INC-\d{4}-\d{4,}$")


class ToolErrorEnvelope(BaseModel):
    """Structured error contract guiding the LLM toward deterministic self-recovery."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["error"] = Field(
        default="error",
        description="Fixed status flag indicating recoverable tool failure.",
    )
    error_code: str = Field(
        description="Machine-readable error code for branching and telemetry."
    )
    message: str = Field(description="Clear explanation of why the call failed.")
    recovery_instructions: str = Field(
        description="Actionable step-by-step instructions telling the agent how to recover."
    )
    suggested_next_tool: str | None = Field(
        default=None,
        description="Specific tool name the agent should invoke next to resolve the error.",
    )
    valid_options: list[str] = Field(
        default_factory=list,
        description="Allowed parameter values or valid resource identifiers.",
    )


class TelemetryAnomalyQuery(BaseModel):
    """Validated input schema for `fetch_service_telemetry_anomalies`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Target NovaShop Cloud microservice name."
    )
    window_minutes: int = Field(
        ge=5,
        le=240,
        description="Lookback telemetry window in minutes (5 to 240).",
    )
    incident_id: str = Field(
        description="Incident ticket identifier formatted as INC-YYYY-NNNN."
    )

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        if not _INCIDENT_ID_PATTERN.match(value):
            raise ValueError(
                "incident_id must match format INC-YYYY-NNNN (e.g., INC-2026-1042)."
            )
        return value


class DeploymentCorrelationQuery(BaseModel):
    """Validated input schema for `correlate_recent_deployments`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Target microservice whose deployment timeline should be audited."
    )
    lookback_hours: int = Field(
        ge=1,
        le=168,
        description="Hours of deployment history to inspect (1 to 168).",
    )


class RunbookSearchQuery(BaseModel):
    """Validated input schema for `search_verified_runbooks`."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        min_length=3,
        max_length=300,
        description="Natural-language symptom or error signature query.",
    )
    service_name: ServiceName = Field(
        description="Service context to prioritize relevant SRE runbooks."
    )
    top_k: int = Field(
        ge=1,
        le=5,
        description="Maximum number of runbook matches to return (1 to 5).",
    )


class HealthyRevisionsQuery(BaseModel):
    """Validated input schema for `list_verified_healthy_revisions`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Service name for which verified healthy rollback candidates are listed."
    )


class BlastRadiusQuery(BaseModel):
    """Validated input schema for `calculate_blast_radius_estimate`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Microservice affected by the proposed remediation."
    )
    action_type: ActionType = Field(
        description="Remediation category (`canary_rollback`, `waf_ip_rate_limit`, or `config_flag_revert`)."
    )
    traffic_shift_pct: int = Field(
        ge=1,
        le=100,
        description="Percentage of live traffic affected by the proposed change (1 to 100).",
    )


class BlastRadiusEstimate(BaseModel):
    """Structured output schema for blast-radius risk analysis."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["success"] = "success"
    service_name: ServiceName
    action_type: ActionType
    traffic_shift_pct: int
    estimated_affected_rps: int
    downstream_dependencies: list[str]
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    requires_human_approval: bool
    policy_note: str


class CanaryRollbackRequest(BaseModel):
    """Validated input schema for high-stakes `execute_canary_traffic_rollback`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Target production microservice to roll back."
    )
    target_revision: str = Field(
        description="Verified healthy target revision formatted as <service>-vX.Y.Z."
    )
    traffic_shift_pct: int = Field(
        ge=1,
        le=100,
        description="Percentage of traffic to shift to target_revision (1 to 100).",
    )
    severity: SeverityLevel = Field(
        description="Active incident severity tier (P0, P1, P2, or P3)."
    )
    incident_id: str = Field(
        description="Associated incident ID (INC-YYYY-NNNN)."
    )
    justification: str = Field(
        min_length=10,
        max_length=500,
        description="Evidence-grounded rationale referencing runbook/telemetry findings.",
    )

    @field_validator("target_revision")
    @classmethod
    def _validate_revision(cls, value: str) -> str:
        if not _REVISION_PATTERN.match(value):
            raise ValueError(
                "target_revision must match '<service>-vX.Y.Z' (e.g., checkout-api-v2.4.0)."
            )
        return value

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        if not _INCIDENT_ID_PATTERN.match(value):
            raise ValueError("incident_id must match INC-YYYY-NNNN.")
        return value


class WafRateLimitRequest(BaseModel):
    """Validated input schema for high-stakes `apply_waf_ip_rate_limit`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Service edge protected by Cloud Armor / WAF policy."
    )
    source_cidr: str = Field(
        description="IPv4 CIDR block to rate-limit (e.g., 198.51.100.42/32)."
    )
    requests_per_minute: int = Field(
        ge=10,
        le=10000,
        description="Maximum allowed requests per minute per source (10 to 10000).",
    )
    duration_minutes: int = Field(
        ge=5,
        le=1440,
        description="Auto-expiration TTL in minutes (5 to 1440).",
    )
    incident_id: str = Field(description="Incident ticket ID (INC-YYYY-NNNN).")

    @field_validator("source_cidr")
    @classmethod
    def _validate_cidr(cls, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(
                "source_cidr must be a valid IPv4/IPv6 CIDR (e.g., 198.51.100.42/32)."
            ) from exc
        if network.prefixlen < 24 and network.version == 4:
            raise ValueError(
                "Refusing overly broad IPv4 prefix (< /24); narrow CIDR to /24../32."
            )
        return str(network)

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        if not _INCIDENT_ID_PATTERN.match(value):
            raise ValueError("incident_id must match INC-YYYY-NNNN.")
        return value


class WarRoomUpdateRequest(BaseModel):
    """Validated input schema for `send_war_room_incident_update`."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(description="Incident ticket ID (INC-YYYY-NNNN).")
    channel: Literal["#sre-war-room", "#incident-exec-updates", "pagerduty-oncall"] = (
        Field(description="Approved incident notification destination.")
    )
    severity: SeverityLevel = Field(description="Incident severity tier.")
    summary: str = Field(
        min_length=15,
        max_length=1200,
        description="Concise PII-free incident status summary.",
    )

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        if not _INCIDENT_ID_PATTERN.match(value):
            raise ValueError("incident_id must match INC-YYYY-NNNN.")
        return value


class MemoryRecallQuery(BaseModel):
    """Validated input schema for `recall_historical_incident_lessons`."""

    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName = Field(
        description="Microservice to search historical incident lessons for."
    )
    symptom_keywords: str = Field(
        min_length=2,
        max_length=200,
        description="Keywords describing symptoms, error codes, or failure mode.",
    )


class RootCauseSynthesis(BaseModel):
    """Structured output schema enforced on `root_cause_synthesizer` agent."""

    incident_id: str = Field(description="Active incident identifier.")
    service_name: str = Field(description="Impacted production service.")
    severity: SeverityLevel = Field(description="Assessed severity level.")
    probable_root_cause: str = Field(
        description="Concise causal explanation grounded strictly in retrieved evidence."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    cited_evidence: list[str] = Field(
        description="List of telemetry metrics, commit SHAs, and runbook IDs supporting the RCA."
    )
    recommended_action: Literal[
        "canary_rollback",
        "waf_ip_rate_limit",
        "escalate_only",
        "monitor_only",
    ] = Field(description="Safest policy-compliant remediation strategy.")
    target_revision_or_cidr: str = Field(
        description="Healthy target revision or attacker CIDR if applicable, else 'none'."
    )
    requires_human_approval: bool = Field(
        description="True whenever production mutation requires explicit HITL approval."
    )


class PostmortemCritique(BaseModel):
    """Structured output schema enforced on `sre_quality_critic` inside LoopAgent."""

    grade: Literal["pass", "revise"] = Field(
        description="'pass' only when all blameless SRE postmortem criteria are met."
    )
    grounding_verified: bool = Field(
        description="True if all metrics, SHAs, and runbook IDs match session state evidence."
    )
    pii_free: bool = Field(
        description="True if zero emails, tokens, SSNs, cards, or secrets appear in the draft."
    )
    missing_sections: list[str] = Field(
        default_factory=list,
        description="Required sections absent or incomplete in the draft.",
    )
    feedback: str = Field(
        description="Specific actionable revisions required if grade is 'revise'."
    )


def export_all_tool_schemas() -> dict[str, dict[str, Any]]:
    """Export JSON Schemas for every AegisOps tool input and structured agent output."""
    models: list[type[BaseModel]] = [
        TelemetryAnomalyQuery,
        DeploymentCorrelationQuery,
        RunbookSearchQuery,
        HealthyRevisionsQuery,
        BlastRadiusQuery,
        BlastRadiusEstimate,
        CanaryRollbackRequest,
        WafRateLimitRequest,
        WarRoomUpdateRequest,
        MemoryRecallQuery,
        RootCauseSynthesis,
        PostmortemCritique,
        ToolErrorEnvelope,
    ]
    return {model.__name__: model.model_json_schema() for model in models}
