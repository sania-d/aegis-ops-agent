"""Typed environment-driven settings for AegisOps (zero secrets stored here)."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

import google.auth
from google.auth.exceptions import DefaultCredentialsError
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def resolve_default_gcp_project() -> str | None:
    """Resolve the active GCP project ID safely without failing in offline tests."""
    env_project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if env_project:
        return env_project
    if os.environ.get("AEGIS_OFFLINE_MODE", "").lower() in {"1", "true", "yes"}:
        return None
    try:
        _, project_id = google.auth.default()
        return str(project_id) if project_id else None
    except (DefaultCredentialsError, OSError):
        return None


class AegisSettings(BaseSettings):
    """Non-secret runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    aegis_env: Literal["local", "test", "staging", "production"] = Field(
        default="local",
        alias="AEGIS_ENV",
        description="Execution environment controlling fail-closed security behavior.",
    )
    google_cloud_project: str | None = Field(
        default_factory=resolve_default_gcp_project,
        alias="GOOGLE_CLOUD_PROJECT",
        description="Google Cloud project ID.",
    )
    google_cloud_location: str = Field(
        default="us-central1",
        alias="GOOGLE_CLOUD_LOCATION",
        description="Vertex AI location for Gemini inference.",
    )
    aegis_region: str = Field(
        default="us-central1",
        alias="AEGIS_REGION",
        description="Primary GCP deployment region (Agent Runtime, DLP, Model Armor).",
    )
    google_genai_use_vertexai: bool = Field(
        default=True,
        alias="GOOGLE_GENAI_USE_VERTEXAI",
        description="Route Gemini calls through Vertex AI when True.",
    )

    # Strategic model routing defaults (overridable via env vars)
    fast_model: str = Field(
        default="gemini-2.5-flash",
        alias="AEGIS_FAST_MODEL",
        description="Low-latency Flash model for routing, parallel diagnostics, and compaction.",
    )
    reasoning_model: str = Field(
        default="gemini-2.5-pro",
        alias="AEGIS_REASONING_MODEL",
        description="High-reasoning Pro model for root-cause synthesis, planning, and postmortems.",
    )
    judge_model: str = Field(
        default="gemini-2.5-flash",
        alias="AEGIS_JUDGE_MODEL",
        description="Deterministic judge model (temperature=0.0) for policy self-eval and critique.",
    )

    # Persistence, Vertex AI Search, and Memory Bank
    session_db_url: str = Field(
        default="sqlite+aiosqlite:///./.aegis_state/sessions.db",
        alias="AEGIS_SESSION_DB_URL",
        description="Persistent DatabaseSessionService URI for local/standalone runs.",
    )
    memory_db_path: str = Field(
        default="./.aegis_state/incident_memory.db",
        alias="AEGIS_MEMORY_DB_PATH",
        description="Persistent SQLite fallback path for async long-term memory.",
    )
    agent_engine_id: str | None = Field(
        default=None,
        alias="AGENT_ENGINE_ID",
        description="Vertex AI Agent Engine / Agent Runtime ID for VertexAiMemoryBankService.",
    )
    vertex_search_datastore_id: str | None = Field(
        default=None,
        alias="VERTEX_SEARCH_DATASTORE_ID",
        description="Optional Vertex AI Search Data Store resource path for SRE runbooks.",
    )

    # Guardrails, DLP, and Policy Controls
    dlp_enabled: bool = Field(
        default=False,
        alias="AEGIS_DLP_ENABLED",
        description="Enable live Google Cloud DLP API calls (deterministic redactor always active).",
    )
    model_armor_template: str | None = Field(
        default=None,
        alias="AEGIS_MODEL_ARMOR_TEMPLATE",
        description="Full resource name of a Google Cloud Model Armor template.",
    )
    change_freeze_active: bool = Field(
        default=False,
        alias="AEGIS_CHANGE_FREEZE_ACTIVE",
        description="When True, non-P0 production mutations are blocked by policy.",
    )
    self_eval_use_llm: bool = Field(
        default=False,
        alias="AEGIS_SELF_EVAL_USE_LLM",
        description="Enable live LLM-as-a-Judge checks inside PolicySelfEvalPlugin.",
    )

    # Observability
    otel_enabled: bool = Field(
        default=True,
        alias="AEGIS_OTEL_ENABLED",
        description="Enable OpenTelemetry tracing instrumentation.",
    )
    log_level: str = Field(
        default="INFO",
        alias="AEGIS_LOG_LEVEL",
        description="Structured JSON logging level.",
    )
    bq_analytics_dataset_id: str = Field(
        default="aegis_ops_agent_telemetry",
        alias="BQ_ANALYTICS_DATASET_ID",
        description="BigQuery dataset ID for ADK Agent Analytics.",
    )
    logs_bucket_name: str | None = Field(
        default=None,
        alias="LOGS_BUCKET_NAME",
        description="GCS bucket for ADK artifact and telemetry storage.",
    )

    # Secret Manager Secret IDs (names only, never secret values)
    pagerduty_secret_id: str = Field(
        default="aegis-ops-agent-pagerduty-token",
        alias="AEGIS_PAGERDUTY_SECRET_ID",
    )
    slack_webhook_secret_id: str = Field(
        default="aegis-ops-agent-slack-webhook",
        alias="AEGIS_SLACK_WEBHOOK_SECRET_ID",
    )


@lru_cache(maxsize=1)
def get_settings() -> AegisSettings:
    """Return cached singleton AegisSettings instance."""
    return AegisSettings()


def reset_settings_cache() -> None:
    """Clear settings cache (used by tests after mutating environment variables)."""
    get_settings.cache_clear()
