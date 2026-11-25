# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""AegisOps ADK Application entrypoint.

Wires:
- Root multi-agent hierarchy (Coordinator + Parallel + Sequential + Loop).
- Strategic Model Routing (gemini-2.5-flash vs. gemini-2.5-pro vs. 0-temp judge).
- Global ADK Plugins (Constitution, Model Armor Guardrail, Policy Self-Eval,
  Intent-vs-Outcome Audit Observability, Reflect-and-Retry, BigQuery Analytics).
- Context Management (EventsCompactionConfig + ContextCacheConfig).
- Human-in-the-Loop Resumability (`ResumabilityConfig(is_resumable=True)`).
"""

from __future__ import annotations

import os
from typing import Any

from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps import App, ResumabilityConfig
from google.adk.apps.app import EventsCompactionConfig
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.plugins.bigquery_agent_analytics_plugin import (
    BigQueryAgentAnalyticsPlugin,
    BigQueryLoggerConfig,
)
from google.adk.plugins.global_instruction_plugin import GlobalInstructionPlugin
from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin

from app.agents.coordinator import create_incident_commander
from app.config.models import ModelTier, get_model_router
from app.config.settings import AegisSettings, get_settings
from app.observability.logging_setup import configure_structured_logging, get_logger
from app.observability.tracing import configure_tracing
from app.plugins.audit_observability_plugin import IntentOutcomeAuditPlugin
from app.plugins.guardrails_plugin import (
    ModelArmorGuardrailPlugin,
    PolicySelfEvalPlugin,
)
from app.prompts.constitution import INCIDENT_COMMANDER_CONSTITUTION

_settings = get_settings()
configure_tracing(_settings)
configure_structured_logging(_settings)
logger = get_logger("agent_bootstrap")

# Configure Vertex AI defaults safely when a GCP project is resolved
if _settings.google_cloud_project and not os.environ.get("GOOGLE_API_KEY"):
    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", _settings.google_cloud_project)
    os.environ.setdefault("GOOGLE_CLOUD_LOCATION", _settings.google_cloud_location)
    os.environ.setdefault(
        "GOOGLE_GENAI_USE_VERTEXAI",
        "True" if _settings.google_genai_use_vertexai else "False",
    )


def _build_plugins(settings: AegisSettings) -> list[BasePlugin]:
    """Assemble global cross-cutting ADK plugins for security, audit, and telemetry."""
    plugins: list[BasePlugin] = [
        GlobalInstructionPlugin(
            global_instruction=INCIDENT_COMMANDER_CONSTITUTION,
            name="aegis_constitution_plugin",
        ),
        ModelArmorGuardrailPlugin(),
        PolicySelfEvalPlugin(settings=settings),
        IntentOutcomeAuditPlugin(),
        ReflectAndRetryToolPlugin(
            name="aegis_reflect_retry_plugin",
            max_retries=2,
            throw_exception_if_retry_exceeded=False,
        ),
    ]

    # Attach BigQuery Agent Analytics when running in GCP with live credentials
    if (
        settings.google_cloud_project
        and settings.aegis_env in {"staging", "production"}
        and os.environ.get("AEGIS_OFFLINE_MODE", "").lower() not in {"1", "true", "yes"}
    ):
        try:
            from google.cloud import bigquery

            bq = bigquery.Client(project=settings.google_cloud_project)
            bq.create_dataset(
                f"{settings.google_cloud_project}.{settings.bq_analytics_dataset_id}",
                exists_ok=True,
            )
            plugins.append(
                BigQueryAgentAnalyticsPlugin(
                    project_id=settings.google_cloud_project,
                    dataset_id=settings.bq_analytics_dataset_id,
                    location=settings.aegis_region,
                    config=BigQueryLoggerConfig(
                        gcs_bucket_name=os.environ.get("BQ_ANALYTICS_GCS_BUCKET"),
                        connection_id=os.environ.get("BQ_ANALYTICS_CONNECTION_ID"),
                    ),
                )
            )
        except Exception as exc:
            logger.warning(
                "bigquery_analytics_init_skipped",
                error_type=type(exc).__name__,
            )
    return plugins


def create_aegis_app(settings: AegisSettings | None = None) -> tuple[Any, App]:
    """Construct a fresh (root_agent, App) pair with full AgentOps configuration."""
    cfg = settings or get_settings()
    router = get_model_router(cfg)
    agent = create_incident_commander(router)

    compaction_config = EventsCompactionConfig(
        compaction_interval=10,
        overlap_size=3,
        token_threshold=12000,
        event_retention_size=6,
        summarizer=LlmEventSummarizer(
            llm=router.create_llm(ModelTier.EVENT_COMPACTION)
        ),
    )

    cache_config = ContextCacheConfig(
        min_tokens=2048,
        ttl_seconds=1800,
        cache_intervals=10,
    )

    adk_app = App(
        name="app",
        root_agent=agent,
        plugins=_build_plugins(cfg),
        events_compaction_config=compaction_config,
        context_cache_config=cache_config,
        resumability_config=ResumabilityConfig(is_resumable=True),
    )
    return agent, adk_app


root_agent, app = create_aegis_app(_settings)
