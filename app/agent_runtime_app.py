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

"""Managed Vertex AI Agent Runtime (`AdkApp`) entrypoint for AegisOps."""

from __future__ import annotations

import os
from typing import Any

import vertexai
from dotenv import load_dotenv
from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.cloud import logging as google_cloud_logging
from vertexai.agent_engines.templates.adk import AdkApp

from app.agent import app as adk_app
from app.app_utils.telemetry import setup_telemetry
from app.app_utils.typing import Feedback
from app.config.settings import get_settings
from app.memory.async_memory import get_memory_manager
from app.memory.session_factory import create_persistent_session_service
from app.observability.logging_setup import configure_structured_logging, get_logger
from app.observability.tracing import configure_tracing
from app.security.pii_redactor import get_pii_redactor

load_dotenv()


class AgentEngineApp(AdkApp):
    """Managed Agent Runtime wrapper with OpenTelemetry, structured JSON, and DLP-safe feedback."""

    def set_up(self) -> None:
        """Initialize Vertex AI, OpenTelemetry tracing, and structured JSON logging."""
        settings = get_settings()
        configure_tracing(settings)
        configure_structured_logging(settings)
        self._struct_logger = get_logger("agent_runtime_app")

        if os.environ.get("INTEGRATION_TEST", "").upper() != "TRUE":
            try:
                vertexai.init(
                    project=settings.google_cloud_project,
                    location=settings.aegis_region,
                )
            except Exception as exc:
                self._struct_logger.warning(
                    "vertexai_init_deferred", error_type=type(exc).__name__
                )

        setup_telemetry()
        if os.environ.get("AEGIS_OFFLINE_MODE", "").lower() not in {"1", "true", "yes"}:
            super().set_up()

        self.logger: Any = None
        if os.environ.get("INTEGRATION_TEST", "").upper() != "TRUE":
            try:
                logging_client = google_cloud_logging.Client(
                    project=settings.google_cloud_project
                )
                self.logger = logging_client.logger(__name__)
            except Exception as exc:
                self._struct_logger.warning(
                    "cloud_logging_client_fallback", error_type=type(exc).__name__
                )

        if gemini_location:
            os.environ["GOOGLE_CLOUD_LOCATION"] = gemini_location

    def register_feedback(self, feedback: dict[str, Any]) -> None:
        """Validate, PII-scrub, and log structured user feedback."""
        feedback_obj = Feedback.model_validate(feedback)
        scrubbed_payload = get_pii_redactor().redact_obj(feedback_obj.model_dump())
        if getattr(self, "logger", None) is not None:
            self.logger.log_struct(scrubbed_payload, severity="INFO")
        else:
            logger = getattr(self, "_struct_logger", None) or get_logger(
                "agent_runtime_app"
            )
            logger.info("user_feedback_recorded", feedback=scrubbed_payload)

    def register_operations(self) -> dict[str, list[str]]:
        """Expose standard ADK operations plus `register_feedback` on Agent Runtime."""
        operations = super().register_operations()
        operations[""] = [*operations.get("", []), "register_feedback"]
        return operations

    def clone(self) -> AgentEngineApp:
        """Return clone reference required by Agent Runtime serialization."""
        return self


gemini_location = os.environ.get("GOOGLE_CLOUD_LOCATION")
logs_bucket_name = os.environ.get("LOGS_BUCKET_NAME")
_running_in_managed_runtime = bool(os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID"))

if os.environ.get("INTEGRATION_TEST", "").upper() == "TRUE" and not os.environ.get(
    "GOOGLE_CLOUD_PROJECT"
):
    os.environ["GOOGLE_CLOUD_PROJECT"] = "aegis-offline-test"

# In Managed Agent Runtime, Vertex AI automatically provisions managed VertexAiSessionService
# and VertexAiMemoryBankService. Locally/standalone, attach persistent SQLite/Memory builders.
agent_runtime = AgentEngineApp(
    app=adk_app,
    enable_tracing=True,
    artifact_service_builder=lambda: (
        GcsArtifactService(bucket_name=logs_bucket_name)
        if logs_bucket_name
        else InMemoryArtifactService()
    ),
    session_service_builder=(
        None
        if _running_in_managed_runtime
        else lambda: create_persistent_session_service(get_settings())
    ),
    memory_service_builder=(
        None
        if _running_in_managed_runtime
        else lambda: get_memory_manager().get_adk_memory_service()
    ),
)
