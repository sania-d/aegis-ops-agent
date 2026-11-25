"""OpenTelemetry distributed tracing configured for Google Cloud Trace + local testing."""

from __future__ import annotations

import os
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
)

from app.config.settings import AegisSettings, get_settings

_CONFIGURED = False


def configure_tracing(
    settings: AegisSettings | None = None,
    *,
    exporter: SpanExporter | None = None,
    force: bool = False,
) -> TracerProvider:
    """Initialize OpenTelemetry TracerProvider with Google Cloud Trace exporter.

    Args:
        settings: Optional AegisSettings instance.
        exporter: Optional explicit SpanExporter (e.g., InMemorySpanExporter in tests).
        force: Attach explicit exporter to active provider when already initialized.

    Returns:
        Configured OpenTelemetry TracerProvider.
    """
    global _CONFIGURED
    cfg = settings or get_settings()

    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        if exporter is not None:
            existing.add_span_processor(SimpleSpanProcessor(exporter))
        _CONFIGURED = True
        return existing

    resource = Resource.create(
        {
            "service.name": "aegis-ops-agent",
            "service.namespace": "aegis-ops",
            "service.version": os.environ.get("COMMIT_SHA", "0.1.0"),
            "deployment.environment": cfg.aegis_env,
        }
    )
    provider = TracerProvider(resource=resource)

    active_exporter = exporter
    if active_exporter is not None:
        provider.add_span_processor(SimpleSpanProcessor(active_exporter))
    elif (
        cfg.otel_enabled
        and cfg.google_cloud_project
        and cfg.aegis_env in {"staging", "production"}
    ):
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

            provider.add_span_processor(
                BatchSpanProcessor(
                    CloudTraceSpanExporter(project_id=cfg.google_cloud_project)
                )
            )
        except Exception:
            pass

    trace.set_tracer_provider(provider)
    _CONFIGURED = True
    return provider


def get_tracer(name: str = "aegis_ops_agent") -> trace.Tracer:
    """Return an OpenTelemetry Tracer bound to the active TracerProvider."""
    if not _CONFIGURED:
        configure_tracing()
    return trace.get_tracer(name)


def get_current_trace_context(project_id: str | None = None) -> dict[str, Any]:
    """Return Cloud Logging-compatible trace and span correlation fields."""
    span = trace.get_current_span()
    ctx = span.get_span_context() if span is not None else None
    if ctx is None or not ctx.is_valid:
        return {}

    trace_id = f"{ctx.trace_id:032x}"
    span_id = f"{ctx.span_id:016x}"
    proj = project_id or get_settings().google_cloud_project or "local-project"
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "logging.googleapis.com/trace": f"projects/{proj}/traces/{trace_id}",
        "logging.googleapis.com/spanId": span_id,
        "logging.googleapis.com/trace_sampled": bool(ctx.trace_flags.sampled),
    }
