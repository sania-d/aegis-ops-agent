"""Structured JSON logging with Cloud Logging severity, OTel trace links, and PII redaction."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from app.config.settings import AegisSettings, get_settings
from app.observability.tracing import get_current_trace_context
from app.security.pii_redactor import get_pii_redactor

_LOGGING_CONFIGURED = False


def _inject_cloud_logging_fields(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Map structlog log levels to Google Cloud Logging severity & service metadata."""
    event_dict["severity"] = method_name.upper()
    event_dict.setdefault("service", "aegis-ops-agent")
    return event_dict


def _inject_otel_trace_context(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Attach active OpenTelemetry trace/span IDs to every structured JSON log line."""
    trace_ctx = get_current_trace_context()
    for key, value in trace_ctx.items():
        event_dict.setdefault(key, value)
    return event_dict


def _redact_pii_processor(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Scrub all PII and secrets from every structured log payload prior to emission."""
    redactor = get_pii_redactor()
    return {
        str(k): redactor.redact_obj(v, key_name=str(k))
        for k, v in event_dict.items()
    }


def configure_structured_logging(
    settings: AegisSettings | None = None, *, force: bool = False
) -> None:
    """Configure structlog to emit strict single-line JSON records with PII redaction."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED and not force:
        return

    cfg = settings or get_settings()
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=force,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _inject_cloud_logging_fields,
            _inject_otel_trace_context,
            _redact_pii_processor,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    _LOGGING_CONFIGURED = True


def get_logger(name: str = "aegis_ops_agent") -> structlog.stdlib.BoundLogger | Any:
    """Return a structured JSON logger bound with component name."""
    if not _LOGGING_CONFIGURED:
        configure_structured_logging()
    return structlog.get_logger(component=name)
