"""Institutional long-term memory recall tool complementing ADK PreloadMemoryTool."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.memory.async_memory import get_memory_manager
from app.observability.tracing import get_tracer
from app.schemas.incidents import VALID_SERVICES, MemoryRecallQuery, ToolErrorEnvelope

tracer = get_tracer("aegis_ops.tools.memory")


async def recall_historical_incident_lessons(
    service_name: str,
    symptom_keywords: str,
) -> dict[str, Any]:
    """Query distilled, PII-redacted past incident root causes and winning mitigations.

    Retrieves cross-session institutional memory consolidated asynchronously from
    prior war-room investigations to accelerate triage of recurring failure modes.

    Args:
        service_name: Microservice to search lessons for (`checkout-api`,
            `auth-gateway`, `catalog-search`, or `payments-ledger`).
        symptom_keywords: Space-separated keywords describing current symptoms or
            error patterns (e.g., `sync lock db pool 503`).

    Returns:
        A JSON-serializable dictionary containing `status`, `service_name`, and
        `historical_lessons` (ranked list of past incident IDs, root causes, and
        winning mitigations); or a structured `ToolErrorEnvelope` on invalid input.
    """
    with tracer.start_as_current_span("tool.recall_historical_incident_lessons") as span:
        try:
            validated = MemoryRecallQuery(
                service_name=service_name,  # type: ignore[arg-type]
                symptom_keywords=symptom_keywords,
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            return ToolErrorEnvelope(
                error_code="INVALID_MEMORY_QUERY",
                message=f"Invalid memory recall parameter: {first.get('msg')}",
                recovery_instructions=(
                    "Provide a valid service name and at least 2 characters of symptom keywords."
                ),
                suggested_next_tool="recall_historical_incident_lessons",
                valid_options=list(VALID_SERVICES),
            ).model_dump()

        span.set_attribute("aegis.service_name", validated.service_name)
        lessons = await get_memory_manager().recall_lessons(
            service_name=validated.service_name,
            symptom_keywords=validated.symptom_keywords,
            limit=3,
        )
        return {
            "status": "success",
            "service_name": validated.service_name,
            "lesson_count": len(lessons),
            "historical_lessons": lessons,
        }
