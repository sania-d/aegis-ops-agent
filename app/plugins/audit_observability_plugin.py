"""Structured Intent-vs-Outcome audit logging + OpenTelemetry span plugin for ADK."""

from __future__ import annotations

import time
import uuid
from typing import Any

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools import BaseTool, ToolContext
from google.genai import types
from opentelemetry.trace import Status, StatusCode

from app.observability.logging_setup import get_logger
from app.observability.tracing import get_tracer
from app.schemas.incidents import ToolErrorEnvelope
from app.security.pii_redactor import PiiRedactor, get_pii_redactor

logger = get_logger("audit_observability_plugin")
tracer = get_tracer("aegis_ops.plugins.audit")


class IntentOutcomeAuditPlugin(BasePlugin):
    """Records correlated Intent (before) vs. Outcome (after) JSON logs & OTel spans."""

    def __init__(
        self,
        *,
        name: str = "aegis_intent_outcome_audit",
        redactor: PiiRedactor | None = None,
    ) -> None:
        super().__init__(name=name)
        self._redactor = redactor or get_pii_redactor()
        self._active_tool_spans: dict[str, Any] = {}
        self._active_agent_spans: dict[str, Any] = {}
        self._agent_starts: dict[str, float] = {}

    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> types.Content | None:
        """Record agent turn intent and start an OpenTelemetry span."""
        turn_id = str(uuid.uuid4())
        key = f"{callback_context.invocation_id}:{agent.name}"
        self._agent_starts[key] = time.perf_counter()
        span = tracer.start_span(f"agent.run.{agent.name}")
        span.set_attribute("aegis.agent.name", agent.name)
        span.set_attribute("aegis.turn_id", turn_id)
        self._active_agent_spans[key] = (turn_id, span)

        logger.info(
            "agent_turn_intent",
            event_type="agent_intent",
            action_id=turn_id,
            agent_name=agent.name,
            invocation_id=callback_context.invocation_id,
        )
        return None

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> types.Content | None:
        """Record agent turn outcome with latency and close its OpenTelemetry span."""
        key = f"{callback_context.invocation_id}:{agent.name}"
        start = self._agent_starts.pop(key, time.perf_counter())
        duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
        turn_id, span = self._active_agent_spans.pop(key, ("unknown", None))

        if span is not None:
            span.set_attribute("aegis.duration_ms", duration_ms)
            span.set_status(Status(StatusCode.OK))
            span.end()

        logger.info(
            "agent_turn_outcome",
            event_type="agent_outcome",
            action_id=turn_id,
            agent_name=agent.name,
            invocation_id=callback_context.invocation_id,
            outcome_status="completed",
            intent_matched_outcome=True,
            duration_ms=duration_ms,
        )
        return None

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        """Emit structured `agent_intent` log & start OTel span before tool execution."""
        action_id = str(uuid.uuid4())
        state_key = f"temp:audit_action_id:{tool.name}"
        start_key = f"temp:audit_start:{action_id}"
        tool_context.state[state_key] = action_id
        tool_context.state[start_key] = time.perf_counter()

        span = tracer.start_span(f"tool.exec.{tool.name}")
        span.set_attribute("aegis.action_id", action_id)
        span.set_attribute("aegis.tool.name", tool.name)
        span.set_attribute("aegis.agent.name", tool_context.agent_name)
        self._active_tool_spans[action_id] = span

        redacted_args = self._redactor.redact_obj(tool_args)
        session = getattr(tool_context, "session", None)
        logger.info(
            "tool_action_intent",
            event_type="agent_intent",
            action_id=action_id,
            agent_name=tool_context.agent_name,
            intended_tool=tool.name,
            intended_args=redacted_args,
            session_id=getattr(session, "id", "unknown"),
        )
        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Emit correlated `agent_outcome` log comparing actual result against intent."""
        state_key = f"temp:audit_action_id:{tool.name}"
        action_id = str(tool_context.state.get(state_key, "unknown"))
        start = float(
            tool_context.state.get(f"temp:audit_start:{action_id}", time.perf_counter())
        )
        duration_ms = round((time.perf_counter() - start) * 1000.0, 2)

        outcome_status = (
            str(result.get("status", "success"))
            if isinstance(result, dict)
            else "success"
        )
        intent_matched = outcome_status == "success"
        redacted_result = self._redactor.redact_obj(result)

        span = self._active_tool_spans.pop(action_id, None)
        if span is not None:
            span.set_attribute("aegis.outcome_status", outcome_status)
            span.set_attribute("aegis.intent_matched_outcome", intent_matched)
            span.set_attribute("aegis.duration_ms", duration_ms)
            span.set_status(
                Status(StatusCode.OK if intent_matched else StatusCode.ERROR)
            )
            span.end()

        session = getattr(tool_context, "session", None)
        logger.info(
            "tool_action_outcome",
            event_type="agent_outcome",
            action_id=action_id,
            agent_name=tool_context.agent_name,
            executed_tool=tool.name,
            outcome_status=outcome_status,
            intent_matched_outcome=intent_matched,
            actual_outcome=redacted_result,
            duration_ms=duration_ms,
            session_id=getattr(session, "id", "unknown"),
        )
        return None

    async def on_tool_error_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> dict[str, Any] | None:
        """Log failed outcome and convert unexpected exceptions into guided recovery envelopes."""
        state_key = f"temp:audit_action_id:{tool.name}"
        action_id = str(tool_context.state.get(state_key, "unknown"))
        start = float(
            tool_context.state.get(f"temp:audit_start:{action_id}", time.perf_counter())
        )
        duration_ms = round((time.perf_counter() - start) * 1000.0, 2)

        span = self._active_tool_spans.pop(action_id, None)
        if span is not None:
            span.set_attribute("aegis.outcome_status", "unhandled_exception")
            span.set_attribute("aegis.error_type", type(error).__name__)
            span.set_status(Status(StatusCode.ERROR, description=type(error).__name__))
            span.end()

        logger.error(
            "tool_action_error_outcome",
            event_type="agent_outcome",
            action_id=action_id,
            agent_name=tool_context.agent_name,
            executed_tool=tool.name,
            outcome_status="unhandled_exception",
            intent_matched_outcome=False,
            error_type=type(error).__name__,
            duration_ms=duration_ms,
        )
        return ToolErrorEnvelope(
            error_code="TOOL_EXECUTION_EXCEPTION",
            message=f"Tool '{tool.name}' encountered an unexpected {type(error).__name__}.",
            recovery_instructions=(
                "Verify parameter values and try an alternative diagnostic tool or "
                "escalate to the on-call SRE without repeating identical arguments."
            ),
            suggested_next_tool=None,
            valid_options=[],
        ).model_dump()
