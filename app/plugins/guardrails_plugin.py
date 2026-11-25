"""Security guardrails (Model Armor) & Self-Evaluation policy plugins for ADK App."""

from __future__ import annotations

import re
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools import BaseTool, ToolContext
from google.genai import types

from app.config.settings import AegisSettings, get_settings
from app.observability.logging_setup import get_logger
from app.observability.tracing import get_tracer
from app.security.model_armor import ModelArmorScanner, get_model_armor_scanner
from app.security.pii_redactor import PiiRedactor, get_pii_redactor

logger = get_logger("guardrails_plugin")
tracer = get_tracer("aegis_ops.plugins.guardrails")

_UNSAFE_POLICY_CLAIMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "FORBIDDEN_WAF_DISABLE",
        re.compile(r"(?i)\b(?:disabled|turned\s+off|removed)\s+(?:all\s+)?waf\s+rate\s+limits?\b"),
    ),
    (
        "FORBIDDEN_SECRET_EXPOSURE",
        re.compile(r"(?i)\bDB_PASS\s*=\s*[^\s]+|\bAIza[0-9A-Za-z\-_]{20,}\b"),
    ),
)


def _extract_latest_user_text(llm_request: LlmRequest) -> str:
    """Return text from the most recent user content message in an LlmRequest."""
    contents = getattr(llm_request, "contents", None) or []
    for content in reversed(contents):
        if getattr(content, "role", None) == "user":
            parts = getattr(content, "parts", None) or []
            texts = [part.text for part in parts if getattr(part, "text", None)]
            if texts:
                return "\n".join(texts)
    return ""


def _extract_response_text(llm_response: LlmResponse) -> str:
    """Return concatenated text parts from an LlmResponse."""
    content = getattr(llm_response, "content", None)
    if content is None or not getattr(content, "parts", None):
        return ""
    return "\n".join(
        part.text for part in content.parts if getattr(part, "text", None)
    )


class ModelArmorGuardrailPlugin(BasePlugin):
    """Global ADK plugin enforcing Google Cloud Model Armor & log-poisoning defense."""

    def __init__(
        self,
        *,
        name: str = "aegis_model_armor_guardrail",
        scanner: ModelArmorScanner | None = None,
        redactor: PiiRedactor | None = None,
    ) -> None:
        super().__init__(name=name)
        self._scanner = scanner or get_model_armor_scanner()
        self._redactor = redactor or get_pii_redactor()

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> LlmResponse | None:
        """Screen incoming user prompts before LLM inference."""
        user_text = _extract_latest_user_text(llm_request)
        if not user_text:
            return None

        with tracer.start_as_current_span("guardrail.before_model") as span:
            verdict = self._scanner.scan_text(user_text, is_response=False)
            span.set_attribute("aegis.guardrail.allowed", verdict.allowed)
            span.set_attribute("aegis.guardrail.backend", verdict.backend)

            if not verdict.allowed:
                logger.warning(
                    "guardrail_blocked_prompt",
                    agent_name=callback_context.agent_name,
                    matched_rules=verdict.matched_rules,
                    backend=verdict.backend,
                )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part.from_text(
                                text=(
                                    "Request blocked by AegisOps Model Armor security guardrail "
                                    f"(matched policies: {', '.join(verdict.matched_rules)}). "
                                    "I cannot bypass Human-in-the-Loop approvals, disable WAF "
                                    "protections, or expose credentials. Please rephrase with "
                                    "a legitimate incident triage or remediation request."
                                )
                            )
                        ],
                    )
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
        """Sanitize tool outputs to neutralize indirect prompt injection in crash logs."""
        if not isinstance(result, dict):
            return None

        with tracer.start_as_current_span("guardrail.after_tool_sanitize") as span:
            span.set_attribute("aegis.tool_name", tool.name)
            flagged_rules: set[str] = set()

            def _sanitize_value(val: Any) -> Any:
                if isinstance(val, str):
                    verdict = self._scanner.scan_text(val, is_response=False)
                    if not verdict.allowed:
                        flagged_rules.update(verdict.matched_rules)
                        return verdict.sanitized_text
                    return val
                if isinstance(val, dict):
                    return {k: _sanitize_value(v) for k, v in val.items()}
                if isinstance(val, list):
                    return [_sanitize_value(item) for item in val]
                return val

            sanitized_result = _sanitize_value(result)
            if flagged_rules:
                logger.warning(
                    "indirect_prompt_injection_neutralized",
                    tool_name=tool.name,
                    agent_name=tool_context.agent_name,
                    matched_rules=sorted(flagged_rules),
                )
                sanitized_result["security_guardrail_notice"] = (
                    "Untrusted instruction-like content detected inside external tool output "
                    f"({', '.join(sorted(flagged_rules))}) and neutralized by Model Armor guardrail."
                )
                return sanitized_result
        return None

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> LlmResponse | None:
        """Filter model responses via Model Armor and scrub any accidental PII/tokens."""
        response_text = _extract_response_text(llm_response)
        if not response_text:
            return None

        with tracer.start_as_current_span("guardrail.after_model") as span:
            verdict = self._scanner.scan_text(response_text, is_response=True)
            redaction = self._redactor.redact_text_with_report(
                verdict.sanitized_text if not verdict.allowed else response_text
            )
            span.set_attribute("aegis.guardrail.allowed", verdict.allowed)
            span.set_attribute("aegis.pii.redactions", redaction.redaction_count)

            if not verdict.allowed or redaction.redaction_count > 0:
                logger.warning(
                    "guardrail_sanitized_model_response",
                    agent_name=callback_context.agent_name,
                    matched_rules=verdict.matched_rules,
                    pii_redactions=redaction.redaction_count,
                )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=redaction.redacted_text)],
                    )
                )
        return None


class PolicySelfEvalPlugin(BasePlugin):
    """Self-evaluation guardrail validating groundedness, PII safety, and change-freeze rules."""

    def __init__(
        self,
        *,
        name: str = "aegis_policy_self_eval",
        settings: AegisSettings | None = None,
        redactor: PiiRedactor | None = None,
    ) -> None:
        super().__init__(name=name)
        self._settings = settings or get_settings()
        self._redactor = redactor or get_pii_redactor()

    def evaluate_response_text(
        self, text: str, state: dict[str, Any]
    ) -> dict[str, Any]:
        """Run deterministic policy self-evaluation checks on an agent response."""
        violations: list[str] = []

        for rule_name, pattern in _UNSAFE_POLICY_CLAIMS:
            if pattern.search(text):
                violations.append(rule_name)

        pii_report = self._redactor.redact_text_with_report(text)
        if pii_report.redaction_count > 0:
            violations.append(
                f"PII_DETECTED:{','.join(pii_report.detected_types)}"
            )

        # Ensure agent does not falsely claim a mutation executed when none was recorded
        claimed_exec = bool(
            re.search(
                r"(?i)\b(?:rollback\s+(?:completed|executed\s+successfully)|waf\s+rule\s+applied\s+successfully)\b",
                text,
            )
        )
        if claimed_exec and not state.get("last_mitigation_action"):
            violations.append("UNGROUNDED_MUTATION_CLAIM")

        return {
            "passed": len(violations) == 0,
            "violations": violations,
            "sanitized_text": pii_report.redacted_text,
        }

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> LlmResponse | None:
        """Audit model text responses against domain policies before delivery."""
        response_text = _extract_response_text(llm_response)
        if not response_text:
            return None

        # Skip structured JSON outputs destined for internal state keys
        stripped = response_text.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            return None

        with tracer.start_as_current_span("guardrail.policy_self_eval") as span:
            raw_state: Any = callback_context.state
            state_dict: dict[str, Any] = (
                raw_state.to_dict()
                if hasattr(raw_state, "to_dict")
                else dict(raw_state)
            )
            result = self.evaluate_response_text(response_text, state_dict)
            span.set_attribute("aegis.self_eval.passed", result["passed"])

            logger.info(
                "policy_self_eval_verdict",
                agent_name=callback_context.agent_name,
                passed=result["passed"],
                violations=result["violations"],
            )
            if not result["passed"]:
                safe_text = result["sanitized_text"]
                if "UNGROUNDED_MUTATION_CLAIM" in result["violations"]:
                    safe_text = (
                        f"{safe_text}\n\n[Policy Self-Eval Notice: No production mutation "
                        "has been confirmed executed in the current session state; explicit "
                        "Human-in-the-Loop approval is required before changes take effect.]"
                    )
                if "FORBIDDEN_WAF_DISABLE" in result["violations"]:
                    safe_text = (
                        "Policy Self-Eval Blocked Response: AegisOps cannot disable "
                        "production WAF protections or claim they were disabled."
                    )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=safe_text)],
                    )
                )
        return None
