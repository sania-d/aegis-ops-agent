"""Google Cloud Model Armor integration with deterministic prompt-injection defense.

Screens three critical boundaries:
1. User prompts (`before_model_callback`) — blocks direct jailbreaks and secret exfiltration.
2. External tool outputs (`after_tool_callback`) — neutralizes indirect prompt injections
   embedded inside untrusted production crash logs or HTTP headers.
3. Model outputs (`after_model_callback`) — blocks leaked secrets or policy violations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.config.settings import AegisSettings, get_settings

_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "PROMPT_INJECTION_OVERRIDE",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|above)\s+"
            r"(?:instructions?|prompts?|rules?|constraints?)\b"
        ),
    ),
    (
        "BYPASS_SAFETY_GATE",
        re.compile(
            r"(?i)\b(?:bypass|skip|disable|override)\s+(?:human|hitl|approval|confirmation|"
            r"guardrails?|waf\s+rate\s+limits?|safety\s+checks?|change\s+freeze)\b"
        ),
    ),
    (
        "SECRET_EXFILTRATION",
        re.compile(
            r"(?i)\b(?:print|dump|reveal|exfiltrate|expose|echo|return)\s+(?:the\s+)?"
            r"(?:db_pass|secret|api[_\s]?key|env(?:ironment)?\s+variables?|credentials?|bearer\s+token)\b"
        ),
    ),
    (
        "SYSTEM_PROMPT_EXTRACTION",
        re.compile(
            r"(?i)\b(?:reveal|repeat|print|output)\s+(?:your\s+)?(?:full\s+)?"
            r"(?:system\s+prompt|constitution|hidden\s+instructions?)\b"
        ),
    ),
    (
        "DESTRUCTIVE_SHELL_INJECTION",
        re.compile(r"(?i)(?:;\s*rm\s+-rf\b|\bdrop\s+table\b|\bcurl\s+[^\n]+\|\s*(?:sh|bash)\b)"),
    ),
)


@dataclass(frozen=True)
class GuardrailVerdict:
    """Result returned by ModelArmorScanner."""

    allowed: bool
    category: str
    matched_rules: list[str] = field(default_factory=list)
    sanitized_text: str = ""
    backend: str = "deterministic_local"


class ModelArmorScanner:
    """Dual-mode security scanner using Google Cloud Model Armor + deterministic rules."""

    def __init__(
        self,
        settings: AegisSettings | None = None,
        client: Any | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            from google.api_core.client_options import ClientOptions
            from google.cloud import modelarmor_v1

            endpoint = f"modelarmor.{self._settings.aegis_region}.rep.googleapis.com"
            self._client = modelarmor_v1.ModelArmorClient(
                client_options=ClientOptions(api_endpoint=endpoint)
            )
        return self._client

    def _check_cloud_model_armor(self, text: str, *, is_response: bool) -> list[str]:
        """Call Google Cloud Model Armor API when a template is configured."""
        template = self._settings.model_armor_template
        if not template:
            return []
        try:
            from google.cloud import modelarmor_v1

            client = self._get_client()
            if is_response:
                request = modelarmor_v1.SanitizeModelResponseRequest(
                    name=template,
                    model_response_data=modelarmor_v1.DataItem(text=text),
                )
                result = client.sanitize_model_response(request=request)
            else:
                request = modelarmor_v1.SanitizeUserPromptRequest(
                    name=template,
                    user_prompt_data=modelarmor_v1.DataItem(text=text),
                )
                result = client.sanitize_user_prompt(request=request)

            sanitization = result.sanitization_result
            if (
                sanitization
                and sanitization.filter_match_state
                == modelarmor_v1.FilterMatchState.MATCH_FOUND
            ):
                return ["MODEL_ARMOR_MATCH_FOUND"]
            return []
        except Exception:
            # Deterministic rules still enforce baseline security if API is unreachable
            return []

    def scan_text(self, text: str, *, is_response: bool = False) -> GuardrailVerdict:
        """Evaluate prompt, tool payload, or model response against security policies."""
        if not text:
            return GuardrailVerdict(allowed=True, category="clean", sanitized_text=text)

        matched: list[str] = []
        backend = "deterministic_local"

        cloud_matches = self._check_cloud_model_armor(text, is_response=is_response)
        if self._settings.model_armor_template:
            backend = "cloud_model_armor+deterministic"
        matched.extend(cloud_matches)

        sanitized = text
        for rule_name, pattern in _INJECTION_RULES:
            if pattern.search(sanitized):
                matched.append(rule_name)
                sanitized = pattern.sub(f"[BLOCKED_BY_GUARDRAIL:{rule_name}]", sanitized)

        if matched:
            return GuardrailVerdict(
                allowed=False,
                category="security_policy_violation",
                matched_rules=sorted(set(matched)),
                sanitized_text=sanitized,
                backend=backend,
            )

        return GuardrailVerdict(
            allowed=True,
            category="clean",
            matched_rules=[],
            sanitized_text=text,
            backend=backend,
        )


_DEFAULT_SCANNER: ModelArmorScanner | None = None


def get_model_armor_scanner() -> ModelArmorScanner:
    """Return singleton ModelArmorScanner."""
    global _DEFAULT_SCANNER
    if _DEFAULT_SCANNER is None:
        _DEFAULT_SCANNER = ModelArmorScanner()
    return _DEFAULT_SCANNER
