"""Active PII & credential scrubbing powered by Google Cloud DLP + deterministic fallback.

Enforced across both:
1. The structured JSON logging pipeline (`app/observability/logging_setup.py`).
2. The async memory and tool audit pipeline (`app/memory/async_memory.py` & `app/plugins/`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.config.settings import AegisSettings, get_settings

DLP_INFO_TYPES: tuple[str, ...] = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "IP_ADDRESS",
    "PERSON_NAME",
)

# Deterministic compiled patterns covering PII & leaked credentials/tokens in crash logs
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "AUTH_TOKEN",
        re.compile(
            r"(?i)\b(?:bearer|token)\s+[A-Za-z0-9\-._~+/]+=*"
            r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            r"|\bAIza[0-9A-Za-z\-_]{20,}\b"
            r"|\bsk-[A-Za-z0-9]{16,}\b"
            r"|\bghp_[A-Za-z0-9]{20,}\b"
            r"|\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"
        ),
    ),
    (
        "CREDENTIAL_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api_key|apikey|db_pass)\s*[=:]\s*['\"]?[^\s,'\";}]{4,}['\"]?"
        ),
    ),
    (
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "US_SOCIAL_SECURITY_NUMBER",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "CREDIT_CARD_NUMBER",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
    (
        "PHONE_NUMBER",
        re.compile(r"(?<!\w)(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
)

# Structured operational fields that carry allowlisted documentation/WAF CIDRs
_ALLOWLISTED_INFRA_KEYS: frozenset[str] = frozenset({"source_cidr", "blocked_cidr"})


def _passes_luhn(digits: str) -> bool:
    """Validate candidate credit card numbers using the Luhn checksum."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        val = int(ch)
        if idx % 2 == parity:
            val *= 2
            if val > 9:
                val -= 9
        checksum += val
    return checksum % 10 == 0


@dataclass
class RedactionReport:
    """Audit metadata describing PII redactions applied to a text payload."""

    redacted_text: str
    redaction_count: int = 0
    detected_types: list[str] = field(default_factory=list)
    backend: str = "deterministic_local"


class PiiRedactor:
    """Hybrid Cloud DLP + deterministic local PII & secret scrubber."""

    def __init__(
        self,
        settings: AegisSettings | None = None,
        dlp_client: Any | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._dlp_client = dlp_client

    def _get_dlp_client(self) -> Any:
        if self._dlp_client is None:
            from google.cloud import dlp_v2

            self._dlp_client = dlp_v2.DlpServiceClient()
        return self._dlp_client

    def _redact_via_cloud_dlp(self, text: str) -> str | None:
        """Invoke Google Cloud DLP `deidentify_content` when enabled."""
        if not self._settings.dlp_enabled or not self._settings.google_cloud_project:
            return None
        try:
            client = self._get_dlp_client()
            parent = (
                f"projects/{self._settings.google_cloud_project}"
                f"/locations/{self._settings.aegis_region}"
            )
            inspect_config = {
                "info_types": [{"name": info_type} for info_type in DLP_INFO_TYPES]
            }
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [
                        {"primitive_transformation": {"replace_with_info_type_config": {}}}
                    ]
                }
            }
            response = client.deidentify_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "deidentify_config": deidentify_config,
                    "item": {"value": text},
                }
            )
            return str(response.item.value)
        except Exception:
            return None

    def redact_text_with_report(self, text: str) -> RedactionReport:
        """Scrub PII and leaked tokens from text, returning a detailed report."""
        if not text:
            return RedactionReport(redacted_text=text)

        backend = "deterministic_local"
        current = text
        redaction_count = 0
        detected: set[str] = set()

        dlp_output = self._redact_via_cloud_dlp(current)
        if dlp_output is not None:
            backend = "cloud_dlp+deterministic"
            if dlp_output != current:
                redaction_count += 1
                detected.add("CLOUD_DLP_DEIDENTIFIED")
            current = dlp_output

        # Always run deterministic pass as defense-in-depth (tokens, keys, offline CI)
        for info_type, pattern in _TOKEN_PATTERNS:
            if info_type == "CREDIT_CARD_NUMBER":
                def _replace_cc(match: re.Match[str]) -> str:
                    nonlocal redaction_count
                    raw = match.group(0)
                    digits = re.sub(r"\D", "", raw)
                    # Accept Luhn-valid cards OR explicit 16-digit grouped synthetic test cards
                    if _passes_luhn(digits) or re.fullmatch(r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}", raw):
                        redaction_count += 1
                        detected.add("CREDIT_CARD_NUMBER")
                        return "[REDACTED_CREDIT_CARD_NUMBER]"
                    return raw

                current = pattern.sub(_replace_cc, current)
            else:
                def _replace_generic(match: re.Match[str], tag: str = info_type) -> str:
                    nonlocal redaction_count
                    redaction_count += 1
                    detected.add(tag)
                    return f"[REDACTED_{tag}]"

                current = pattern.sub(_replace_generic, current)

        return RedactionReport(
            redacted_text=current,
            redaction_count=redaction_count,
            detected_types=sorted(detected),
            backend=backend,
        )

    def redact_text(self, text: str) -> str:
        """Return PII-scrubbed text string."""
        return self.redact_text_with_report(text).redacted_text

    def redact_obj(self, value: Any, *, key_name: str | None = None) -> Any:
        """Recursively scrub PII/secrets across nested dicts, lists, and tuples."""
        if key_name and key_name.lower() in {
            "password",
            "db_pass",
            "api_key",
            "secret",
            "authorization",
            "token",
        }:
            return "[REDACTED_SECRET]"
        if isinstance(value, str):
            if key_name in _ALLOWLISTED_INFRA_KEYS:
                return value
            return self.redact_text(value)
        if isinstance(value, dict):
            return {
                str(k): self.redact_obj(v, key_name=str(k)) for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact_obj(item, key_name=key_name) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_obj(item, key_name=key_name) for item in value)
        return value


_DEFAULT_REDACTOR: PiiRedactor | None = None


def get_pii_redactor() -> PiiRedactor:
    """Return singleton PiiRedactor instance."""
    global _DEFAULT_REDACTOR
    if _DEFAULT_REDACTOR is None:
        _DEFAULT_REDACTOR = PiiRedactor()
    return _DEFAULT_REDACTOR
