"""Strategic model routing configuration separating fast triage vs. deep reasoning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from google.adk.models import Gemini
from google.genai import types

from app.config.settings import AegisSettings, get_settings


class ModelTier(StrEnum):
    """Cognitive tiers used for intentional cost/latency/quality model routing."""

    FAST_TRIAGE = "fast_triage"
    DEEP_REASONING = "deep_reasoning"
    DETERMINISTIC_JUDGE = "deterministic_judge"
    EVENT_COMPACTION = "event_compaction"


@dataclass(frozen=True)
class ModelRouterConfig:
    """Centralized model routing registry for AegisOps multi-agent hierarchy."""

    fast_model_name: str
    reasoning_model_name: str
    judge_model_name: str
    retry_attempts: int = 3

    def _retry_options(self) -> types.HttpRetryOptions:
        return types.HttpRetryOptions(attempts=self.retry_attempts)

    def model_name_for(self, tier: ModelTier) -> str:
        """Return the concrete Gemini model identifier for a routing tier."""
        if tier is ModelTier.DEEP_REASONING:
            return self.reasoning_model_name
        if tier is ModelTier.DETERMINISTIC_JUDGE:
            return self.judge_model_name
        return self.fast_model_name

    def create_llm(self, tier: ModelTier) -> Gemini:
        """Instantiate an ADK Gemini model wrapper configured with retry policy."""
        return Gemini(
            model=self.model_name_for(tier),
            retry_options=self._retry_options(),
        )

    def generate_config_for(self, tier: ModelTier) -> types.GenerateContentConfig:
        """Return tailored generation hyperparameters per cognitive tier."""
        if tier is ModelTier.DETERMINISTIC_JUDGE:
            return types.GenerateContentConfig(temperature=0.0, max_output_tokens=1024)
        if tier is ModelTier.DEEP_REASONING:
            return types.GenerateContentConfig(temperature=0.1, max_output_tokens=4096)
        return types.GenerateContentConfig(temperature=0.1, max_output_tokens=2048)

    def routing_table(self) -> dict[str, dict[str, Any]]:
        """Expose explicit documentation of agent-to-model routing decisions."""
        return {
            "incident_commander_coordinator": {
                "tier": ModelTier.FAST_TRIAGE.value,
                "model": self.fast_model_name,
                "rationale": "Low-latency intent classification and sub-agent orchestration.",
            },
            "telemetry_analyst": {
                "tier": ModelTier.FAST_TRIAGE.value,
                "model": self.fast_model_name,
                "rationale": "High-speed parallel anomaly extraction from telemetry payloads.",
            },
            "deployment_change_auditor": {
                "tier": ModelTier.FAST_TRIAGE.value,
                "model": self.fast_model_name,
                "rationale": "Parallel commit/release diff extraction.",
            },
            "runbook_researcher": {
                "tier": ModelTier.FAST_TRIAGE.value,
                "model": self.fast_model_name,
                "rationale": "Fast grounded retrieval from Vertex AI Search / runbook store.",
            },
            "root_cause_synthesizer": {
                "tier": ModelTier.DEEP_REASONING.value,
                "model": self.reasoning_model_name,
                "rationale": "Cross-signal causal reasoning across metrics, deploys, and runbooks.",
            },
            "mitigation_executor": {
                "tier": ModelTier.DEEP_REASONING.value,
                "model": self.reasoning_model_name,
                "rationale": "High-stakes remediation planning, blast-radius verification, and HITL.",
            },
            "postmortem_drafter": {
                "tier": ModelTier.DEEP_REASONING.value,
                "model": self.reasoning_model_name,
                "rationale": "Structured blameless SRE postmortem synthesis.",
            },
            "sre_quality_critic": {
                "tier": ModelTier.DETERMINISTIC_JUDGE.value,
                "model": self.judge_model_name,
                "temperature": 0.0,
                "rationale": "Deterministic zero-temperature self-evaluation of postmortem grounding.",
            },
            "events_compaction_summarizer": {
                "tier": ModelTier.EVENT_COMPACTION.value,
                "model": self.fast_model_name,
                "rationale": "Cost-efficient sliding-window conversation history compaction.",
            },
        }


def get_model_router(settings: AegisSettings | None = None) -> ModelRouterConfig:
    """Create a ModelRouterConfig from the active AegisSettings."""
    cfg = settings or get_settings()
    return ModelRouterConfig(
        fast_model_name=cfg.fast_model,
        reasoning_model_name=cfg.reasoning_model,
        judge_model_name=cfg.judge_model,
    )
