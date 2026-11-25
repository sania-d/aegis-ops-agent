"""SequentialAgent pipeline executing Pro-tier root-cause synthesis -> HITL remediation."""

from __future__ import annotations

from google.adk.agents import Agent, SequentialAgent

from app.config.models import ModelRouterConfig, ModelTier, get_model_router
from app.prompts.constitution import (
    MITIGATION_EXECUTOR_INSTRUCTION,
    ROOT_CAUSE_SYNTHESIZER_INSTRUCTION,
)
from app.schemas.incidents import RootCauseSynthesis
from app.tools.diagnostics_tools import (
    calculate_blast_radius_estimate,
    list_verified_healthy_revisions,
)
from app.tools.remediation_tools import (
    canary_rollback_tool,
    send_war_room_incident_update,
    waf_rate_limit_tool,
)


def create_remediation_pipeline(
    router: ModelRouterConfig | None = None,
) -> SequentialAgent:
    """Build SequentialAgent combining structured Pro-tier RCA and HITL execution."""
    models = router or get_model_router()

    root_cause_synthesizer = Agent(
        name="root_cause_synthesizer",
        model=models.create_llm(ModelTier.DEEP_REASONING),
        generate_content_config=models.generate_config_for(ModelTier.DEEP_REASONING),
        description=(
            "Synthesizes telemetry, deployment, and runbook evidence into a strict "
            "Pydantic RootCauseSynthesis assessment."
        ),
        instruction=ROOT_CAUSE_SYNTHESIZER_INSTRUCTION,
        output_schema=RootCauseSynthesis,
        output_key="root_cause_assessment",
    )

    mitigation_executor = Agent(
        name="mitigation_executor",
        model=models.create_llm(ModelTier.DEEP_REASONING),
        generate_content_config=models.generate_config_for(ModelTier.DEEP_REASONING),
        description=(
            "Quantifies blast radius and proposes or executes HITL-guarded canary "
            "rollbacks, WAF rate limits, and PII-scrubbed war-room updates."
        ),
        instruction=MITIGATION_EXECUTOR_INSTRUCTION,
        tools=[
            calculate_blast_radius_estimate,
            list_verified_healthy_revisions,
            canary_rollback_tool,
            waf_rate_limit_tool,
            send_war_room_incident_update,
        ],
    )

    return SequentialAgent(
        name="remediation_pipeline",
        description=(
            "Deterministic 2-stage remediation workflow: structured Pro-tier root-cause "
            "synthesis followed by blast-radius quantification and HITL-gated execution."
        ),
        sub_agents=[root_cause_synthesizer, mitigation_executor],
    )
