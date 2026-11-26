"""SequentialAgent fan-out/fan-in pipeline: Parallel Diagnostics -> Pro RCA -> HITL Mitigation."""

from __future__ import annotations

from google.adk.agents import Agent, SequentialAgent
from google.adk.tools import FunctionTool

from app.agents.parallel_squad import create_parallel_diagnostics_squad
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
    """Build deterministic fan-out/fan-in SequentialAgent.

    Stage 1 (`ParallelAgent`, Flash tier): Concurrent telemetry, deployment, and runbook gathering.
    Stage 2 (`root_cause_synthesizer`, Pro tier): Structured `RootCauseSynthesis` fan-in.
    Stage 3 (`mitigation_executor`, Pro tier): Blast-radius check, HITL-gated remediation, and final brief.
    """
    models = router or get_model_router()

    parallel_diagnostics = create_parallel_diagnostics_squad(models)

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
            "Quantifies blast radius, verifies healthy revisions, proposes or triggers "
            "HITL-guarded remediation, and produces the unified final SRE incident brief."
        ),
        instruction=MITIGATION_EXECUTOR_INSTRUCTION,
        tools=[
            FunctionTool(calculate_blast_radius_estimate),
            FunctionTool(list_verified_healthy_revisions),
            canary_rollback_tool,
            waf_rate_limit_tool,
            FunctionTool(send_war_room_incident_update),
        ],
    )

    return SequentialAgent(
        name="remediation_pipeline",
        description=(
            "End-to-end incident triage and guarded remediation pipeline: runs parallel "
            "Flash diagnostics (telemetry, deployments, runbooks), synthesizes a structured "
            "Pro-tier root cause, calculates blast radius, and enforces HITL confirmation."
        ),
        sub_agents=[
            parallel_diagnostics,
            root_cause_synthesizer,
            mitigation_executor,
        ],
    )
