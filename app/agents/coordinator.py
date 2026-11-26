"""Root Coordinator LlmAgent orchestrating parallel triage, remediation, and postmortems."""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.adk.tools import FunctionTool
from google.adk.tools.preload_memory_tool import PreloadMemoryTool

from app.agents.postmortem_loop import create_postmortem_refinement_loop
from app.agents.remediation_pipeline import create_remediation_pipeline
from app.config.models import ModelRouterConfig, ModelTier, get_model_router
from app.memory.async_memory import schedule_async_memory_consolidation
from app.prompts.constitution import COORDINATOR_INSTRUCTION
from app.tools.memory_tools import recall_historical_incident_lessons

DEFAULT_SESSION_STATE: dict[str, str] = {
    "active_incident_id": "unassigned",
    "active_service": "unassigned",
    "historical_lessons_hint": (
        "Not yet loaded; invoke recall_historical_incident_lessons when a service is identified."
    ),
    "telemetry_findings": "Not yet collected.",
    "deployment_findings": "Not yet collected.",
    "runbook_findings": "Not yet collected.",
    "root_cause_assessment": "Not yet synthesized.",
    "postmortem_draft": "No draft generated yet.",
    "postmortem_critique": "Initial iteration — no prior critique.",
}


async def initialize_incident_state(callback_context: CallbackContext) -> None:
    """Initialize required template state keys before first turn to prevent KeyErrors."""
    state = callback_context.state
    for key, default_val in DEFAULT_SESSION_STATE.items():
        if key not in state:
            state[key] = default_val
    return None


def create_incident_commander(
    router: ModelRouterConfig | None = None,
) -> Agent:
    """Create the root Coordinator agent wiring all multi-agent patterns and memory hooks."""
    models = router or get_model_router()

    return Agent(
        name="incident_commander_coordinator",
        model=models.create_llm(ModelTier.FAST_TRIAGE),
        generate_content_config=models.generate_config_for(ModelTier.FAST_TRIAGE),
        description=(
            "AegisOps Incident Commander Coordinator routing SRE triage, parallel "
            "diagnostics, HITL-guarded remediation, and blameless postmortems."
        ),
        instruction=COORDINATOR_INSTRUCTION,
        tools=[
            PreloadMemoryTool(),
            FunctionTool(recall_historical_incident_lessons),
        ],
        sub_agents=[
            create_remediation_pipeline(models),
            create_postmortem_refinement_loop(models),
        ],
        before_agent_callback=initialize_incident_state,
        after_agent_callback=schedule_async_memory_consolidation,
    )
