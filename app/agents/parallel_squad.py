"""ParallelAgent fan-out executing 3 fast-tier SRE diagnostic specialists concurrently."""

from __future__ import annotations

from google.adk.agents import Agent, ParallelAgent
from google.adk.tools import FunctionTool

from app.config.models import ModelRouterConfig, ModelTier, get_model_router
from app.prompts.constitution import (
    DEPLOYMENT_AUDITOR_INSTRUCTION,
    RUNBOOK_RESEARCHER_INSTRUCTION,
    TELEMETRY_ANALYST_INSTRUCTION,
)
from app.tools.diagnostics_tools import (
    correlate_recent_deployments,
    fetch_service_telemetry_anomalies,
    list_verified_healthy_revisions,
    search_verified_runbooks,
)


def create_parallel_diagnostics_squad(
    router: ModelRouterConfig | None = None,
) -> ParallelAgent:
    """Build ParallelAgent gathering telemetry, deployments, and runbooks simultaneously.

    All three specialists route to `ModelTier.FAST_TRIAGE` (`gemini-2.5-flash`)
    for minimal fan-out latency and write to isolated `output_key` state slots.
    """
    models = router or get_model_router()

    telemetry_analyst = Agent(
        name="telemetry_analyst",
        model=models.create_llm(ModelTier.FAST_TRIAGE),
        generate_content_config=models.generate_config_for(ModelTier.FAST_TRIAGE),
        description=(
            "Fetches latency, error-rate anomalies, and PII-scrubbed error logs "
            "for the impacted microservice."
        ),
        instruction=TELEMETRY_ANALYST_INSTRUCTION,
        tools=[FunctionTool(fetch_service_telemetry_anomalies)],
        output_key="telemetry_findings",
    )

    deployment_change_auditor = Agent(
        name="deployment_change_auditor",
        model=models.create_llm(ModelTier.FAST_TRIAGE),
        generate_content_config=models.generate_config_for(ModelTier.FAST_TRIAGE),
        description=(
            "Audits recent deployment commits and verifies healthy rollback candidates."
        ),
        instruction=DEPLOYMENT_AUDITOR_INSTRUCTION,
        tools=[
            FunctionTool(correlate_recent_deployments),
            FunctionTool(list_verified_healthy_revisions),
        ],
        output_key="deployment_findings",
    )

    runbook_researcher = Agent(
        name="runbook_researcher",
        model=models.create_llm(ModelTier.FAST_TRIAGE),
        generate_content_config=models.generate_config_for(ModelTier.FAST_TRIAGE),
        description=(
            "Retrieves verified SRE runbooks via Vertex AI Search or local vector store."
        ),
        instruction=RUNBOOK_RESEARCHER_INSTRUCTION,
        tools=[FunctionTool(search_verified_runbooks)],
        output_key="runbook_findings",
    )

    return ParallelAgent(
        name="parallel_diagnostics_squad",
        description=(
            "Concurrently gathers telemetry anomalies, recent deployments, healthy "
            "revisions, and verified SRE runbooks in parallel."
        ),
        sub_agents=[
            telemetry_analyst,
            deployment_change_auditor,
            runbook_researcher,
        ],
    )
