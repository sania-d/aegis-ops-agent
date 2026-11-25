"""LoopAgent implementing iterative blameless SRE postmortem drafting & self-critique."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any

from google.adk.agents import Agent, BaseAgent, LoopAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions

from app.config.models import ModelRouterConfig, ModelTier, get_model_router
from app.prompts.constitution import (
    POSTMORTEM_CRITIC_INSTRUCTION,
    POSTMORTEM_DRAFTER_INSTRUCTION,
)
from app.schemas.incidents import PostmortemCritique


class PostmortemEscalationChecker(BaseAgent):
    """Custom BaseAgent terminating the refinement LoopAgent once critic passes."""

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        raw_critique: Any = ctx.session.state.get("postmortem_critique")
        parsed: dict[str, Any] = {}
        if isinstance(raw_critique, dict):
            parsed = raw_critique
        elif isinstance(raw_critique, str):
            try:
                parsed = json.loads(raw_critique)
            except json.JSONDecodeError:
                parsed = {}

        passed = (
            parsed.get("grade") == "pass"
            and parsed.get("grounding_verified") is True
            and parsed.get("pii_free") is True
        )
        if passed:
            yield Event(author=self.name, actions=EventActions(escalate=True))
        else:
            yield Event(author=self.name)


def create_postmortem_refinement_loop(
    router: ModelRouterConfig | None = None,
    *,
    max_iterations: int = 3,
) -> LoopAgent:
    """Build LoopAgent iterating Pro drafter -> zero-temp Flash critic -> escalation check."""
    models = router or get_model_router()

    postmortem_drafter = Agent(
        name="postmortem_drafter",
        model=models.create_llm(ModelTier.DEEP_REASONING),
        generate_content_config=models.generate_config_for(ModelTier.DEEP_REASONING),
        description="Drafts and revises a blameless 5-section SRE postmortem.",
        instruction=POSTMORTEM_DRAFTER_INSTRUCTION,
        output_key="postmortem_draft",
    )

    sre_quality_critic = Agent(
        name="sre_quality_critic",
        model=models.create_llm(ModelTier.DETERMINISTIC_JUDGE),
        generate_content_config=models.generate_config_for(
            ModelTier.DETERMINISTIC_JUDGE
        ),
        description=(
            "Zero-temperature self-evaluation judge checking postmortem completeness, "
            "evidence grounding, and PII cleanliness."
        ),
        instruction=POSTMORTEM_CRITIC_INSTRUCTION,
        output_schema=PostmortemCritique,
        output_key="postmortem_critique",
    )

    escalation_checker = PostmortemEscalationChecker(
        name="postmortem_escalation_checker",
        description="Stops the postmortem LoopAgent when quality critique passes.",
    )

    return LoopAgent(
        name="postmortem_refinement_loop",
        description=(
            "Iteratively drafts and self-evaluates a blameless SRE postmortem until "
            "grounding and PII-free criteria pass."
        ),
        sub_agents=[postmortem_drafter, sre_quality_critic, escalation_checker],
        max_iterations=max_iterations,
    )
