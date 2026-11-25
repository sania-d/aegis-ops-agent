"""Unit tests for Multi-Agent Topology, Strategic Model Routing, Compaction, and Async Memory."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.adk.agents import LoopAgent, ParallelAgent, SequentialAgent

from app.agent import create_aegis_app
from app.agents.postmortem_loop import PostmortemEscalationChecker
from app.config.models import ModelTier, get_model_router
from app.config.settings import AegisSettings
from app.memory.async_memory import AsyncIncidentMemoryManager, IncidentLessonRecord


def test_multi_agent_patterns_strategic_routing_and_app_configs() -> None:
    settings = AegisSettings(AEGIS_ENV="test")
    root_agent, adk_app = create_aegis_app(settings)

    # Verify App-level Compaction, Context Cache, Resumability, and Global Plugins
    assert adk_app.name == "app"
    assert adk_app.events_compaction_config is not None
    assert adk_app.events_compaction_config.compaction_interval == 10
    assert adk_app.events_compaction_config.token_threshold == 12000
    assert adk_app.context_cache_config is not None
    assert adk_app.context_cache_config.min_tokens == 2048
    assert adk_app.resumability_config is not None
    assert adk_app.resumability_config.is_resumable is True

    plugin_names = {p.name for p in adk_app.plugins}
    assert {
        "aegis_constitution_plugin",
        "aegis_model_armor_guardrail",
        "aegis_policy_self_eval",
        "aegis_intent_outcome_audit",
        "aegis_reflect_retry_plugin",
    }.issubset(plugin_names)

    # Verify Multi-Agent Patterns
    sub_by_name = {agent.name: agent for agent in root_agent.sub_agents}
    assert isinstance(sub_by_name["parallel_diagnostics_squad"], ParallelAgent)
    assert isinstance(sub_by_name["remediation_pipeline"], SequentialAgent)
    assert isinstance(sub_by_name["postmortem_refinement_loop"], LoopAgent)

    # Verify distinct output_keys on ParallelAgent to prevent race conditions
    parallel_agents = sub_by_name["parallel_diagnostics_squad"].sub_agents
    output_keys = [a.output_key for a in parallel_agents]
    assert len(output_keys) == len(set(output_keys)) == 3

    # Verify Strategic Model Routing (Flash for fast triage/judge, Pro for deep reasoning)
    router = get_model_router(settings)
    assert router.model_name_for(ModelTier.FAST_TRIAGE) == "gemini-2.5-flash"
    assert router.model_name_for(ModelTier.DEEP_REASONING) == "gemini-2.5-pro"
    assert root_agent.model.model == "gemini-2.5-flash"

    seq_agents = {a.name: a for a in sub_by_name["remediation_pipeline"].sub_agents}
    assert seq_agents["root_cause_synthesizer"].model.model == "gemini-2.5-pro"
    assert seq_agents["mitigation_executor"].model.model == "gemini-2.5-pro"

    loop_agents = {a.name: a for a in sub_by_name["postmortem_refinement_loop"].sub_agents}
    assert loop_agents["postmortem_drafter"].model.model == "gemini-2.5-pro"
    assert loop_agents["sre_quality_critic"].model.model == "gemini-2.5-flash"
    assert loop_agents["sre_quality_critic"].generate_content_config.temperature == 0.0
    assert isinstance(
        loop_agents["postmortem_escalation_checker"], PostmortemEscalationChecker
    )


@pytest.mark.asyncio
async def test_postmortem_escalation_checker_gates_loop_exit() -> None:
    checker = PostmortemEscalationChecker(name="postmortem_escalation_checker")

    # Revise verdict should NOT escalate
    revise_ctx = SimpleNamespace(
        session=SimpleNamespace(
            state={
                "postmortem_critique": json.dumps(
                    {
                        "grade": "revise",
                        "grounding_verified": False,
                        "pii_free": True,
                        "missing_sections": ["Action Items"],
                        "feedback": "Add missing section.",
                    }
                )
            }
        )
    )
    revise_events = [e async for e in checker._run_async_impl(revise_ctx)]  # type: ignore[arg-type]
    assert not revise_events[0].actions.escalate

    # Passing grounded & PII-free verdict SHOULD escalate
    pass_ctx = SimpleNamespace(
        session=SimpleNamespace(
            state={
                "postmortem_critique": json.dumps(
                    {
                        "grade": "pass",
                        "grounding_verified": True,
                        "pii_free": True,
                        "missing_sections": [],
                        "feedback": "Looks great.",
                    }
                )
            }
        )
    )
    pass_events = [e async for e in checker._run_async_impl(pass_ctx)]  # type: ignore[arg-type]
    assert pass_events[0].actions.escalate is True


@pytest.mark.asyncio
async def test_async_memory_is_non_blocking_redacts_pii_and_persists(
    tmp_path: Path,
) -> None:
    db_file = tmp_path / "memory.db"
    manager = AsyncIncidentMemoryManager(
        settings=AegisSettings(AEGIS_ENV="test"),
        db_path=str(db_file),
    )

    # Confirm scheduling returns immediately without blocking the user turn
    start = time.perf_counter()
    task = manager.schedule_consolidation(
        session_id="sess-async-42",
        state={
            "active_incident_id": "INC-2026-1042",
            "active_service": "checkout-api",
            "root_cause_assessment": json.dumps(
                {
                    "incident_id": "INC-2026-1042",
                    "service_name": "checkout-api",
                    "severity": "P1",
                    "probable_root_cause": (
                        "Sync lock timeout reported by alex.rivera@example.com with ssn 123-45-6789"
                    ),
                    "recommended_action": "canary_rollback",
                }
            ),
        },
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    assert task is not None
    assert elapsed_ms < 100.0

    await manager.drain_background_tasks()

    # Verify persisted record is recallable in a fresh manager instance and has zero raw PII
    reloaded = AsyncIncidentMemoryManager(
        settings=AegisSettings(AEGIS_ENV="test"),
        db_path=str(db_file),
    )
    lessons = await reloaded.recall_lessons("checkout-api", "sync lock timeout", limit=5)
    matching = [item for item in lessons if item["incident_id"] == "INC-2026-1042"]
    assert len(matching) == 1
    assert "alex.rivera@example.com" not in matching[0]["root_cause_summary"]
    assert "123-45-6789" not in matching[0]["root_cause_summary"]

    # Also test direct persist_lesson API
    direct = await reloaded.persist_lesson(
        IncidentLessonRecord(
            incident_id="INC-2026-1099",
            service_name="catalog-search",
            severity="P2",
            root_cause_summary="Canary reranker timeout",
            winning_mitigation="5% canary revert",
            recorded_at="2026-11-25T12:00:00Z",
        )
    )
    assert direct["incident_id"] == "INC-2026-1099"
    await asyncio.sleep(0)
