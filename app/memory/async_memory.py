"""Non-blocking asynchronous memory consolidation with Cloud DLP PII redaction.

Supports:
- Managed Vertex AI Memory Bank (`VertexAiMemoryBankService`) on Agent Runtime.
- Persistent parameterized SQLite institutional memory store locally / in CI.
All expensive memory summarization and consolidation tasks execute asynchronously
via `asyncio.create_task` so user responses are never blocked.
"""

from __future__ import annotations

import asyncio
import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite
from google.adk.agents.callback_context import CallbackContext
from google.adk.memory import InMemoryMemoryService, VertexAiMemoryBankService

from app.config.settings import AegisSettings, get_settings
from app.observability.logging_setup import get_logger
from app.observability.tracing import get_tracer
from app.security.pii_redactor import PiiRedactor, get_pii_redactor

logger = get_logger("async_memory")
tracer = get_tracer("aegis_ops.memory")


@dataclass(frozen=True)
class IncidentLessonRecord:
    """Distilled, PII-redacted institutional incident lesson."""

    incident_id: str
    service_name: str
    severity: str
    root_cause_summary: str
    winning_mitigation: str
    recorded_at: str


_SEED_LESSONS: tuple[IncidentLessonRecord, ...] = (
    IncidentLessonRecord(
        incident_id="INC-2026-0911",
        service_name="checkout-api",
        severity="P1",
        root_cause_summary=(
            "Synchronous locking in payment retry workers exhausted PostgreSQL pool "
            "connections under burst load; runbook RB-CHK-001 canary rollback restored SLO."
        ),
        winning_mitigation="25% canary rollback to previous verified healthy revision.",
        recorded_at="2026-10-14T18:20:00Z",
    ),
    IncidentLessonRecord(
        incident_id="INC-2026-0978",
        service_name="auth-gateway",
        severity="P1",
        root_cause_summary=(
            "Automated credential stuffing campaign from single /32 source elevated "
            "login latency; applying targeted WAF 60rpm rate limit mitigated attack."
        ),
        winning_mitigation="HITL-approved /32 WAF rate limit via RB-AUTH-004 (60rpm, 60m TTL).",
        recorded_at="2026-11-02T04:10:00Z",
    ),
)


class AsyncIncidentMemoryManager:
    """Manages non-blocking background memory writes and cross-session recall."""

    def __init__(
        self,
        settings: AegisSettings | None = None,
        redactor: PiiRedactor | None = None,
        db_path: str | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._redactor = redactor or get_pii_redactor()
        self._db_path = Path(db_path or self._settings.memory_db_path)
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._initialized = False
        self._adk_memory_service: Any | None = None

    def get_adk_memory_service(self) -> Any:
        """Return VertexAiMemoryBankService in prod or InMemoryMemoryService locally."""
        if self._adk_memory_service is not None:
            return self._adk_memory_service

        if self._settings.agent_engine_id and self._settings.google_cloud_project:
            self._adk_memory_service = VertexAiMemoryBankService(
                project=self._settings.google_cloud_project,
                location=self._settings.aegis_region,
                agent_engine_id=self._settings.agent_engine_id,
            )
        else:
            self._adk_memory_service = InMemoryMemoryService()
        return self._adk_memory_service

    async def _ensure_db_initialized(self) -> None:
        if self._initialized:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    root_cause_summary TEXT NOT NULL,
                    winning_mitigation TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                )
                """
            )
            cursor = await db.execute("SELECT COUNT(*) FROM incident_lessons")
            row = await cursor.fetchone()
            if row is not None and int(row[0]) == 0:
                await db.executemany(
                    """
                    INSERT INTO incident_lessons (
                        incident_id, service_name, severity,
                        root_cause_summary, winning_mitigation, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            lesson.incident_id,
                            lesson.service_name,
                            lesson.severity,
                            lesson.root_cause_summary,
                            lesson.winning_mitigation,
                            lesson.recorded_at,
                        )
                        for lesson in _SEED_LESSONS
                    ],
                )
            await db.commit()
        self._initialized = True

    async def persist_lesson(self, lesson: IncidentLessonRecord) -> dict[str, Any]:
        """Scrub PII via Cloud DLP/local redactor and persist lesson using parameterized SQL."""
        with tracer.start_as_current_span("memory.persist_lesson") as span:
            span.set_attribute("aegis.incident_id", lesson.incident_id)
            span.set_attribute("aegis.service_name", lesson.service_name)
            await self._ensure_db_initialized()

            redacted_rca = self._redactor.redact_text(lesson.root_cause_summary)
            redacted_mitigation = self._redactor.redact_text(lesson.winning_mitigation)

            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    """
                    INSERT INTO incident_lessons (
                        incident_id, service_name, severity,
                        root_cause_summary, winning_mitigation, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lesson.incident_id,
                        lesson.service_name,
                        lesson.severity,
                        redacted_rca,
                        redacted_mitigation,
                        lesson.recorded_at,
                    ),
                )
                await db.commit()

            logger.info(
                "async_memory_lesson_persisted",
                incident_id=lesson.incident_id,
                service_name=lesson.service_name,
                severity=lesson.severity,
            )
            return {
                "incident_id": lesson.incident_id,
                "service_name": lesson.service_name,
                "redacted_root_cause": redacted_rca,
            }

    async def recall_lessons(
        self, service_name: str, symptom_keywords: str, limit: int = 3
    ) -> list[dict[str, Any]]:
        """Retrieve relevant historical lessons using strictly parameterized SQL queries."""
        with tracer.start_as_current_span("memory.recall_lessons") as span:
            span.set_attribute("aegis.service_name", service_name)
            await self._ensure_db_initialized()

            async with aiosqlite.connect(self._db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    """
                    SELECT incident_id, service_name, severity,
                           root_cause_summary, winning_mitigation, recorded_at
                    FROM incident_lessons
                    WHERE service_name = ?
                    ORDER BY id DESC
                    LIMIT 25
                    """,
                    (service_name,),
                )
                rows = await cursor.fetchall()

            keywords = {
                tok for tok in symptom_keywords.lower().split() if len(tok) >= 3
            }
            ranked: list[tuple[int, dict[str, Any]]] = []
            for row in rows:
                haystack = (
                    f"{row['root_cause_summary']} {row['winning_mitigation']}"
                ).lower()
                hits = sum(1 for kw in keywords if kw in haystack)
                ranked.append(
                    (
                        hits,
                        {
                            "incident_id": row["incident_id"],
                            "service_name": row["service_name"],
                            "severity": row["severity"],
                            "root_cause_summary": row["root_cause_summary"],
                            "winning_mitigation": row["winning_mitigation"],
                            "recorded_at": row["recorded_at"],
                            "keyword_overlap": hits,
                        },
                    )
                )
            ranked.sort(key=lambda pair: pair[0], reverse=True)
            return [item for _, item in ranked[:limit]]

    def schedule_consolidation(
        self,
        *,
        session_id: str,
        state: dict[str, Any],
        callback_context: CallbackContext | None = None,
    ) -> asyncio.Task[Any] | None:
        """Schedule non-blocking background memory extraction & consolidation."""
        rca = state.get("root_cause_assessment")
        if not rca and not state.get("active_service"):
            return None

        async def _background_consolidate() -> None:
            with tracer.start_as_current_span("memory.async_consolidate") as span:
                span.set_attribute("aegis.session_id", session_id)
                try:
                    if isinstance(rca, str):
                        try:
                            rca_dict = json.loads(rca)
                        except json.JSONDecodeError:
                            rca_dict = {"probable_root_cause": rca}
                    elif isinstance(rca, dict):
                        rca_dict = rca
                    else:
                        rca_dict = {}

                    incident_id = str(
                        rca_dict.get("incident_id")
                        or state.get("active_incident_id")
                        or f"INC-SESSION-{session_id[:6]}"
                    )
                    service_name = str(
                        rca_dict.get("service_name")
                        or state.get("active_service")
                        or "checkout-api"
                    )
                    severity = str(rca_dict.get("severity") or "P2")
                    root_cause = str(
                        rca_dict.get("probable_root_cause")
                        or state.get("telemetry_findings")
                        or "Incident triage findings recorded."
                    )[:600]
                    mitigation = str(
                        rca_dict.get("recommended_action")
                        or state.get("last_mitigation_action")
                        or "Runbook-guided triage."
                    )[:400]

                    lesson = IncidentLessonRecord(
                        incident_id=incident_id,
                        service_name=service_name,
                        severity=severity,
                        root_cause_summary=root_cause,
                        winning_mitigation=mitigation,
                        recorded_at=datetime.datetime.now(
                            datetime.UTC
                        ).isoformat(),
                    )
                    await self.persist_lesson(lesson)

                    # Also sync with managed Vertex AI Memory Bank when attached to Runner
                    if callback_context is not None and hasattr(
                        callback_context, "add_session_to_memory"
                    ):
                        try:
                            await callback_context.add_session_to_memory()
                        except Exception as mem_exc:
                            logger.debug(
                                "adk_memory_bank_sync_skipped",
                                reason=type(mem_exc).__name__,
                            )
                except Exception as exc:
                    logger.warning(
                        "async_memory_consolidation_failed",
                        session_id=session_id,
                        error_type=type(exc).__name__,
                    )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None

        task = loop.create_task(
            _background_consolidate(), name=f"aegis-memory-{session_id}"
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        logger.info(
            "async_memory_consolidation_scheduled",
            session_id=session_id,
            pending_tasks=len(self._background_tasks),
        )
        return task

    async def drain_background_tasks(self, timeout_seconds: float = 10.0) -> None:
        """Await all in-flight async memory tasks gracefully (for shutdown & tests)."""
        if not self._background_tasks:
            return
        tasks = list(self._background_tasks)
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout_seconds,
        )


_DEFAULT_MEMORY_MANAGER: AsyncIncidentMemoryManager | None = None


def get_memory_manager() -> AsyncIncidentMemoryManager:
    """Return singleton AsyncIncidentMemoryManager."""
    global _DEFAULT_MEMORY_MANAGER
    if _DEFAULT_MEMORY_MANAGER is None:
        _DEFAULT_MEMORY_MANAGER = AsyncIncidentMemoryManager()
    return _DEFAULT_MEMORY_MANAGER


async def schedule_async_memory_consolidation(
    callback_context: CallbackContext,
) -> None:
    """ADK `after_agent_callback` firing non-blocking memory consolidation."""
    manager = get_memory_manager()
    session = getattr(callback_context, "session", None)
    session_id = getattr(session, "id", "ephemeral")
    raw_state: Any = callback_context.state
    state_snapshot: dict[str, Any] = (
        raw_state.to_dict() if hasattr(raw_state, "to_dict") else dict(raw_state)
    )
    manager.schedule_consolidation(
        session_id=session_id,
        state=state_snapshot,
        callback_context=callback_context,
    )
    return None
