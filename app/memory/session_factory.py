"""Persistent session service factory (VertexAiSessionService in prod, SQLite locally)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from google.adk.sessions import DatabaseSessionService, VertexAiSessionService

from app.config.settings import AegisSettings, get_settings
from app.observability.logging_setup import get_logger

logger = get_logger("session_factory")


def _ensure_sqlite_parent_dir(db_url: str) -> None:
    """Create parent directory with restricted permissions when using SQLite URI."""
    prefix = "sqlite+aiosqlite:///"
    if not db_url.startswith(prefix):
        return
    raw_path = db_url[len(prefix) :]
    if raw_path == ":memory:" or not raw_path:
        return
    parent = Path(raw_path).resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)


def create_persistent_session_service(
    settings: AegisSettings | None = None,
) -> Any:
    """Instantiate a persistent ADK session backend for cross-turn durability.

    - In Managed Vertex AI Agent Runtime (`AGENT_ENGINE_ID` set), returns
      `VertexAiSessionService` connected to the managed Agent Engine session store.
    - Otherwise returns `DatabaseSessionService` backed by async SQLite (or any
      SQLAlchemy async database URL configured in `AEGIS_SESSION_DB_URL`).
    """
    cfg = settings or get_settings()

    if cfg.agent_engine_id and cfg.google_cloud_project:
        logger.info(
            "session_service_initialized",
            backend="vertex_ai_session_service",
            location=cfg.aegis_region,
        )
        return VertexAiSessionService(
            project=cfg.google_cloud_project,
            location=cfg.aegis_region,
            agent_engine_id=cfg.agent_engine_id,
        )

    _ensure_sqlite_parent_dir(cfg.session_db_url)
    logger.info(
        "session_service_initialized",
        backend="database_session_service",
        dialect=cfg.session_db_url.split("://", 1)[0],
    )
    return DatabaseSessionService(db_url=cfg.session_db_url)
