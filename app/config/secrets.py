"""Google Cloud Secret Manager client with TTL caching and fail-closed prod mode.

Security invariants:
- Zero hardcoded API keys, tokens, or literal default fallback secrets.
- Fails closed in production if a required secret cannot be resolved.
- Never logs secret material.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from app.config.settings import AegisSettings, get_settings


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be securely resolved."""


@dataclass
class _CachedSecret:
    value: str
    expires_at: float


class SecretManagerProvider:
    """Secure secret loader backed by Google Cloud Secret Manager."""

    def __init__(
        self,
        settings: AegisSettings | None = None,
        client: Any | None = None,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, _CachedSecret] = {}

    def _get_client(self) -> Any:
        if self._client is None:
            from google.cloud import secretmanager

            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def get_secret(
        self,
        secret_id: str,
        *,
        env_var_name: str | None = None,
        version: str = "latest",
        required: bool = True,
    ) -> str | None:
        """Resolve a secret from injected runtime env var or GCP Secret Manager.

        Args:
            secret_id: Secret name in Google Cloud Secret Manager.
            env_var_name: Optional runtime environment variable injected via
                Agent Runtime / Cloud Run `--secrets` binding.
            version: Secret version identifier (defaults to ``latest``).
            required: When True in staging/production, raises SecretResolutionError
                if the secret cannot be fetched.

        Returns:
            The resolved secret string, or None when optional and unavailable
            in local/test execution.
        """
        cache_key = f"{secret_id}:{version}"
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.value

        # 1. Runtime secret injection (e.g., `agents-cli deploy --secrets ENV=SECRET_ID`)
        if env_var_name:
            injected = os.environ.get(env_var_name)
            if injected:
                self._cache[cache_key] = _CachedSecret(
                    value=injected, expires_at=now + self._cache_ttl_seconds
                )
                return injected

        # 2. Direct Google Cloud Secret Manager API access
        project_id = self._settings.google_cloud_project
        if project_id and self._settings.aegis_env != "test":
            resource_name = (
                f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
            )
            try:
                client = self._get_client()
                response = client.access_secret_version(request={"name": resource_name})
                secret_value = response.payload.data.decode("utf-8")
                self._cache[cache_key] = _CachedSecret(
                    value=secret_value, expires_at=now + self._cache_ttl_seconds
                )
                return secret_value
            except Exception as exc:
                if required and self._settings.aegis_env in {"staging", "production"}:
                    raise SecretResolutionError(
                        f"Failed to access Secret Manager secret '{secret_id}'."
                    ) from exc

        # 3. Fail-closed in staging/production; explicit None (no literal secret) locally
        if required and self._settings.aegis_env in {"staging", "production"}:
            raise SecretResolutionError(
                f"Required secret '{secret_id}' is unavailable in {self._settings.aegis_env}."
            )
        return None

    def clear_cache(self) -> None:
        """Clear in-memory cached secret values."""
        self._cache.clear()


_DEFAULT_PROVIDER: SecretManagerProvider | None = None


def get_secret_provider() -> SecretManagerProvider:
    """Return singleton SecretManagerProvider."""
    global _DEFAULT_PROVIDER
    if _DEFAULT_PROVIDER is None:
        _DEFAULT_PROVIDER = SecretManagerProvider()
    return _DEFAULT_PROVIDER
