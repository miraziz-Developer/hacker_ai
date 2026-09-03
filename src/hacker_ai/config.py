from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    """Raised when required application configuration is missing or invalid."""


def _strict_boolean(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name, str(default).lower()).strip().lower()
    if raw not in {"true", "false"}:
        raise ConfigurationError(f"{name} must be exactly true or false")
    return raw == "true"


@dataclass(frozen=True)
class TelegramSettings:
    token: str
    allowed_user_ids: frozenset[int]
    poll_timeout_seconds: int = 30
    allow_http_recon: bool = False
    allow_subdomain_recon: bool = False
    allow_port_recon: bool = False

    @classmethod
    def from_environment(cls) -> TelegramSettings:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise ConfigurationError("TELEGRAM_BOT_TOKEN is required")
        raw_ids = os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").strip()
        try:
            user_ids = frozenset(
                int(value.strip()) for value in raw_ids.split(",") if value.strip()
            )
        except ValueError as exc:
            raise ConfigurationError("TELEGRAM_ALLOWED_USER_IDS must contain integer IDs") from exc
        if not user_ids or any(user_id <= 0 for user_id in user_ids):
            raise ConfigurationError("TELEGRAM_ALLOWED_USER_IDS must contain positive integer IDs")
        try:
            timeout = int(os.getenv("TELEGRAM_POLL_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise ConfigurationError("TELEGRAM_POLL_TIMEOUT_SECONDS must be an integer") from exc
        if timeout < 1 or timeout > 50:
            raise ConfigurationError("TELEGRAM_POLL_TIMEOUT_SECONDS must be between 1 and 50")
        return cls(
            token=token,
            allowed_user_ids=user_ids,
            poll_timeout_seconds=timeout,
            allow_http_recon=_strict_boolean("HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON"),
            allow_subdomain_recon=_strict_boolean("HACKER_AI_TELEGRAM_ALLOW_SUBDOMAIN_RECON"),
            allow_port_recon=_strict_boolean("HACKER_AI_TELEGRAM_ALLOW_PORT_RECON"),
        )


def network_execution_enabled() -> bool:
    """Return the explicit network-execution opt-in, failing closed on invalid values."""
    return _strict_boolean("HACKER_AI_ALLOW_NETWORK_EXECUTION")


def require_network_execution() -> None:
    """Require the environment opt-in without weakening scope or policy enforcement."""
    if not network_execution_enabled():
        raise ConfigurationError(
            "Network execution is disabled; set HACKER_AI_ALLOW_NETWORK_EXECUTION=true "
            "and use --execute after confirming written authorization"
        )


@dataclass(frozen=True)
class Settings:
    base_url: str
    deployment: str
    auth_mode: Literal["entra", "api_key"] = "entra"
    api_key: str | None = None
    timeout_seconds: float = 30.0

    @classmethod
    def from_environment(cls) -> Settings:
        required = {
            "base_url": os.getenv("AZURE_OPENAI_BASE_URL", "").strip(),
            "deployment": os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip(),
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            names = ", ".join(f"AZURE_OPENAI_{name.upper()}" for name in missing)
            raise ConfigurationError(f"Missing environment variables: {names}")
        parsed = urlparse(required["base_url"])
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError("AZURE_OPENAI_BASE_URL must be a valid HTTPS URL")
        if not parsed.hostname.endswith(".azure.com"):
            raise ConfigurationError("AZURE_OPENAI_BASE_URL must use an azure.com host")

        auth_mode_raw = os.getenv("AZURE_OPENAI_AUTH", "entra").strip().lower()
        if auth_mode_raw not in {"entra", "api_key"}:
            raise ConfigurationError("AZURE_OPENAI_AUTH must be entra or api_key")
        auth_mode = cast(Literal["entra", "api_key"], auth_mode_raw)
        api_key = os.getenv("AZURE_OPENAI_API_KEY", "").strip() or None
        if auth_mode == "api_key" and not api_key:
            raise ConfigurationError("AZURE_OPENAI_API_KEY is required for api_key auth")
        try:
            timeout = float(os.getenv("HACKER_AI_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise ConfigurationError("HACKER_AI_TIMEOUT_SECONDS must be a number") from exc
        if timeout <= 0 or timeout > 300:
            raise ConfigurationError("HACKER_AI_TIMEOUT_SECONDS must be between 0 and 300")
        return cls(
            base_url=required["base_url"],
            deployment=required["deployment"],
            auth_mode=auth_mode,
            api_key=api_key,
            timeout_seconds=timeout,
        )


@dataclass(frozen=True)
class Workspace:
    root: Path

    @property
    def state_dir(self) -> Path:
        return self.root / ".hacker-ai"

    @property
    def database(self) -> Path:
        return self.state_dir / "state.db"

    @property
    def scope_file(self) -> Path:
        return self.state_dir / "scope.yaml"

    @classmethod
    def discover(cls, start: Path | None = None) -> Workspace:
        current = (start or Path.cwd()).resolve()
        for candidate in (current, *current.parents):
            if (candidate / ".hacker-ai").is_dir():
                return cls(candidate)
        raise ConfigurationError("No workspace found. Run `hacker-ai init` first.")
