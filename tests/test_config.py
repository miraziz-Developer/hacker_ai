from pathlib import Path

import pytest

from hacker_ai.config import (
    ConfigurationError,
    Settings,
    Workspace,
    network_execution_enabled,
    require_network_execution,
)


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AZURE_OPENAI_BASE_URL", "https://test-resource.services.ai.azure.com/openai/v1/"
    )
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-oss-20b")
    monkeypatch.setenv("HACKER_AI_TIMEOUT_SECONDS", "12.5")
    settings = Settings.from_environment()
    assert settings.deployment == "gpt-oss-20b"
    assert settings.auth_mode == "entra"
    assert settings.api_key is None
    assert settings.timeout_seconds == 12.5


def test_settings_require_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_BASE_URL", "http://azure.test")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "model")
    with pytest.raises(ConfigurationError, match="HTTPS"):
        Settings.from_environment()


def test_api_key_auth_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AZURE_OPENAI_BASE_URL", "https://test-resource.services.ai.azure.com/openai/v1"
    )
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "model")
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "api_key")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="API_KEY is required"):
        Settings.from_environment()


def test_network_execution_defaults_to_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", raising=False)
    assert network_execution_enabled() is False
    with pytest.raises(ConfigurationError, match="Network execution is disabled"):
        require_network_execution()


def test_network_execution_accepts_explicit_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    assert network_execution_enabled() is True
    require_network_execution()


def test_network_execution_rejects_ambiguous_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "yes")
    with pytest.raises(ConfigurationError, match="exactly true or false"):
        network_execution_enabled()


def test_workspace_discovery_from_child(tmp_path: Path) -> None:
    (tmp_path / ".hacker-ai").mkdir()
    child = tmp_path / "a" / "b"
    child.mkdir(parents=True)
    assert Workspace.discover(child).root == tmp_path


def test_workspace_discovery_fails_without_state(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="No workspace"):
        Workspace.discover(tmp_path)
