from __future__ import annotations

import json
from pathlib import Path

import pytest

from hacker_ai.config import ConfigurationError, TelegramSettings, Workspace
from hacker_ai.models import AgentPlan, FindingDraft
from hacker_ai.storage import Storage
from hacker_ai.telegram import TelegramAgent


def workspace_with_scope(tmp_path: Path) -> tuple[Workspace, Storage]:
    state = tmp_path / ".hacker-ai"
    state.mkdir()
    (state / "scope.yaml").write_text(
        """program:
  name: Telegram test
scope:
  included:
    - type: domain
      value: example.com
rules:
  active_scanning: true
  automated_scanning: limited
""",
        encoding="utf-8",
    )
    workspace = Workspace(tmp_path)
    storage = Storage(workspace.database)
    storage.initialize()
    return workspace, storage


def test_telegram_settings_require_allowlisted_users(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.delenv("TELEGRAM_ALLOWED_USER_IDS", raising=False)
    with pytest.raises(ConfigurationError, match="positive integer IDs"):
        TelegramSettings.from_environment()


def test_telegram_capabilities_default_to_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", "7")
    monkeypatch.delenv("HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON", raising=False)
    monkeypatch.delenv("HACKER_AI_TELEGRAM_ALLOW_SUBDOMAIN_RECON", raising=False)
    monkeypatch.delenv("HACKER_AI_TELEGRAM_ALLOW_PORT_RECON", raising=False)

    settings = TelegramSettings.from_environment()

    assert settings.allow_http_recon is False
    assert settings.allow_subdomain_recon is False
    assert settings.allow_port_recon is False


def test_telegram_capability_rejects_ambiguous_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", "7")
    monkeypatch.setenv("HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON", "yes")
    with pytest.raises(ConfigurationError, match="must be exactly true or false"):
        TelegramSettings.from_environment()


def test_scope_check_from_natural_language_plan(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(
        action="scope_check",
        target="example.com",
        explanation="Scope tekshiriladi.",
    )
    agent = TelegramAgent(workspace, storage, lambda _request: plan)

    reply = agent.handle(7, 8, "example.com scope ichidami?")

    assert reply.startswith("RUXSAT:")
    assert storage.audit_entries()[0]["action"] == "telegram.plan"


def test_out_of_scope_action_is_denied_before_confirmation(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(
        action="recon_http",
        target="outside.test",
        explanation="HTTP tekshiruv.",
    )
    agent = TelegramAgent(workspace, storage, lambda _request: plan)

    reply = agent.handle(7, 8, "outside.test ni tekshir")

    assert reply.startswith("RAD ETILDI:")
    assert 7 not in agent.pending
    assert storage.audit_entries()[0]["allowed"] == 0


def test_recon_requires_separate_confirmation_and_rechecks_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(
        action="recon_http",
        target="https://example.com",
        explanation="Bitta xavfsiz HTTP so‘rovi.",
    )
    agent = TelegramAgent(workspace, storage, lambda _request: plan)
    calls: list[str] = []

    class Result:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            calls.append("executed")
            return {"status_code": 200}

    monkeypatch.setattr("hacker_ai.telegram.recon_target", lambda *_args: Result())

    staged = agent.handle(7, 8, "example.com ni tekshir")
    assert "/confirm" in staged
    assert calls == []

    result = agent.handle(7, 8, "/confirm")
    assert json.loads(result)["status_code"] == 200
    assert calls == ["executed"]
    assert 7 not in agent.pending


def test_confirmation_is_bound_to_original_chat(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(action="recon_http", target="example.com", explanation="HTTP tekshiruv.")
    agent = TelegramAgent(workspace, storage, lambda _request: plan)
    agent.handle(7, 8, "tekshir")

    assert "kutilayotgan amal yo‘q" in agent.handle(7, 9, "/confirm")


def test_disabled_capability_is_denied_before_confirmation(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(action="recon_http", target="example.com", explanation="HTTP tekshiruv.")
    settings = TelegramSettings(token="token", allowed_user_ids=frozenset({7}))
    agent = TelegramAgent(workspace, storage, lambda _request: plan, settings)

    reply = agent.handle(7, 8, "tekshir")

    assert "HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON=false" in reply
    assert 7 not in agent.pending
    assert storage.audit_entries()[0]["action"] == "telegram.capability.denied"


def test_enabled_capability_can_be_staged(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(action="recon_http", target="example.com", explanation="HTTP tekshiruv.")
    settings = TelegramSettings(
        token="token", allowed_user_ids=frozenset({7}), allow_http_recon=True
    )
    agent = TelegramAgent(workspace, storage, lambda _request: plan, settings)

    assert "/confirm" in agent.handle(7, 8, "tekshir")


def test_web_assessment_recons_analyzes_saves_and_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(
        action="assess_web",
        target="https://example.com",
        explanation="Zaif tomonlar va himoya baholanadi.",
    )
    settings = TelegramSettings(
        token="token", allowed_user_ids=frozenset({7}), allow_http_recon=True
    )
    observed: dict[str, str] = {}

    class Recon:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"status_code": 200, "missing_security_headers": ["content-security-policy"]}

    def analyze(target: str, evidence: str, _scope: object) -> FindingDraft:
        observed["target"] = target
        observed["evidence"] = evidence
        return FindingDraft(
            title="Content Security Policy kuzatilmadi",
            severity="low",
            summary="HTTP javobida CSP header kuzatilmadi.",
            evidence=["missing_security_headers: content-security-policy"],
            impact="Brauzer himoyasining qo‘shimcha qatlami mavjud emas.",
            remediation="Mos Content-Security-Policy headerini sinovdan o‘tkazib joriy qiling.",
            confidence="high",
        )

    monkeypatch.setattr("hacker_ai.telegram.recon_target", lambda *_args: Recon())
    agent = TelegramAgent(workspace, storage, lambda _request: plan, settings, analyze)

    staged = agent.handle(7, 8, "example.com zaif tomonlarini top va himoyani ayt")
    result = agent.handle(7, 8, "/confirm")

    assert "/confirm" in staged
    assert "ASSESSMENT #1" in result
    assert "Himoya tavsiyasi" in result
    assert "inson tekshiruvi talab qilinadi" in result
    assert observed["target"] == "https://example.com"
    assert "content-security-policy" in observed["evidence"]
    assert storage.get_finding(1) is not None


def test_web_assessment_requires_http_capability(tmp_path: Path) -> None:
    workspace, storage = workspace_with_scope(tmp_path)
    plan = AgentPlan(action="assess_web", target="example.com", explanation="Web assessment.")
    settings = TelegramSettings(token="token", allowed_user_ids=frozenset({7}))
    agent = TelegramAgent(workspace, storage, lambda _request: plan, settings)

    reply = agent.handle(7, 8, "zaifliklarni top")

    assert "HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON=false" in reply
    assert 7 not in agent.pending
