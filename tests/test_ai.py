import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from openai import OpenAI

from hacker_ai.ai import AnalysisError, AzureAnalyzer
from hacker_ai.config import Settings
from hacker_ai.models import ScopeDocument


class FakeResponses:
    def __init__(self, output_text: str = "", error: Exception | None = None) -> None:
        self.output_text = output_text
        self.error = error
        self.request: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.request = kwargs
        if self.error:
            raise self.error
        return SimpleNamespace(output_text=self.output_text)


def analyzer_with(responses: FakeResponses) -> AzureAnalyzer:
    analyzer = object.__new__(AzureAnalyzer)
    analyzer.settings = Settings(
        "https://test-resource.services.ai.azure.com/openai/v1/",
        "deployment",
        "api_key",
        "test-key",
    )
    analyzer.client = cast(OpenAI, SimpleNamespace(responses=responses))
    return analyzer


@pytest.fixture
def scope() -> ScopeDocument:
    return ScopeDocument.model_validate(
        {
            "program": {"name": "Authorized test"},
            "scope": {"included": [{"type": "domain", "value": "example.com"}]},
        }
    )


def test_analyzer_redacts_and_validates_json(scope: ScopeDocument) -> None:
    response = json.dumps(
        {
            "title": "Review header",
            "severity": "low",
            "summary": "A header may be absent",
            "evidence": ["Observed response"],
            "impact": "Defense in depth",
            "remediation": "Add the header",
            "confidence": "medium",
            "needs_human_validation": False,
        }
    )
    responses = FakeResponses(response)
    finding = analyzer_with(responses).analyze(
        "https://example.com", "Authorization: Bearer private", scope
    )

    assert finding.needs_human_validation is True
    assert responses.request["model"] == "deployment"
    assert responses.request["store"] is False
    assert responses.request["text"]["format"]["type"] == "json_schema"
    prompt = responses.request["input"]
    assert "private" not in prompt
    assert "[REDACTED]" in prompt


def test_analyzer_rejects_invalid_output(scope: ScopeDocument) -> None:
    with pytest.raises(AnalysisError, match="invalid structured output"):
        analyzer_with(FakeResponses("not-json")).analyze("https://example.com", "data", scope)


def test_analyzer_reports_content_filter(scope: ScopeDocument) -> None:
    with pytest.raises(AnalysisError, match="content filtering"):
        analyzer_with(FakeResponses(error=RuntimeError("content_filter"))).analyze(
            "https://example.com", "data", scope
        )


def test_error_does_not_leak_configured_key(scope: ScopeDocument) -> None:
    with pytest.raises(AnalysisError) as error:
        analyzer_with(FakeResponses(error=RuntimeError("failed with test-key"))).analyze(
            "https://example.com", "data", scope
        )
    assert "test-key" not in str(error.value)
    assert "[REDACTED]" in str(error.value)


def test_connection_uses_responses_api() -> None:
    responses = FakeResponses("OK")
    assert analyzer_with(responses).test_connection() == "OK"
    assert responses.request["input"] == "Connectivity test."
    assert responses.request["store"] is False


def test_planner_returns_only_validated_action() -> None:
    responses = FakeResponses(
        json.dumps(
            {
                "action": "scope_check",
                "target": "example.com",
                "ports": None,
                "explanation": "Scope tekshiriladi.",
            }
        )
    )
    plan = analyzer_with(responses).plan("example.com scope ichidami?")

    assert plan.action == "scope_check"
    assert responses.request["store"] is False
    assert responses.request["text"]["format"]["name"] == "agent_plan"


def test_planner_supports_bounded_web_assessment() -> None:
    responses = FakeResponses(
        json.dumps(
            {
                "action": "assess_web",
                "target": "https://example.com",
                "ports": None,
                "explanation": "Web himoyasi evidence asosida baholanadi.",
            }
        )
    )

    plan = analyzer_with(responses).plan("example.com zaif tomonlarini topib himoyani ayt")

    assert plan.action == "assess_web"
    assert "assess_web" in responses.request["instructions"]


def test_system_prompt_forbids_unsafe_assistance() -> None:
    from hacker_ai.ai import SYSTEM_PROMPT

    assert "never propose phishing" in SYSTEM_PROMPT
    assert "Do not claim a vulnerability without" in SYSTEM_PROMPT
