from __future__ import annotations

import json
from typing import Any

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import OpenAI
from pydantic import ValidationError

from hacker_ai.config import Settings
from hacker_ai.models import AgentPlan, FindingDraft, ScopeDocument
from hacker_ai.redaction import redact_secrets


class AnalysisError(RuntimeError):
    """Raised when the model cannot return a valid, reviewable finding."""


SYSTEM_PROMPT = """You are an assistant for explicitly authorized security testing. Analyze
defensively; never propose phishing, malware, persistence, denial of service, credential theft,
stealth, evasion, destructive actions, or data exfiltration. Do not claim a vulnerability without
evidence. Return one JSON object with exactly
these fields: title, severity, summary, evidence, impact, remediation, confidence,
needs_human_validation.
"""

PLANNER_PROMPT = """Convert the user's request into exactly one available action. Available actions
are help, status, scope_check, recon_http, recon_subdomains, recon_ports, and assess_web. Use
assess_web when the user asks to assess a web target, identify evidence-backed weaknesses, and
recommend defenses. Recon and assessment are only for an explicitly supplied target and will
require authorization checks and separate human confirmation.
Never infer or invent a target. Never request arbitrary shell commands, exploit vulnerabilities,
obtain credentials, evade detection, persist, exfiltrate data, cause denial of service, or perform
destructive activity. Use help when the request is ambiguous, unsupported, unsafe, or lacks a
required target. For recon_ports, ports may only be a comma-separated list of TCP port numbers.
Explain the selected action briefly in the user's language.
"""


class AzureAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        credential: str | Any
        if settings.auth_mode == "entra":
            credential = get_bearer_token_provider(
                DefaultAzureCredential(), "https://ai.azure.com/.default"
            )
        elif settings.api_key:
            credential = settings.api_key
        else:
            raise AnalysisError("API key authentication selected without an API key")
        self.client = OpenAI(
            api_key=credential,
            base_url=settings.base_url.rstrip("/") + "/",
            timeout=settings.timeout_seconds,
            max_retries=2,
        )

    def analyze(self, target: str, evidence: str, scope: ScopeDocument) -> FindingDraft:
        sanitized = redact_secrets(evidence)
        context = {
            "program": scope.program.model_dump(),
            "rules": scope.rules.model_dump(),
            "target": target,
            "evidence": sanitized,
        }
        try:
            response = self.client.responses.create(
                model=self.settings.deployment,
                instructions=SYSTEM_PROMPT,
                input=json.dumps(context, ensure_ascii=False),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "finding_draft",
                        "strict": True,
                        "schema": FindingDraft.model_json_schema(),
                    }
                },
                store=False,
            )
            content = response.output_text
            if not content:
                raise AnalysisError("The model returned an empty response")
            draft = FindingDraft.model_validate_json(content)
            if not draft.needs_human_validation:
                draft = draft.model_copy(update={"needs_human_validation": True})
            return draft
        except (json.JSONDecodeError, ValidationError, IndexError) as exc:
            raise AnalysisError(f"The model returned invalid structured output: {exc}") from exc
        except Exception as exc:
            error_code = getattr(exc, "code", None)
            if error_code == "content_filter" or "content_filter" in str(exc).lower():
                raise AnalysisError(
                    "Azure content filtering stopped this analysis; review the evidence manually"
                ) from exc
            message = _safe_error_message(exc, self.settings.api_key)
            raise AnalysisError(f"Azure analysis failed: {type(exc).__name__}: {message}") from exc

    def plan(self, request: str) -> AgentPlan:
        """Map natural language to one constrained action; this method never executes it."""
        if not request.strip() or len(request.encode()) > 16_000:
            raise AnalysisError("The request must be between 1 and 16000 bytes")
        try:
            response = self.client.responses.create(
                model=self.settings.deployment,
                instructions=PLANNER_PROMPT,
                input=redact_secrets(request),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "agent_plan",
                        "strict": True,
                        "schema": AgentPlan.model_json_schema(),
                    }
                },
                store=False,
            )
            if not response.output_text:
                raise AnalysisError("The model returned an empty plan")
            return AgentPlan.model_validate_json(response.output_text)
        except AnalysisError:
            raise
        except (json.JSONDecodeError, ValidationError) as exc:
            raise AnalysisError(f"The model returned an invalid action plan: {exc}") from exc
        except Exception as exc:
            message = _safe_error_message(exc, self.settings.api_key)
            raise AnalysisError(f"Azure planning failed: {type(exc).__name__}: {message}") from exc

    def test_connection(self) -> str:
        """Send a harmless request to validate endpoint, auth, and deployment configuration."""
        try:
            response = self.client.responses.create(
                model=self.settings.deployment,
                instructions="Reply with exactly OK.",
                input="Connectivity test.",
                max_output_tokens=16,
                store=False,
            )
            output = response.output_text.strip()
            if not output:
                raise AnalysisError("The model returned an empty connectivity response")
            return output
        except AnalysisError:
            raise
        except Exception as exc:
            message = _safe_error_message(exc, self.settings.api_key)
            raise AnalysisError(
                f"Azure connection failed: {type(exc).__name__}: {message}"
            ) from exc


def _safe_error_message(error: Exception, api_key: str | None) -> str:
    message = redact_secrets(str(error))
    return message.replace(api_key, "[REDACTED]") if api_key else message


def finding_to_dict(finding: FindingDraft) -> dict[str, Any]:
    return finding.model_dump(mode="json")
