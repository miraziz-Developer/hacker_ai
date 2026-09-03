from typing import Any

import httpx
import pytest

from hacker_ai.models import ScopeDocument
from hacker_ai.recon import ReconError, recon_target


@pytest.fixture
def scope() -> ScopeDocument:
    return ScopeDocument.model_validate(
        {
            "program": {"name": "Authorized test"},
            "scope": {"included": [{"type": "domain", "value": "example.com"}]},
            "rules": {"active_scanning": True, "automated_scanning": "limited"},
        }
    )


def test_recon_is_single_request_without_redirects(
    scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    observed: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            observed.update(kwargs)

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, url: str) -> httpx.Response:
            observed["url"] = url
            return httpx.Response(
                200,
                headers={"content-type": "text/html", "x-content-type-options": "nosniff"},
            )

    monkeypatch.setattr("hacker_ai.recon.resolve_ips", lambda _host: ["93.184.216.34"])
    monkeypatch.setattr("hacker_ai.recon.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("hacker_ai.recon.httpx.Client", FakeClient)
    result = recon_target(scope, "https://example.com/")

    assert result.status_code == 200
    assert observed["follow_redirects"] is False
    assert observed["url"] == "https://example.com/"
    assert "content-security-policy" in result.missing_security_headers


def test_recon_rejects_out_of_scope(scope: ScopeDocument) -> None:
    with pytest.raises(ReconError, match="not in the allowlist"):
        recon_target(scope, "https://outside.test")


def test_recon_rejects_disabled_scanning() -> None:
    scope = ScopeDocument.model_validate(
        {
            "program": {"name": "Passive only"},
            "scope": {"included": [{"type": "domain", "value": "example.com"}]},
        }
    )
    with pytest.raises(ReconError, match="do not allow"):
        recon_target(scope, "https://example.com")


def test_recon_requires_environment_opt_in(
    scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", raising=False)
    with pytest.raises(ReconError, match="Network execution is disabled"):
        recon_target(scope, "https://example.com")
