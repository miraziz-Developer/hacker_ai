from pathlib import Path

import pytest

from hacker_ai.models import ScopeDocument
from hacker_ai.scope import ScopeError, check_scope, load_scope, validate_resolved_ips

SCOPE = {
    "program": {"name": "Test", "platform": "custom"},
    "scope": {
        "included": [
            {"type": "domain", "value": "example.com"},
            {"type": "wildcard_domain", "value": "*.example.com"},
            {"type": "url", "value": "https://api.example.com/v1/"},
        ],
        "excluded": [{"type": "domain", "value": "admin.example.com"}],
    },
    "rules": {"active_scanning": True, "automated_scanning": "limited"},
}


@pytest.fixture
def document() -> ScopeDocument:
    return ScopeDocument.model_validate(SCOPE)


@pytest.mark.parametrize(
    ("target", "allowed"),
    [
        ("https://example.com", True),
        ("https://www.example.com", True),
        ("https://admin.example.com", False),
        ("https://example.com.evil.test", False),
        ("https://evil.test/?next=example.com", False),
    ],
)
def test_default_deny_and_exclusion_precedence(
    document: ScopeDocument, target: str, allowed: bool
) -> None:
    assert check_scope(document, target).allowed is allowed


def test_url_scope_restricts_path() -> None:
    document = ScopeDocument.model_validate(
        {
            "program": {"name": "URL only"},
            "scope": {"included": [{"type": "url", "value": "https://api.test/v1/"}]},
        }
    )
    assert check_scope(document, "https://api.test/v1/users").allowed
    assert not check_scope(document, "https://api.test/v2/users").allowed
    assert not check_scope(document, "http://api.test/v1/users").allowed


def test_private_dns_requires_explicit_ip_scope(document: ScopeDocument) -> None:
    with pytest.raises(ScopeError, match="non-public address"):
        validate_resolved_ips(document, "example.com", ["127.0.0.1"])


def test_load_example_scope() -> None:
    document = load_scope(Path("examples/scope.yaml"))
    assert document.program.name == "Example authorized program"
    assert [(asset.type.value, asset.value) for asset in document.scope.included] == [
        ("domain", "example.com"),
        ("cidr", "192.0.2.0/28"),
    ]
    assert document.scope.excluded == []
    assert document.rules.active_scanning is True
    assert document.rules.automated_scanning == "allowed"
    assert check_scope(document, "example.com").allowed
    assert check_scope(document, "192.0.2.10").allowed
    assert not check_scope(document, "outside.test").allowed
    assert not check_scope(document, "198.51.100.10").allowed


def test_dangerous_rule_cannot_be_enabled() -> None:
    changed = {**SCOPE, "rules": {"denial_of_service": True}}
    with pytest.raises(ValueError, match="never enables"):
        ScopeDocument.model_validate(changed)
