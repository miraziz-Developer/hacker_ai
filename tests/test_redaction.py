from hacker_ai.redaction import redact_secrets


def test_redacts_headers_and_tokens() -> None:
    raw = (
        "Authorization: Bearer secret\nCookie: sid=abc\n"
        "api_key=topsecret\n" + "ghp_" + "abcdefghijklmnopqrstuvwxyz"
    )
    result = redact_secrets(raw)
    assert "secret" not in result
    assert "sid=abc" not in result
    assert "topsecret" not in result
    assert "ghp_" not in result
    assert result.count("[REDACTED]") == 4
