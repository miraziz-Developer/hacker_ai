from pathlib import Path

from hacker_ai.report import render_markdown
from hacker_ai.storage import Storage


def test_storage_and_sanitized_report(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()
    finding_id = storage.save_finding(
        "https://example.com",
        {
            "title": "Missing header",
            "severity": "low",
            "summary": "Cookie: private-value",
            "evidence": ["Header was absent"],
            "impact": "Defense in depth",
            "remediation": "Set the header",
            "confidence": "medium",
            "needs_human_validation": True,
        },
    )
    record = storage.get_finding(finding_id)
    assert record is not None
    report = render_markdown(record)
    assert "Missing header" in report
    assert "private-value" not in report
    assert "[REDACTED]" in report

    storage.audit("test", target="https://example.com", allowed=True)
    assert storage.audit_entries()[0]["action"] == "test"
