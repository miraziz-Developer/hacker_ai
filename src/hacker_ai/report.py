from __future__ import annotations

from typing import Any

from hacker_ai.redaction import redact_secrets


def render_markdown(record: dict[str, Any]) -> str:
    finding = record["payload"]
    evidence = "\n".join(f"- {redact_secrets(item)}" for item in finding["evidence"])
    return f"""# {finding["title"]}

**Target:** `{record["target"]}`  
**Severity:** {finding["severity"].title()}  
**Confidence:** {finding["confidence"].title()}  
**Status:** {record["status"]}  
**Human validation required:** Yes

## Summary

{redact_secrets(finding["summary"])}

## Evidence

{evidence}

## Impact

{redact_secrets(finding["impact"])}

## Remediation

{redact_secrets(finding["remediation"])}

---

Generated as a draft. Validate every claim and follow the program's disclosure policy before
submission.
"""
