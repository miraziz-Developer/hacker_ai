from __future__ import annotations

import re

REDACTION_PATTERNS = (
    re.compile(r"(?im)^(authorization\s*:\s*)(.+)$"),
    re.compile(r"(?im)^(proxy-authorization\s*:\s*)(.+)$"),
    re.compile(r"(?im)^(cookie\s*:\s*)(.+)$"),
    re.compile(r"(?im)^(set-cookie\s*:\s*)(.+)$"),
    re.compile(
        r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret)(\s*[=:]\s*)[\"']?([^\s\"']+)"
    ),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
)


def redact_secrets(text: str) -> str:
    result = text
    for index, pattern in enumerate(REDACTION_PATTERNS):
        if index <= 3:
            result = pattern.sub(r"\1[REDACTED]", result)
        elif index == 4:
            result = pattern.sub(r"\1\2[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED]", result)
    return result
