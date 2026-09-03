from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TextIO, cast


class DatasetError(ValueError):
    """Raised when a dataset cannot be safely audited or prepared."""


DatasetFormat = Literal["chatml", "steering", "sentinel", "unknown"]

SAFE_CATEGORIES = frozenset(
    {
        "advisory_reference",
        "bug_bounty_disclosure",
        "dual_use_boundary_knowledge",
        "fix_commit_reference",
        "vulnerability_exploit_knowledge",
        "vulnerability_reference",
    }
)
ALLOWED_RELEASE_MODES = frozenset({"redistributable_text"})
REQUIRED_METADATA = frozenset({"category", "release_mode", "source_dataset"})
MAX_LINE_BYTES = 4_000_000
SAFE_SYSTEM_PROMPT = """You are a security analyst for explicitly authorized bug bounty and
defensive validation. Stay within the supplied scope. Explain evidence, detection, impact, and
remediation. Never assist phishing, malware deployment, persistence, credential theft, evasion,
denial of service, destructive actions, or data exfiltration. Do not invent facts. Require human
review before testing or disclosure."""

SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


@dataclass
class DatasetAudit:
    path: str
    rows: int = 0
    valid_rows: int = 0
    invalid_json: int = 0
    oversized_rows: int = 0
    secret_rows: int = 0
    formats: Counter[str] = field(default_factory=Counter)
    categories: Counter[str] = field(default_factory=Counter)
    release_modes: Counter[str] = field(default_factory=Counter)
    missing_metadata: Counter[str] = field(default_factory=Counter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "rows": self.rows,
            "valid_rows": self.valid_rows,
            "invalid_json": self.invalid_json,
            "oversized_rows": self.oversized_rows,
            "secret_rows": self.secret_rows,
            "formats": dict(sorted(self.formats.items())),
            "categories": dict(sorted(self.categories.items())),
            "release_modes": dict(sorted(self.release_modes.items())),
            "missing_metadata": dict(sorted(self.missing_metadata.items())),
        }


def _records(path: Path) -> Iterator[tuple[int, str, dict[str, Any] | None]]:
    if not path.is_file():
        raise DatasetError(f"Dataset does not exist or is not a file: {path}")
    try:
        with path.open(encoding="utf-8", errors="strict") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                    yield line_number, line, None
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    yield line_number, line, None
                    continue
                yield line_number, line, value if isinstance(value, dict) else None
    except (OSError, UnicodeError) as exc:
        raise DatasetError(f"Cannot read dataset: {type(exc).__name__}") from exc


def detect_format(record: dict[str, Any]) -> DatasetFormat:
    if isinstance(record.get("messages"), list):
        return "chatml"
    if isinstance(record.get("goal"), str) and isinstance(record.get("target"), str):
        return "steering"
    if all(key in record for key in ("logic_chain", "exploit_example", "attack_vector")):
        return "sentinel"
    return "unknown"


def _has_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def audit_dataset(path: Path) -> DatasetAudit:
    report = DatasetAudit(path=str(path.resolve()))
    for _, raw, record in _records(path):
        report.rows += 1
        if record is None:
            if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
                report.oversized_rows += 1
            else:
                report.invalid_json += 1
            continue
        report.valid_rows += 1
        report.formats[detect_format(record)] += 1
        if _has_secret(raw):
            report.secret_rows += 1
        metadata = record.get("metadata")
        if isinstance(metadata, dict):
            category = str(metadata.get("category", "<missing>"))
            release_mode = str(metadata.get("release_mode", "<missing>"))
            report.categories[category] += 1
            report.release_modes[release_mode] += 1
            for name in REQUIRED_METADATA:
                if not metadata.get(name):
                    report.missing_metadata[name] += 1
        else:
            report.missing_metadata["metadata"] += 1
    return report


def _safe_chatml(record: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    if detect_format(record) != "chatml":
        return None, "unsupported_format"
    metadata = record.get("metadata")
    if not isinstance(metadata, dict) or any(not metadata.get(key) for key in REQUIRED_METADATA):
        return None, "missing_governance_metadata"
    if metadata["category"] not in SAFE_CATEGORIES:
        return None, "unsafe_category"
    if metadata["release_mode"] not in ALLOWED_RELEASE_MODES:
        return None, "restricted_release_mode"
    messages = record["messages"]
    if not isinstance(messages, list):
        return None, "invalid_messages"
    roles = [message.get("role") for message in messages if isinstance(message, dict)]
    if "user" not in roles or "assistant" not in roles:
        return None, "invalid_messages"
    sanitized_messages = [
        message
        for message in messages
        if isinstance(message, dict) and message.get("role") != "system"
    ]
    if any(
        not isinstance(message.get("content"), str) or not message["content"].strip()
        for message in sanitized_messages
    ):
        return None, "invalid_messages"
    output = {
        "messages": [{"role": "system", "content": SAFE_SYSTEM_PROMPT}, *sanitized_messages],
        "metadata": metadata,
    }
    if _has_secret(json.dumps(output, ensure_ascii=False)):
        return None, "secret_detected"
    return output, "accepted"


def _write_jsonl(handle: TextIO, record: dict[str, Any]) -> None:
    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def prepare_dataset(path: Path, output_dir: Path, validation_percent: int = 10) -> dict[str, Any]:
    if validation_percent < 1 or validation_percent > 30:
        raise DatasetError("validation_percent must be between 1 and 30")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "train.jsonl"
    validation_path = output_dir / "validation.jsonl"
    manifest_path = output_dir / "manifest.json"
    database_path = output_dir / ".dedup.sqlite3"
    existing = [
        candidate.name
        for candidate in (train_path, validation_path, manifest_path, database_path)
        if candidate.exists()
    ]
    if existing:
        raise DatasetError(f"Output directory contains generated files: {', '.join(existing)}")
    counts: Counter[str] = Counter()

    try:
        with (
            closing(sqlite3.connect(database_path)) as database,
            train_path.open("w", encoding="utf-8") as train,
            validation_path.open("w", encoding="utf-8") as validation,
        ):
            database.execute("CREATE TABLE hashes (digest TEXT PRIMARY KEY)")
            for _, _, record in _records(path):
                counts["input_rows"] += 1
                if record is None:
                    counts["invalid_rows"] += 1
                    continue
                safe_record, decision = _safe_chatml(record)
                if safe_record is None:
                    counts[f"excluded_{decision}"] += 1
                    continue
                canonical = json.dumps(
                    safe_record["messages"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                digest = hashlib.sha256(canonical.encode()).hexdigest()
                try:
                    database.execute("INSERT INTO hashes VALUES (?)", (digest,))
                except sqlite3.IntegrityError:
                    counts["excluded_duplicate"] += 1
                    continue
                if int(digest[:8], 16) % 100 < validation_percent:
                    _write_jsonl(validation, safe_record)
                    counts["validation_rows"] += 1
                else:
                    _write_jsonl(train, safe_record)
                    counts["train_rows"] += 1
            database.commit()
    except (OSError, sqlite3.Error) as exc:
        raise DatasetError(f"Cannot prepare dataset: {type(exc).__name__}") from exc
    finally:
        database_path.unlink(missing_ok=True)

    manifest = {
        "source": str(path.resolve()),
        "format": "ChatML JSONL",
        "validation_percent": validation_percent,
        "safe_categories": sorted(SAFE_CATEGORIES),
        "allowed_release_modes": sorted(ALLOWED_RELEASE_MODES),
        "counts": dict(sorted(counts.items())),
        "files": {"train": train_path.name, "validation": validation_path.name},
        "sha256": {
            "train": _file_digest(train_path),
            "validation": _file_digest(validation_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return cast(dict[str, Any], manifest)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
