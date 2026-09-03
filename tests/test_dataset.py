import json
from pathlib import Path
from typing import Any

import pytest

from hacker_ai.dataset import DatasetError, audit_dataset, detect_format, prepare_dataset


def row(
    category: str = "bug_bounty_disclosure", release: str = "redistributable_text"
) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": "Old unsafe persona"},
            {"role": "user", "content": "How should this finding be reviewed?"},
            {"role": "assistant", "content": "Validate evidence and recommend remediation."},
        ],
        "metadata": {
            "id": "example",
            "category": category,
            "release_mode": release,
            "source_dataset": "unit-test",
        },
    }


def write_rows(path: Path, rows: list[dict[str, Any] | str]) -> None:
    path.write_text(
        "".join(item + "\n" if isinstance(item, str) else json.dumps(item) + "\n" for item in rows),
        encoding="utf-8",
    )


def test_audit_recognizes_formats_and_invalid_json(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    write_rows(source, [row(), {"goal": "g", "target": "t"}, "not-json"])
    report = audit_dataset(source).to_dict()
    assert report["rows"] == 3
    assert report["formats"] == {"chatml": 1, "steering": 1}
    assert report["invalid_json"] == 1
    assert (
        detect_format({"logic_chain": [], "exploit_example": "x", "attack_vector": "web"})
        == "sentinel"
    )


def test_prepare_filters_deduplicates_splits_and_replaces_system(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    accepted = row()
    write_rows(
        source,
        [
            accepted,
            accepted,
            row("phishing_social_engineering_knowledge"),
            row(release="research_text_with_terms"),
            {"goal": "unsupported", "target": "format"},
        ],
    )
    output = tmp_path / "prepared"
    manifest = prepare_dataset(source, output, validation_percent=10)
    counts = manifest["counts"]
    assert counts["input_rows"] == 5
    assert counts["excluded_duplicate"] == 1
    assert counts["excluded_unsafe_category"] == 1
    assert counts["excluded_restricted_release_mode"] == 1
    assert counts["excluded_unsupported_format"] == 1
    assert counts.get("train_rows", 0) + counts.get("validation_rows", 0) == 1
    prepared = (output / "train.jsonl").read_text() + (output / "validation.jsonl").read_text()
    assert "Old unsafe persona" not in prepared
    assert "explicitly authorized" in prepared
    assert not (output / ".dedup.sqlite3").exists()

    with pytest.raises(DatasetError, match="contains generated files"):
        prepare_dataset(source, output)
