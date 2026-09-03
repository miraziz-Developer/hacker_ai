from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hacker_ai.tools import TOOL_REGISTRY, inspect_tool, installation_plan

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_missing_tool_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: None)
    status = inspect_tool(TOOL_REGISTRY[0])
    assert status.state == "missing"
    assert status.path is None


def test_approved_tool_identity_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: "/safe/bin/nmap")
    monkeypatch.setattr(
        "hacker_ai.tools.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "Nmap version 7.95", ""),
    )
    status = inspect_tool(TOOL_REGISTRY[0])
    assert status.state == "ready"
    assert status.version == "Nmap version 7.95"


def test_name_collision_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = next(item for item in TOOL_REGISTRY if item.name == "httpx")
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: "/venv/bin/httpx")
    monkeypatch.setattr(
        "hacker_ai.tools.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "HTTPX Python client", ""),
    )
    status = inspect_tool(spec)
    assert status.state == "incompatible"
    assert "approved project" in (status.detail or "")


def test_kali_httpx_alias_is_used_after_python_name_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = next(item for item in TOOL_REGISTRY if item.name == "httpx")

    def which(name: str) -> str | None:
        return {
            "httpx": "/venv/bin/httpx",
            "httpx-toolkit": "/usr/bin/httpx-toolkit",
        }.get(name)

    def version(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = (
            "HTTPX Python client"
            if command[0] == "/venv/bin/httpx"
            else "[INF] Current Version: v1.9.0 projectdiscovery httpx"
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("hacker_ai.tools.shutil.which", which)
    monkeypatch.setattr("hacker_ai.tools.subprocess.run", version)

    status = inspect_tool(spec)

    assert status.state == "ready"
    assert status.path == "/usr/bin/httpx-toolkit"


def test_linux_installation_plan_uses_reviewed_kali_packages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("hacker_ai.tools.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "hacker_ai.tools.shutil.which",
        lambda name: "/usr/bin/apt-get" if name == "apt-get" else None,
    )

    assert installation_plan() == [
        "sudo apt-get install --no-install-recommends nmap subfinder httpx-toolkit whatweb"
    ]


def test_kali_bootstrap_dry_run_is_non_privileged() -> None:
    completed = subprocess.run(
        ["bash", str(PROJECT_ROOT / "scripts" / "bootstrap-kali.sh"), "--dry-run"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=True,
        text=True,
    )

    assert "sudo apt-get update" in completed.stdout
    assert "httpx-toolkit" in completed.stdout
    assert "tools doctor" in completed.stdout
    assert "HACKER_AI_ALLOW_NETWORK_EXECUTION=true" not in completed.stdout


def test_tool_timeout_is_redacted_to_exception_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: "/safe/bin/nmap")

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("secret command", 5)

    monkeypatch.setattr("hacker_ai.tools.subprocess.run", timeout)
    status = inspect_tool(TOOL_REGISTRY[0])
    assert status.state == "error"
    assert status.detail == "TimeoutExpired"
    assert "secret" not in str(status.to_dict())
