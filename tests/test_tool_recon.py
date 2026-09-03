from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hacker_ai.cli import app
from hacker_ai.models import ScopeDocument
from hacker_ai.recon import ReconError, run_nmap, run_subfinder
from hacker_ai.storage import Storage
from hacker_ai.tools import ToolExecutionError, ToolOutput, run_approved_tool


@pytest.fixture
def scope() -> ScopeDocument:
    return ScopeDocument.model_validate(
        {
            "program": {"name": "Adapter test"},
            "scope": {
                "included": [
                    {"type": "domain", "value": "example.com", "max_requests_per_second": 0.5},
                    {"type": "wildcard_domain", "value": "*.example.com"},
                    {"type": "ip", "value": "192.0.2.10"},
                ],
                "excluded": [{"type": "domain", "value": "admin.example.com"}],
            },
            "rules": {"active_scanning": True, "automated_scanning": "limited"},
        }
    )


def test_subfinder_filters_exclusions_and_malformed_output(
    scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    seen: list[str] = []

    def fake_run(_name: str, args: list[str], **_kwargs: object) -> ToolOutput:
        seen.extend(args)
        return ToolOutput(
            "api.example.com\nadmin.example.com\noutside.test\nnot a host\napi.example.com\n",
            "",
            0,
        )

    monkeypatch.setattr("hacker_ai.recon.run_approved_tool", fake_run)
    result = run_subfinder(scope, "example.com")
    assert result.discovered == ["api.example.com"]
    assert result.rejected == ["admin.example.com", "outside.test"]
    assert result.malformed_lines == 1
    assert seen[:2] == ["-d", "example.com"]
    assert "-rlm" in seen


def test_subfinder_rejects_unscoped_root(scope: ScopeDocument) -> None:
    with pytest.raises(ReconError, match="explicitly scoped"):
        run_subfinder(scope, "outside.test")


def test_subfinder_rejects_forbidden_automation() -> None:
    document = ScopeDocument.model_validate(
        {
            "program": {"name": "Manual only"},
            "scope": {"included": [{"type": "domain", "value": "example.com"}]},
        }
    )
    with pytest.raises(ReconError, match="automated passive discovery"):
        run_subfinder(document, "example.com")


def test_nmap_uses_fixed_profile_and_parses_xml(
    scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    seen: list[str] = []
    xml = """<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
    <service name="https"/></port></ports></host></nmaprun>"""

    def fake_run(_name: str, args: list[str], **_kwargs: object) -> ToolOutput:
        seen.extend(args)
        return ToolOutput(xml, "", 0)

    monkeypatch.setattr("hacker_ai.recon.run_approved_tool", fake_run)
    result = run_nmap(scope, "192.0.2.10", "443,80")
    assert result.services[0].service == "https"
    assert result.services[0].port == 443
    assert seen[-1] == "192.0.2.10"
    assert "--" in seen
    assert "-sV" not in seen
    assert "-Pn" not in seen


def test_nmap_rejects_private_domain_resolution(
    scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("hacker_ai.recon.resolve_ips", lambda _host: ["127.0.0.1"])
    with pytest.raises(ReconError, match="non-public address"):
        run_nmap(scope, "example.com")


def test_nmap_rejects_malformed_xml(scope: ScopeDocument, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    monkeypatch.setattr(
        "hacker_ai.recon.run_approved_tool", lambda *_args, **_kwargs: ToolOutput("<bad", "", 0)
    )
    with pytest.raises(ReconError, match="malformed XML"):
        run_nmap(scope, "192.0.2.10")


def test_runner_reports_unavailable_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: None)
    with pytest.raises(ToolExecutionError, match="unavailable"):
        run_approved_tool("nmap", ["--version"], timeout=1)


def test_runner_sanitizes_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", "true")
    monkeypatch.setattr("hacker_ai.tools.shutil.which", lambda _name: "/safe/nmap")
    monkeypatch.setattr(
        "hacker_ai.tools.inspect_tool",
        lambda spec: __import__("hacker_ai.tools", fromlist=["ToolStatus"]).ToolStatus(
            spec.name, spec.purpose, spec.source, "ready", path="/safe/nmap"
        ),
    )

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["secret-target"], 1)

    monkeypatch.setattr("hacker_ai.tools.subprocess.run", timeout)
    with pytest.raises(ToolExecutionError) as error:
        run_approved_tool("nmap", ["secret-target"], timeout=1)
    assert "secret-target" not in str(error.value)


def test_runner_requires_environment_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", raising=False)
    with pytest.raises(ToolExecutionError, match="Network execution is disabled"):
        run_approved_tool("nmap", ["--version"], timeout=1)


def test_cli_subfinder_scope_denial_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init", "."]).exit_code == 0
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "program:\n  name: CLI adapter test\nscope:\n  included:\n"
        "    - type: domain\n      value: example.com\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["program", "import", str(scope_file)]).exit_code == 0
    result = runner.invoke(app, ["recon", "subdomains", "outside.test", "--execute"])
    assert result.exit_code == 2
    assert "DENIED" in result.stdout
    entries = Storage(tmp_path / ".hacker-ai" / "state.db").audit_entries()
    assert entries[0]["action"] == "recon.subfinder.denied"


def test_cli_execution_gate_denial_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HACKER_AI_ALLOW_NETWORK_EXECUTION", raising=False)
    assert runner.invoke(app, ["init", "."]).exit_code == 0
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "program:\n  name: CLI gate test\nscope:\n  included:\n"
        "    - type: domain\n      value: example.com\nrules:\n"
        "  automated_scanning: limited\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["program", "import", str(scope_file)]).exit_code == 0

    result = runner.invoke(app, ["recon", "subdomains", "example.com", "--execute"])

    assert result.exit_code == 2
    assert "Network execution is disabled" in result.stdout
    entries = Storage(tmp_path / ".hacker-ai" / "state.db").audit_entries()
    assert entries[0]["action"] == "recon.subfinder.denied"
