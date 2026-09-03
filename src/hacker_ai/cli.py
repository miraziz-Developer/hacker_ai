from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Annotated, Never

import typer
from rich.console import Console
from rich.table import Table

from hacker_ai.ai import AnalysisError, AzureAnalyzer, finding_to_dict
from hacker_ai.config import ConfigurationError, Settings, TelegramSettings, Workspace
from hacker_ai.dataset import DatasetError, audit_dataset, prepare_dataset
from hacker_ai.recon import ReconError, recon_target, run_nmap, run_subfinder
from hacker_ai.redaction import redact_secrets
from hacker_ai.report import render_markdown
from hacker_ai.scope import ScopeError, check_scope, load_scope
from hacker_ai.storage import Storage
from hacker_ai.telegram import TelegramError, run_bot
from hacker_ai.tools import inspect_toolchain, installation_plan

app = typer.Typer(
    name="hacker-ai",
    help="Private, scope-enforced assistant for authorized bug bounty work.",
    no_args_is_help=True,
)
program_app = typer.Typer(help="Manage bug bounty program scope.")
scope_app = typer.Typer(help="Validate targets against the imported scope.")
recon_app = typer.Typer(help="Run low-impact, scope-enforced reconnaissance.")
analyze_app = typer.Typer(help="Analyze sanitized evidence with Azure OpenAI.")
report_app = typer.Typer(help="Render reviewable finding reports.")
audit_app = typer.Typer(help="Inspect the immutable-by-default local audit trail.")
ai_app = typer.Typer(help="Configure and test the Azure OpenAI connection.")
dataset_app = typer.Typer(help="Audit and safely prepare JSONL fine-tuning datasets.")
tools_app = typer.Typer(help="Inspect the approved external security toolchain.")
telegram_app = typer.Typer(help="Run the allowlisted Telegram agent interface.")
app.add_typer(program_app, name="program")
app.add_typer(scope_app, name="scope")
app.add_typer(recon_app, name="recon")
app.add_typer(analyze_app, name="analyze")
app.add_typer(report_app, name="report")
app.add_typer(audit_app, name="audit")
app.add_typer(ai_app, name="ai")
app.add_typer(dataset_app, name="dataset")
app.add_typer(tools_app, name="tools")
app.add_typer(telegram_app, name="telegram")
console = Console()


def fail(message: str) -> Never:
    console.print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(code=1)


def current() -> tuple[Workspace, Storage]:
    workspace = Workspace.discover()
    storage = Storage(workspace.database)
    storage.initialize()
    return workspace, storage


@app.command()
def doctor() -> None:
    """Validate local configuration without sending an Azure request."""
    try:
        settings = Settings.from_environment()
        table = Table("Check", "Value")
        table.add_row("Endpoint", settings.base_url)
        table.add_row("Deployment", settings.deployment)
        table.add_row("Authentication", settings.auth_mode)
        table.add_row("Timeout", f"{settings.timeout_seconds:g}s")
        credential = "API key configured" if settings.api_key else "DefaultAzureCredential"
        table.add_row("Credential", credential)
        console.print(table)
        console.print("[green]Configuration is valid.[/green]")
    except ConfigurationError as exc:
        fail(str(exc))


@ai_app.command("test")
def ai_test() -> None:
    """Send one harmless request to verify Azure authentication and deployment access."""
    try:
        settings = Settings.from_environment()
        output = AzureAnalyzer(settings).test_connection()
        console.print(f"[green]Azure connection succeeded.[/green] Model response: {output}")
    except (ConfigurationError, AnalysisError) as exc:
        fail(redact_secrets(str(exc)))


@telegram_app.command("run")
def telegram_run() -> None:
    """Long-poll Telegram and execute only constrained, scope-enforced agent actions."""
    try:
        workspace, _ = current()
        telegram_settings = TelegramSettings.from_environment()
        analyzer = AzureAnalyzer(Settings.from_environment())
        console.print("[green]Telegram agent started. Press Ctrl-C to stop.[/green]")
        run_bot(telegram_settings, workspace, analyzer)
    except (ConfigurationError, AnalysisError, TelegramError) as exc:
        fail(redact_secrets(str(exc)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Telegram agent stopped.[/yellow]")


@dataset_app.command("audit")
def dataset_audit(
    input_file: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
) -> None:
    """Stream a JSONL dataset and report schema, governance, and secret risks."""
    try:
        console.print_json(json.dumps(audit_dataset(input_file).to_dict()))
    except DatasetError as exc:
        fail(str(exc))


@dataset_app.command("prepare")
def dataset_prepare(
    input_file: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output_dir: Annotated[Path, typer.Argument(file_okay=False)],
    validation_percent: Annotated[int, typer.Option(min=1, max=30)] = 10,
) -> None:
    """Filter, deduplicate, and split safe ChatML data without loading it into memory."""
    try:
        manifest = prepare_dataset(input_file, output_dir, validation_percent)
        console.print_json(json.dumps(manifest))
        console.print(f"[green]Prepared reviewable dataset:[/green] {output_dir.resolve()}")
    except DatasetError as exc:
        fail(str(exc))


@tools_app.command("doctor")
def tools_doctor() -> None:
    """Verify approved binaries, versions, and package-name collisions."""
    statuses = inspect_toolchain()
    table = Table("Tool", "State", "Version", "Path")
    for status in statuses:
        color = "green" if status.state == "ready" else "yellow"
        table.add_row(
            status.name,
            f"[{color}]{status.state.upper()}[/{color}]",
            status.version or status.detail or "-",
            status.path or "-",
        )
    console.print(table)
    if any(status.state == "incompatible" for status in statuses):
        console.print("[yellow]An incompatible same-name binary will not be used.[/yellow]")


@tools_app.command("install-plan")
def tools_install_plan() -> None:
    """Print reproducible installation commands without executing them."""
    commands = installation_plan()
    if not commands:
        console.print("[green]All package-managed tools are ready.[/green]")
        return
    for command in commands:
        console.print(command)


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Workspace directory")] = Path("."),
) -> None:
    """Initialize a private local workspace."""
    workspace = Workspace(path.resolve())
    workspace.state_dir.mkdir(parents=True, exist_ok=True)
    Storage(workspace.database).initialize()
    console.print(f"[green]Initialized:[/green] {workspace.root}")
    console.print("Next: hacker-ai program import examples/scope.yaml")


@program_app.command("import")
def import_program(path: Annotated[Path, typer.Argument(exists=True, readable=True)]) -> None:
    """Validate and import a universal YAML/JSON scope document."""
    try:
        workspace, storage = current()
        document = load_scope(path)
        workspace.scope_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, workspace.scope_file)
        storage.audit(
            "program.import",
            allowed=True,
            details={"program": document.program.name, "source": str(path.resolve())},
        )
        console.print(f"[green]Imported scope:[/green] {document.program.name}")
    except (ConfigurationError, ScopeError, OSError) as exc:
        fail(str(exc))


@scope_app.command("check")
def scope_check(target: str) -> None:
    """Check a target using default-deny scope policy."""
    try:
        workspace, storage = current()
        decision = check_scope(load_scope(workspace.scope_file), target)
        storage.audit(
            "scope.check",
            target=target,
            allowed=decision.allowed,
            details={"reason": decision.reason},
        )
        color = "green" if decision.allowed else "red"
        status = "ALLOWED" if decision.allowed else "DENIED"
        console.print(f"[{color}]{status}[/{color}]: {decision.reason}")
        if not decision.allowed:
            raise typer.Exit(code=2)

    except (ConfigurationError, ScopeError) as exc:
        fail(str(exc))


@recon_app.command("run")
def recon_run(
    target: str,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Required acknowledgement for an active HTTP request."),
    ] = False,
) -> None:
    """Resolve DNS and perform one low-impact HTTP GET without following redirects."""
    try:
        workspace, storage = current()
        document = load_scope(workspace.scope_file)
        decision = check_scope(document, target)
        if not decision.allowed:
            storage.audit(
                "recon.denied",
                target=target,
                allowed=False,
                details={"reason": decision.reason},
            )
            fail(decision.reason)
        console.print(
            f"Target: {target}\nAction: DNS resolution + one HTTP GET\nScope: {decision.reason}"
        )

        if not execute:
            storage.audit("recon.dry-run", target=target, allowed=True)
            console.print("[yellow]Dry run only.[/yellow] Add --execute to send the request.")
            return

        result = recon_target(document, target)
        payload = result.model_dump(mode="json")
        storage.audit("recon.run", target=target, allowed=True, details=payload)
        console.print_json(json.dumps(payload))

    except (ConfigurationError, ScopeError, ReconError) as exc:
        fail(str(exc))


def _tool_recon(
    *,
    action: str,
    target: str,
    execute: bool,
    operation: str,
    run: object,
) -> None:
    workspace, storage = current()
    document = load_scope(workspace.scope_file)
    console.print(f"Target: {target}\nAction: {operation}")
    if not execute:
        storage.audit(f"recon.{action}.dry-run", target=target, allowed=True)
        console.print("[yellow]Dry run only.[/yellow] Add --execute to invoke the approved tool.")
        return
    try:
        if action == "subfinder":
            payload = run_subfinder(document, target).model_dump(mode="json")
        else:
            payload = run_nmap(document, target, ports=str(run)).model_dump(mode="json")
    except ReconError as exc:
        storage.audit(
            f"recon.{action}.denied",
            target=target,
            allowed=False,
            details={"reason": str(exc)},
        )
        console.print(f"[red]DENIED[/red]: {exc}")
        raise typer.Exit(code=2) from exc
    storage.audit(f"recon.{action}.run", target=target, allowed=True, details=payload)
    console.print_json(json.dumps(payload))


@recon_app.command("subdomains")
def recon_subdomains(
    domain: str,
    execute: Annotated[bool, typer.Option("--execute")] = False,
) -> None:
    """Run passive Subfinder discovery for an explicitly scoped root domain."""
    try:
        _tool_recon(
            action="subfinder",
            target=domain,
            execute=execute,
            operation="bounded passive subdomain discovery",
            run=None,
        )
    except (ConfigurationError, ScopeError) as exc:
        fail(str(exc))


@recon_app.command("ports")
def recon_ports(
    target: str,
    ports: Annotated[
        str, typer.Option(help="Comma-separated TCP ports; maximum 20.")
    ] = "80,443,8080,8443",
    execute: Annotated[bool, typer.Option("--execute")] = False,
) -> None:
    """Run a conservative Nmap TCP inventory against explicit scope."""
    try:
        _tool_recon(
            action="nmap",
            target=target,
            execute=execute,
            operation=f"TCP connect inventory on ports {ports}",
            run=ports,
        )
    except (ConfigurationError, ScopeError) as exc:
        fail(str(exc))


@analyze_app.command("file")
def analyze_file(
    target: str,
    evidence_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
) -> None:
    """Redact and analyze an evidence file, then save a needs-review finding."""
    try:
        workspace, storage = current()
        document = load_scope(workspace.scope_file)
        decision = check_scope(document, target)
        if not decision.allowed:
            storage.audit(
                "analyze.denied",
                target=target,
                allowed=False,
                details={"reason": decision.reason},
            )
            fail(decision.reason)
        evidence = evidence_file.read_text(encoding="utf-8")
        if len(evidence.encode()) > 1_000_000:
            fail("Evidence is larger than the 1 MB safety limit")
        finding = AzureAnalyzer(Settings.from_environment()).analyze(target, evidence, document)
        payload = finding_to_dict(finding)
        finding_id = storage.save_finding(target, payload)
        storage.audit(
            "analyze.file",
            target=target,
            allowed=True,
            details={"finding_id": finding_id, "source": evidence_file.name},
        )
        console.print_json(json.dumps(payload))
        console.print(f"[green]Saved finding #{finding_id} as needs-review.[/green]")
    except (ConfigurationError, ScopeError, AnalysisError, OSError, ValueError) as exc:
        fail(redact_secrets(str(exc)))


@report_app.command("render")
def report_render(
    finding_id: int,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Render a finding as a sanitized Markdown draft."""
    try:
        _, storage = current()
        record = storage.get_finding(finding_id)
        if record is None:
            fail(f"Finding #{finding_id} does not exist")
        report = render_markdown(record)
        if output:
            output.write_text(report, encoding="utf-8")
            console.print(f"[green]Written:[/green] {output.resolve()}")
        else:
            console.print(report)
        storage.audit("report.render", allowed=True, details={"finding_id": finding_id})
    except (ConfigurationError, OSError) as exc:
        fail(str(exc))


@audit_app.command("show")
def audit_show(limit: Annotated[int, typer.Option(min=1, max=500)] = 50) -> None:
    """Show recent local audit entries without exposing evidence or credentials."""
    try:
        _, storage = current()
        table = Table("ID", "Time", "Action", "Target", "Allowed")
        for row in storage.audit_entries(limit):
            table.add_row(
                str(row["id"]),
                row["created_at"],
                row["action"],
                row["target"] or "-",
                str(bool(row["allowed"])),
            )
        console.print(table)
    except ConfigurationError as exc:
        fail(str(exc))
