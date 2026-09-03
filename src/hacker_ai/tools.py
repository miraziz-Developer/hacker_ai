from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Literal

from hacker_ai.config import ConfigurationError, require_network_execution


@dataclass(frozen=True)
class ToolSpec:
    name: str
    purpose: str
    source: str
    version_args: tuple[str, ...]
    identity_markers: tuple[str, ...]
    brew_formula: str | None = None
    apt_package: str | None = None
    executable_aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolStatus:
    name: str
    purpose: str
    source: str
    state: Literal["ready", "missing", "incompatible", "error"]
    path: str | None = None
    version: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


class ToolExecutionError(RuntimeError):
    """Raised when an approved external tool cannot be run safely."""


@dataclass(frozen=True)
class ToolOutput:
    stdout: str
    stderr: str
    returncode: int


TOOL_REGISTRY = (
    ToolSpec(
        name="nmap",
        purpose="Network and service inventory for explicitly scoped assets",
        source="https://nmap.org/",
        version_args=("--version",),
        identity_markers=("Nmap version",),
        brew_formula="nmap",
        apt_package="nmap",
    ),
    ToolSpec(
        name="subfinder",
        purpose="Passive subdomain discovery for explicitly scoped domains",
        source="https://github.com/projectdiscovery/subfinder",
        version_args=("-version",),
        identity_markers=("subfinder", "Current Version"),
        brew_formula="subfinder",
        apt_package="subfinder",
    ),
    ToolSpec(
        name="httpx",
        purpose="HTTP service metadata collection (ProjectDiscovery binary only)",
        source="https://github.com/projectdiscovery/httpx",
        version_args=("-version",),
        identity_markers=("projectdiscovery", "httpx"),
        apt_package="httpx-toolkit",
        executable_aliases=("httpx-toolkit",),
    ),
    ToolSpec(
        name="whatweb",
        purpose="Low-aggression web technology identification",
        source="https://github.com/urbanadventurer/WhatWeb",
        version_args=("--version",),
        identity_markers=("WhatWeb",),
        apt_package="whatweb",
    ),
)


def inspect_tool(spec: ToolSpec, timeout: float = 5.0) -> ToolStatus:
    """Identify an approved binary without invoking a shell or network operation."""
    first_failure: ToolStatus | None = None
    for executable_name in (spec.name, *spec.executable_aliases):
        executable = shutil.which(executable_name)
        if executable is None:
            continue
        status = _inspect_executable(spec, executable, timeout)
        if status.state == "ready":
            return status
        if first_failure is None:
            first_failure = status
    return first_failure or ToolStatus(spec.name, spec.purpose, spec.source, "missing")


def _inspect_executable(spec: ToolSpec, executable: str, timeout: float) -> ToolStatus:
    try:
        completed = subprocess.run(
            [executable, *spec.version_args],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(
            spec.name,
            spec.purpose,
            spec.source,
            "error",
            path=executable,
            detail=type(exc).__name__,
        )
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
    )
    first_line = output.splitlines()[0][:300] if output else None
    if completed.returncode != 0 or not all(
        marker.casefold() in output.casefold() for marker in spec.identity_markers
    ):
        return ToolStatus(
            spec.name,
            spec.purpose,
            spec.source,
            "incompatible",
            path=executable,
            version=first_line,
            detail="Binary identity did not match the approved project",
        )
    return ToolStatus(
        spec.name,
        spec.purpose,
        spec.source,
        "ready",
        path=executable,
        version=first_line,
    )


def inspect_toolchain() -> list[ToolStatus]:
    return [inspect_tool(spec) for spec in TOOL_REGISTRY]


def run_approved_tool(
    name: str,
    args: list[str],
    *,
    timeout: float,
    max_output_bytes: int = 2_000_000,
) -> ToolOutput:
    """Run a registry tool without a shell, inherited stdin, or unbounded runtime/output."""
    spec = next((item for item in TOOL_REGISTRY if item.name == name), None)
    if spec is None:
        raise ToolExecutionError("Tool is not in the approved registry")
    try:
        require_network_execution()
    except ConfigurationError as exc:
        raise ToolExecutionError(str(exc)) from exc
    status = inspect_tool(spec)
    if status.state != "ready" or status.path is None:
        raise ToolExecutionError(f"{name} is unavailable or failed its identity check")
    try:
        completed = subprocess.run(
            [status.path, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"{name} exceeded the {timeout:g}s timeout") from exc
    except OSError as exc:
        raise ToolExecutionError(f"{name} could not be started: {type(exc).__name__}") from exc
    size = len(completed.stdout.encode()) + len(completed.stderr.encode())
    if size > max_output_bytes:
        raise ToolExecutionError(f"{name} output exceeded the safety limit")
    if completed.returncode != 0:
        raise ToolExecutionError(f"{name} exited with status {completed.returncode}")
    return ToolOutput(completed.stdout, completed.stderr, completed.returncode)


def installation_plan() -> list[str]:
    """Return reproducible package-manager commands; never execute installation implicitly."""
    missing_formulae = [
        spec.brew_formula
        for spec in TOOL_REGISTRY
        if spec.brew_formula and inspect_tool(spec).state != "ready"
    ]
    if platform.system() == "Darwin" and shutil.which("brew") and missing_formulae:
        return [f"brew install {' '.join(missing_formulae)}"]
    missing_apt_packages = [
        spec.apt_package
        for spec in TOOL_REGISTRY
        if spec.apt_package and inspect_tool(spec).state != "ready"
    ]
    if platform.system() == "Linux" and shutil.which("apt-get") and missing_apt_packages:
        return ["sudo apt-get install --no-install-recommends " + " ".join(missing_apt_packages)]
    if missing_formulae:
        packages = ", ".join(missing_formulae)
        return [f"Install approved packages using the operating system package manager: {packages}"]
    return []
