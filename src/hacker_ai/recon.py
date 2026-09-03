from __future__ import annotations

import ipaddress
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx

from hacker_ai.config import ConfigurationError, require_network_execution
from hacker_ai.models import (
    AssetType,
    NmapResult,
    NmapService,
    ReconResult,
    ScopeDocument,
    SubfinderResult,
)
from hacker_ai.scope import (
    ScopeError,
    check_scope,
    normalize_target,
    resolve_ips,
    validate_resolved_ips,
)
from hacker_ai.tools import ToolExecutionError, run_approved_tool

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
)


class ReconError(RuntimeError):
    """Raised when a recon operation violates policy or cannot run safely."""


HOSTNAME_RE = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _active_scanning_allowed(document: ScopeDocument) -> None:
    if not document.rules.active_scanning or document.rules.automated_scanning == "forbidden":
        raise ReconError("Program rules do not allow automated active scanning")


def _domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ReconError("Domain is malformed") from exc
    if not HOSTNAME_RE.fullmatch(candidate):
        raise ReconError("Domain is malformed")
    return candidate


def run_subfinder(document: ScopeDocument, domain: str, timeout: float = 60.0) -> SubfinderResult:
    """Run bounded passive enumeration and retain only scope-approved hostnames."""
    root = _domain(domain)
    eligible = [
        asset
        for asset in document.scope.included
        if (asset.type == AssetType.DOMAIN and _domain(asset.value) == root)
        or (
            asset.type == AssetType.WILDCARD_DOMAIN
            and _domain(asset.value.removeprefix("*.")) == root
        )
    ]
    if not eligible:
        raise ReconError("Subfinder requires an explicitly scoped root domain")
    if document.rules.automated_scanning == "forbidden":
        raise ReconError("Program rules do not allow automated passive discovery")
    try:
        require_network_execution()
    except ConfigurationError as exc:
        raise ReconError(str(exc)) from exc
    rate_per_minute = max(1, int(min(asset.max_requests_per_second for asset in eligible) * 60))
    try:
        output = run_approved_tool(
            "subfinder",
            [
                "-d",
                root,
                "-silent",
                "-rlm",
                str(rate_per_minute),
                "-timeout",
                "10",
                "-max-time",
                "1",
            ],
            timeout=timeout,
        )
    except ToolExecutionError as exc:
        raise ReconError(str(exc)) from exc
    discovered: set[str] = set()
    rejected: set[str] = set()
    malformed = 0
    for raw_line in output.stdout.splitlines():
        try:
            host = _domain(raw_line)
        except ReconError:
            malformed += 1
            continue
        if host == root or not host.endswith(f".{root}"):
            rejected.add(host)
        elif check_scope(document, f"https://{host}").allowed:
            discovered.add(host)
        else:
            rejected.add(host)
    return SubfinderResult(
        domain=root,
        discovered=sorted(discovered),
        rejected=sorted(rejected),
        malformed_lines=malformed,
    )


def _nmap_target(document: ScopeDocument, target: str) -> tuple[str, list[str]]:
    raw = target.strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        network = None
    if network is not None and "/" in raw:
        canonical = str(network)
        included = any(
            asset.type == AssetType.CIDR
            and ipaddress.ip_network(asset.value, strict=False) == network
            for asset in document.scope.included
        )
        if not included:
            raise ReconError("Nmap requires an explicitly scoped CIDR")
        if document.scope.excluded:
            raise ReconError("CIDR scans are denied when scope exclusions are present")
        if network.num_addresses > 256:
            raise ReconError("CIDR scan exceeds the 256-address safety limit")
        return canonical, [canonical]
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is None:
        host = _domain(raw)
        included = any(
            asset.type == AssetType.DOMAIN and _domain(asset.value) == host
            for asset in document.scope.included
        )
        if not included or not check_scope(document, host).allowed:
            raise ReconError("Nmap requires an explicitly scoped, non-excluded domain")
        addresses = resolve_ips(host)
        if len(addresses) > 16:
            raise ReconError("Domain resolved to more than 16 addresses")
        try:
            validate_resolved_ips(document, host, addresses)
        except ScopeError as exc:
            raise ReconError(str(exc)) from exc
        return host, addresses
    canonical_ip = address.compressed
    included = any(
        asset.type == AssetType.IP and ipaddress.ip_address(asset.value) == address
        for asset in document.scope.included
    )
    if not included or not check_scope(document, canonical_ip).allowed:
        raise ReconError("Nmap requires an explicitly scoped, non-excluded IP")
    validate_resolved_ips(document, canonical_ip, [canonical_ip])
    return canonical_ip, [canonical_ip]


def _ports(value: str) -> str:
    try:
        ports = sorted({int(item) for item in value.split(",")})
    except ValueError as exc:
        raise ReconError("Ports must be a comma-separated list of integers") from exc
    if not ports or len(ports) > 20 or any(port < 1 or port > 65535 for port in ports):
        raise ReconError("Specify between 1 and 20 valid TCP ports")
    return ",".join(str(port) for port in ports)


def run_nmap(
    document: ScopeDocument,
    target: str,
    ports: str = "80,443,8080,8443",
    timeout: float = 60.0,
) -> NmapResult:
    """Run a fixed, low-concurrency TCP inventory profile against explicit scope."""
    _active_scanning_allowed(document)
    normalized, scan_targets = _nmap_target(document, target)
    try:
        require_network_execution()
    except ConfigurationError as exc:
        raise ReconError(str(exc)) from exc
    safe_ports = _ports(ports)
    args = [
        "-sT",
        "-n",
        "--max-rate",
        "10",
        "--max-parallelism",
        "1",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{max(1, int(timeout))}s",
        "-p",
        safe_ports,
        "-oX",
        "-",
        "--",
        *scan_targets,
    ]
    try:
        output = run_approved_tool("nmap", args, timeout=timeout + 5)
        root = ET.fromstring(output.stdout)
    except ToolExecutionError as exc:
        raise ReconError(str(exc)) from exc
    except ET.ParseError as exc:
        raise ReconError("Nmap returned malformed XML") from exc
    services: list[NmapService] = []
    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        if address_node is None or not address_node.get("addr"):
            continue
        address = str(address_node.get("addr"))
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None:
                continue
            service_node = port_node.find("service")
            services.append(
                NmapService(
                    address=address,
                    port=int(port_node.get("portid", "0")),
                    state=state_node.get("state", "unknown")[:30],
                    service=(service_node.get("name", "")[:80] or None)
                    if service_node is not None
                    else None,
                )
            )
    return NmapResult(target=normalized, scanned_addresses=scan_targets, services=services)


def recon_target(document: ScopeDocument, target: str, timeout: float = 10.0) -> ReconResult:
    decision = check_scope(document, target)
    if not decision.allowed:
        raise ReconError(decision.reason)
    _active_scanning_allowed(document)
    try:
        require_network_execution()
    except ConfigurationError as exc:
        raise ReconError(str(exc)) from exc

    scheme, host, port, path = normalize_target(target)
    ips = resolve_ips(host)
    validate_resolved_ips(document, target, ips)
    netloc = f"{host}:{port}" if port else host
    url = f"{scheme}://{netloc}{path}"
    rate = decision.matched_asset.max_requests_per_second if decision.matched_asset else 1.0
    time.sleep(1 / rate)

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": "hacker-ai-authorized-security-review/0.1"},
        ) as client:
            response = client.get(url)
        present = {
            name: response.headers[name] for name in SECURITY_HEADERS if name in response.headers
        }
        return ReconResult(
            target=url,
            resolved_ips=ips,
            status_code=response.status_code,
            server=response.headers.get("server"),
            content_type=response.headers.get("content-type"),
            security_headers=present,
            missing_security_headers=[name for name in SECURITY_HEADERS if name not in present],
        )
    except (httpx.HTTPError, ScopeError) as exc:
        return ReconResult(target=url, resolved_ips=ips, error=f"{type(exc).__name__}: {exc}")


def redirect_is_allowed(document: ScopeDocument, location: str) -> bool:
    parsed = urlparse(location)
    return bool(parsed.hostname and check_scope(document, location).allowed)
