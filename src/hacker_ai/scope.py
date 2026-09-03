from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

import yaml

from hacker_ai.models import AssetType, ScopeAsset, ScopeDecision, ScopeDocument


class ScopeError(ValueError):
    """Raised when scope input is malformed or unsafe."""


def load_scope(path: Path) -> ScopeDocument:
    try:
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        return ScopeDocument.model_validate(raw)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ScopeError(f"Unable to load scope from {path}: {exc}") from exc


def normalize_target(target: str) -> tuple[str, str, int | None, str]:
    value = target.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Target must be a valid HTTP(S) URL, domain, or IP")

    host = parsed.hostname.rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError("Target contains an invalid hostname") from exc
    path = parsed.path or "/"
    return parsed.scheme, host, parsed.port, path


def _asset_matches(asset: ScopeAsset, target: str) -> bool:
    _, host, _, path = normalize_target(target)
    value = asset.value.strip()
    if asset.type == AssetType.DOMAIN:
        return host == value.rstrip(".").lower()
    if asset.type == AssetType.WILDCARD_DOMAIN:
        suffix = value.removeprefix("*.").rstrip(".").lower()
        return host.endswith(f".{suffix}") and host != suffix
    if asset.type == AssetType.IP:
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(value)
        except ValueError:
            return False
    if asset.type == AssetType.CIDR:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    if asset.type == AssetType.URL:
        asset_scheme, asset_host, asset_port, asset_path = normalize_target(value)
        target_scheme, _, target_port, _ = normalize_target(target)
        prefix = asset_path if asset_path.endswith("/") else f"{asset_path}/"
        path_match = path == asset_path or path.startswith(prefix)
        return (
            host == asset_host
            and target_scheme == asset_scheme
            and target_port == asset_port
            and path_match
        )
    return False


def check_scope(document: ScopeDocument, target: str) -> ScopeDecision:
    normalize_target(target)
    for asset in document.scope.excluded:
        if _asset_matches(asset, target):
            return ScopeDecision(
                allowed=False,
                target=target,
                reason="Target matches an explicit exclusion",
                matched_asset=asset,
            )
    for asset in document.scope.included:
        if _asset_matches(asset, target):
            return ScopeDecision(
                allowed=True,
                target=target,
                reason="Target matches the allowlist",
                matched_asset=asset,
            )
    return ScopeDecision(allowed=False, target=target, reason="Target is not in the allowlist")


def resolve_ips(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS resolution failed for {host}: {exc}") from exc
    return sorted({str(record[4][0]) for record in records})


def validate_resolved_ips(document: ScopeDocument, target: str, ips: list[str]) -> None:
    """Block surprising private destinations unless directly covered by IP/CIDR scope."""
    for raw_ip in ips:
        ip = ipaddress.ip_address(raw_ip)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
            continue
        directly_scoped = any(
            asset.type in {AssetType.IP, AssetType.CIDR} and _asset_matches(asset, raw_ip)
            for asset in document.scope.included
        )
        if not directly_scoped:
            raise ScopeError(
                f"{target} resolves to non-public address {raw_ip}; add that IP/CIDR explicitly"
            )
