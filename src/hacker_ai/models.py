from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetType(StrEnum):
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"


class ScopeAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: AssetType
    value: str = Field(min_length=1)
    max_requests_per_second: float = Field(default=1.0, gt=0, le=10)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        return value.strip()


class Program(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    platform: str = "custom"


class ScopeList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    included: list[ScopeAsset] = Field(min_length=1)
    excluded: list[ScopeAsset] = Field(default_factory=list)


class Rules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active_scanning: bool = False
    automated_scanning: Literal["forbidden", "limited", "allowed"] = "forbidden"
    denial_of_service: bool = False
    social_engineering: bool = False
    data_exfiltration: bool = False
    notes: str = ""

    @field_validator("denial_of_service", "social_engineering", "data_exfiltration")
    @classmethod
    def dangerous_capabilities_must_be_disabled(cls, value: bool) -> bool:
        if value:
            raise ValueError("This application never enables destructive or deceptive capabilities")
        return value


class ScopeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program: Program
    scope: ScopeList
    rules: Rules = Field(default_factory=Rules)


class ScopeDecision(BaseModel):
    allowed: bool
    target: str
    reason: str
    matched_asset: ScopeAsset | None = None


class ReconResult(BaseModel):
    target: str
    resolved_ips: list[str]
    status_code: int | None = None
    server: str | None = None
    content_type: str | None = None
    security_headers: dict[str, str] = Field(default_factory=dict)
    missing_security_headers: list[str] = Field(default_factory=list)
    error: str | None = None


class SubfinderResult(BaseModel):
    domain: str
    discovered: list[str] = Field(default_factory=list)
    rejected: list[str] = Field(default_factory=list)
    malformed_lines: int = 0


class NmapService(BaseModel):
    address: str
    protocol: Literal["tcp"] = "tcp"
    port: int = Field(ge=1, le=65535)
    state: str
    service: str | None = None


class NmapResult(BaseModel):
    target: str
    scanned_addresses: list[str]
    services: list[NmapService] = Field(default_factory=list)


class FindingDraft(BaseModel):
    title: str
    severity: Literal["informational", "low", "medium", "high", "critical"]
    summary: str
    evidence: list[str]
    impact: str
    remediation: str
    confidence: Literal["low", "medium", "high"]
    needs_human_validation: bool = True


class AgentPlan(BaseModel):
    """A deliberately small set of actions available to the conversational planner."""

    model_config = ConfigDict(extra="forbid")

    action: Literal[
        "help",
        "status",
        "scope_check",
        "recon_http",
        "recon_subdomains",
        "recon_ports",
        "assess_web",
    ]
    target: str | None = None
    ports: str | None = None
    explanation: str = Field(min_length=1, max_length=1000)
