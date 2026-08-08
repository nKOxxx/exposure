"""API request/response schemas (Pydantic)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SubjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    alt_names: list[str] = Field(default_factory=list)
    city: str | None = None
    country: str | None = None
    employers: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list)
    personal_domains: list[str] = Field(default_factory=list)


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_search: bool = False
    include_sensitive: bool = False
    manual_urls: list[str] = Field(default_factory=list)


class FindingDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(pattern="^(me|not_me|unsure)$")


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    registry_route_id: str | None = None
    route: str | None = None


class CaseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_state: str
    note: str | None = None


class ProviderUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    api_key: str | None = None  # stored in the secret vault, never in the DB
    config: dict[str, Any] = Field(default_factory=dict)
