"""Scenario file schema (v0.1 subset).

Mirrors docs/scenario-schema.md. Step-specific fields are not enforced
here — they're validated by the step dispatcher in runner.py. Adding
strict per-step models is a v0.2 hardening goal.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Canary(BaseModel):
    id: str
    type: Literal["http", "dns", "file"] = "http"


class Fixture(BaseModel):
    id: str
    path: str
    content: str = ""
    must_be_outside_roots: bool = False


class Setup(BaseModel):
    canaries: list[Canary] = []
    fixtures: list[Fixture] = []


class Requires(BaseModel):
    transport: list[str] = []
    capabilities: list[dict[str, list[str]]] = []
    spec_features: list[str] = []


class Step(BaseModel):
    model_config = ConfigDict(extra="allow")
    step: str


class Oracle(BaseModel):
    any_of: list[dict[str, Any]] = []
    all_of: list[dict[str, Any]] = []


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    references: list[str] = []
    spec_versions: list[str]
    requires: Requires = Field(default_factory=Requires)
    setup: Setup = Field(default_factory=Setup)
    attack: list[Step]
    oracle: Oracle
    cleanup: list[dict[str, Any]] = []
    expected_in_baseline: bool = False
