# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""SARIF 2.1.0 output models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SarifMessage(BaseModel):
    text: str


class SarifArtifactLocation(BaseModel):
    uri: str


class SarifRegion(BaseModel):
    startLine: int
    endLine: int | None = None
    startColumn: int | None = None
    endColumn: int | None = None


class SarifPhysicalLocation(BaseModel):
    artifactLocation: SarifArtifactLocation
    region: SarifRegion | None = None


class SarifLocation(BaseModel):
    physicalLocation: SarifPhysicalLocation


class SarifRuleConfig(BaseModel):
    level: str = "warning"


class SarifRule(BaseModel):
    id: str
    name: str
    shortDescription: SarifMessage
    fullDescription: SarifMessage | None = None
    defaultConfiguration: SarifRuleConfig = Field(default_factory=SarifRuleConfig)


class SarifDriver(BaseModel):
    name: str = "malwar"
    version: str = "0.1.0"
    informationUri: str = "https://github.com/veritasaequitas/malwar"
    rules: list[SarifRule] = Field(default_factory=list)


class SarifTool(BaseModel):
    driver: SarifDriver = Field(default_factory=SarifDriver)


class SarifResult(BaseModel):
    ruleId: str
    level: str = "warning"
    message: SarifMessage
    locations: list[SarifLocation] = Field(default_factory=list)


class SarifRun(BaseModel):
    tool: SarifTool = Field(default_factory=SarifTool)
    results: list[SarifResult] = Field(default_factory=list)


class SarifReport(BaseModel):
    version: str = "2.1.0"
    runs: list[SarifRun] = Field(default_factory=list)
