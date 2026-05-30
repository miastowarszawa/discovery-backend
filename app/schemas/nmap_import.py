import uuid

from pydantic import BaseModel, Field


class NmapScriptResult(BaseModel):
    script_id: str
    output: str | None = None


class NmapServiceInfo(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    method: str | None = None
    conf: str | None = None
    cpes: list[str] = Field(default_factory=list)


class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str | None = None
    reason: str | None = None
    service: NmapServiceInfo | None = None
    scripts: list[NmapScriptResult] = Field(default_factory=list)


class NmapHost(BaseModel):
    addresses: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    status: str | None = None
    ports: list[NmapPort] = Field(default_factory=list)
    scripts: list[NmapScriptResult] = Field(default_factory=list)


class NmapParseSummary(BaseModel):
    total_hosts: int = 0
    up_hosts: int = 0
    total_ports: int = 0
    total_scripts: int = 0


class NmapParseResult(BaseModel):
    scanner: str | None = None
    args: str | None = None
    started: str | None = None
    hosts: list[NmapHost] = Field(default_factory=list)
    summary: NmapParseSummary = Field(default_factory=NmapParseSummary)


class ScopeEvaluation(BaseModel):
    in_scope: bool
    matched_by: list[str] = Field(default_factory=list)
    rejected_reasons: list[str] = Field(default_factory=list)


class HostScopeDecision(BaseModel):
    addresses: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    in_scope: bool
    matched_by: list[str] = Field(default_factory=list)
    rejected_reasons: list[str] = Field(default_factory=list)


class NmapImportRequest(BaseModel):
    target_id: uuid.UUID
    xml_text: str
    strict: bool = True


class NmapImportResponse(BaseModel):
    scan_id: uuid.UUID
    scan_type: str
    status: str
    strict: bool
    summary: dict

    model_config = {'from_attributes': True}
