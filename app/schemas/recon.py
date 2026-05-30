import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ReconJobCreate(BaseModel):
    target_id: uuid.UUID
    scan_type: str = Field(default='recon')
    config_json: dict = Field(default_factory=dict)


class ReconJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    status: str
    config_json: dict = Field(default_factory=dict)
    result_json: dict = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
