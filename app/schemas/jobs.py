from datetime import datetime
from pydantic import BaseModel, Field
from uuid import UUID


class ReconJobPayload(BaseModel):
    target_id: UUID
    scan_id: UUID
    domain: str = Field(min_length=1)
    requested_at: datetime
    tools: list[str] = Field(default_factory=lambda: ['subfinder', 'httpx', 'naabu'])
