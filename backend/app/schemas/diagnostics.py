from pydantic import BaseModel, Field
from typing import Any, Optional

class LivePingProbeRequest(BaseModel):
    target_host: str = Field(..., min_length=1, description="IP address or domain of target host/gateway")
    count: int = Field(default=4, ge=1, le=20, description="Number of ICMP packets to send")

class DiagnosticRunRequest(BaseModel):
    incident_id: Optional[str] = None
    telemetry: list[dict[str, Any]]
