from datetime import datetime, timezone
from typing import any
from pydantic inport BaseModel, Field, ConfigDict, field_validator
class TelemetryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(
        min_length=1,
        max_length=120
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)

    )
    metrics: dict[str, Any]
    @field_validator("metrics")
    @classmethod
    def validate_matrics(cls, value):
        if not value:
            raise ValueError("Metrics cannot be empty")
        limits = {
            "latency_ms": (0, 60000),
            "jitter_ms": (0, 60000),
            "packet_lost_pct": (0,100),
            "link_utilization_pct": (0, 100),
            "cpu_percent": (0, 100),
            "memory_percent": (0, 100),
             "signal_dbm": (-120, 0),
            "throughput_mbps": (0, 10**9),
            "queue_drops": (0, 10**12),
            "interface_errors": (0, 10**12)
        }
        for key, (minimum, maximum) in limits.items():
            if key not in value:
                continue
            number = value[key]
            if (
                not isinstance(number, (int, float))
                or isinstance(number, bool)
            ):
                raise ValueError(f"{key} must be numeric")
            if not minimum <=number <= maximum:
                raise ValueError(f"Invalid value for {key}")
        for key in ["dns_ok", "dhcp_ok"]:
            if key in value and not isinstance(value[key], bool):
                raise ValueError(f"{key} must be boolean")
        return value 