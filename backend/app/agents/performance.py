"""Deterministic telemetry and performance analysis for NetCoop AI."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional

from pydantic import Field, ValidationError, field_validator
from .common import (
    AgentError, AgentFinding, AgentName, AgentResponse, ErrorCode,
    ExecutionStatus, Evidence, EvidenceType, FindingType, ProtocolBaseModel,
    Severity, utc_now,
)

# Starter defaults only; real deployments should configure thresholds to their SLAs.
DEFAULT_THRESHOLDS = {
    "latency_ms": 100.0,
    "packet_loss_pct": 1.0,
    "jitter_ms": 30.0,
    "bandwidth_utilization_pct": 80.0,
}


class PerformanceTelemetry(ProtocolBaseModel):
    """One performance observation from a probe or network device."""
    metric_name: str = Field(min_length=1, max_length=128)
    value: float
    unit: str = Field(min_length=1, max_length=32)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    interface_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    segment_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    service_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    expected_value: Optional[float] = None
    record_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("timestamp must include a timezone")
        return value


class PerformanceAgent:
    """Analyzes latency, packet loss, jitter, throughput and link utilization.

    Threshold comparisons and unit conversions use deterministic Python logic.
    """
    agent_name = AgentName.PERFORMANCE

    def __init__(self, thresholds: Optional[dict[str, float]] = None) -> None:
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        for name, value in self.thresholds.items():
            if not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"Threshold '{name}' must be a non-negative number.")

    @staticmethod
    def _canonical_metric(name: str) -> Optional[str]:
        key = name.strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "latency": "latency_ms", "rtt": "latency_ms", "icmp_rtt": "latency_ms",
            "icmp_rtt_p95": "latency_ms", "latency_ms": "latency_ms",
            "packet_loss": "packet_loss_pct", "packet_loss_rate": "packet_loss_pct",
            "packet_loss_pct": "packet_loss_pct", "jitter": "jitter_ms",
            "jitter_ms": "jitter_ms", "throughput": "throughput_mbps",
            "throughput_mbps": "throughput_mbps",
            "bandwidth_utilization": "bandwidth_utilization_pct",
            "bandwidth_utilization_pct": "bandwidth_utilization_pct",
            "utilization": "bandwidth_utilization_pct",
        }
        return aliases.get(key)

    @staticmethod
    def _normalize(metric: str, value: float, unit: str) -> tuple[float, str]:
        u = unit.strip().lower()
        if metric in ("latency_ms", "jitter_ms"):
            factors = {"ms": 1.0, "millisecond": 1.0, "milliseconds": 1.0,
                       "s": 1000.0, "sec": 1000.0, "seconds": 1000.0}
            if u not in factors:
                raise ValueError(f"Unsupported time unit '{unit}'.")
            return value * factors[u], "ms"
        if metric in ("packet_loss_pct", "bandwidth_utilization_pct"):
            factors = {"%": 1.0, "percent": 1.0, "fraction": 100.0, "ratio": 100.0}
            if u not in factors:
                raise ValueError(f"Unsupported percentage unit '{unit}'.")
            normalized = value * factors[u]
            if not 0 <= normalized <= 100:
                raise ValueError(f"{metric} must normalize to a value between 0 and 100.")
            return normalized, "%"
        if metric == "throughput_mbps":
            factors = {"mbps": 1.0, "gbps": 1000.0, "kbps": 0.001}
            if u not in factors:
                raise ValueError(f"Unsupported throughput unit '{unit}'.")
            return value * factors[u], "Mbps"
        raise ValueError(f"Unsupported metric '{metric}'.")

    def analyze(self, telemetry: list[dict[str, Any] | PerformanceTelemetry]) -> AgentResponse:
        started = utc_now()
        findings: list[AgentFinding] = []
        errors: list[AgentError] = []
        completed: list[str] = []
        evaluated_metrics: set[str] = set()

        for index, raw in enumerate(telemetry):
            try:
                has_explicit_ts = (
                    ("timestamp" in raw and raw["timestamp"] is not None)
                    if isinstance(raw, Mapping)
                    else ("timestamp" in raw.model_fields_set if isinstance(raw, PerformanceTelemetry) else False)
                )
                item = raw if isinstance(raw, PerformanceTelemetry) else PerformanceTelemetry.model_validate(raw)
                metric = self._canonical_metric(item.metric_name)
                if metric is None:
                    raise ValueError(f"Unknown performance metric '{item.metric_name}'.")
                if item.value < 0:
                    raise ValueError("Metric values cannot be negative.")
                value, unit = self._normalize(metric, item.value, item.unit)
                expected = None
                if item.expected_value is not None:
                    expected, _ = self._normalize(metric, item.expected_value, item.unit)
                completed.append(metric)
                evaluated_metrics.add(metric)

                threshold = self.thresholds.get(metric)
                # Throughput is only flagged when the caller supplies an expected minimum.
                abnormal = value < expected if metric == "throughput_mbps" and expected is not None else (
                    value > threshold if threshold is not None else False
                )
                if not abnormal:
                    continue

                code = {
                    "latency_ms": "HIGH_LATENCY", "packet_loss_pct": "HIGH_PACKET_LOSS",
                    "jitter_ms": "HIGH_JITTER", "bandwidth_utilization_pct": "HIGH_BANDWIDTH_UTILIZATION",
                    "throughput_mbps": "LOW_THROUGHPUT",
                }[metric]
                baseline = expected if metric == "throughput_mbps" else threshold
                severity = self._severity(value, baseline)
                evidence = Evidence(
                    evidence_type=EvidenceType.METRIC, metric_name=metric,
                    observed_value=round(value, 4), unit=unit,
                    expected_value=round(baseline, 4) if baseline is not None else None,
                    device_id=item.device_id, interface_id=item.interface_id,
                    segment_id=item.segment_id, service_id=item.service_id,
                    source_agent=AgentName.PERFORMANCE,
                    telemetry_record_id=item.record_id,
                    description=f"{item.metric_name} normalized to {value:.4g} {unit}.",
                    timestamp=item.timestamp,
                )
                finding_limitations = (
                    []
                    if has_explicit_ts
                    else [
                        "Source performance telemetry omitted an explicit observation timestamp; "
                        "timestamp defaulted to ingestion time (utc_now)."
                    ]
                )
                finding = AgentFinding(
                    agent_source=AgentName.PERFORMANCE, finding_code=code,
                    finding_type=FindingType.PERFORMANCE_DEGRADATION, severity=severity,
                    summary=f"{item.metric_name} exceeded its performance threshold",
                    description=f"Observed {value:.4g} {unit}; comparison threshold/baseline was {baseline:.4g} {unit}.",
                    confidence=0.85 if expected is not None else 0.80,
                    affected_devices=[item.device_id] if item.device_id else [],
                    affected_segments=[item.segment_id] if item.segment_id else [],
                    evidence=[evidence],
                    limitations=finding_limitations,
                    timestamp=item.timestamp,
                )
                if not has_explicit_ts:
                    evidence.model_fields_set.discard("timestamp")
                    finding.model_fields_set.discard("timestamp")
                findings.append(finding)
            except (ValidationError, ValueError, TypeError) as exc:
                code = ErrorCode.MALFORMED_TELEMETRY if isinstance(exc, ValidationError) else ErrorCode.UNKNOWN_METRIC_OR_UNIT
                errors.append(AgentError(
                    error_code=code,
                    message=f"Telemetry record at index {index} was skipped: {exc}",
                    source_agent=AgentName.PERFORMANCE,
                    details={"record_index": index},
                ))

        if not telemetry:
            errors.append(AgentError(
                error_code=ErrorCode.MISSING_INPUT,
                message="No performance telemetry records were supplied.",
                source_agent=AgentName.PERFORMANCE,
            ))

        status = (ExecutionStatus.FAILED if not completed and errors
                  else ExecutionStatus.PARTIAL if errors
                  else ExecutionStatus.SUCCESS)
        elapsed = (utc_now() - started).total_seconds() * 1000
        return AgentResponse(
            agent_name=AgentName.PERFORMANCE, status=status, findings=findings,
            completed_checks=sorted(set(completed)), errors=errors,
            processing_time_ms=elapsed,
            execution_metadata={"records_received": len(telemetry),
                                "records_evaluated": len(completed),
                                "metrics_evaluated": sorted(evaluated_metrics)},
        )

    @staticmethod
    def _severity(value: float, baseline: Optional[float]) -> Severity:
        if baseline is None or baseline <= 0:
            return Severity.HIGH
        ratio = value / baseline
        if ratio >= 2.0:
            return Severity.CRITICAL
        if ratio >= 1.5:
            return Severity.HIGH
        return Severity.MEDIUM


def analyze_performance(telemetry: list[dict[str, Any] | PerformanceTelemetry],
                        thresholds: Optional[dict[str, float]] = None) -> AgentResponse:
    """Convenience entry point for the orchestrator and tests."""
    return PerformanceAgent(thresholds).analyze(telemetry)
