"""Deterministic analysis of network device and interface infrastructure health for NetCoop AI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from time import perf_counter
from typing import Any, Optional, Union

from pydantic import Field, ValidationError, field_validator, model_validator

from .common import (
    AgentError,
    AgentFinding,
    AgentName,
    AgentResponse,
    ErrorCode,
    Evidence,
    EvidenceType,
    ExecutionStatus,
    FindingType,
    ProtocolBaseModel,
    Severity,
    ensure_utc_timestamp,
    utc_now,
)

# =====================================================================
# 1. CONFIGURABLE THRESHOLD DEFAULTS & CONSTANTS
# =====================================================================

DEFAULT_THRESHOLDS: dict[str, float] = {
    "cpu_warning_pct": 80.0,
    "cpu_critical_pct": 95.0,
    "memory_warning_pct": 80.0,
    "memory_critical_pct": 95.0,
    "interface_errors_warning": 1.0,
    "interface_errors_critical": 100.0,
    "interface_error_rate_warning_per_sec": 0.1,
    "interface_error_rate_critical_per_sec": 5.0,
    "interface_discards_warning": 1.0,
    "interface_discards_critical": 100.0,
    "interface_discard_rate_warning_per_sec": 0.1,
    "interface_discard_rate_critical_per_sec": 5.0,
    "egress_queue_drops_warning": 1.0,
    "egress_queue_drops_critical": 100.0,
    "egress_queue_drop_rate_warning_per_sec": 0.1,
    "egress_queue_drop_rate_critical_per_sec": 5.0,
}

HEALTHY_DEVICE_STATUSES: frozenset[str] = frozenset({"up", "online", "healthy", "ok", "active", "reachable"})
DEGRADED_DEVICE_STATUSES: frozenset[str] = frozenset({"degraded", "warning", "impaired"})
DOWN_DEVICE_STATUSES: frozenset[str] = frozenset({"down", "unreachable", "offline", "failed", "critical", "dead"})
RECOGNIZED_DEVICE_STATUSES: frozenset[str] = (
    HEALTHY_DEVICE_STATUSES | DEGRADED_DEVICE_STATUSES | DOWN_DEVICE_STATUSES
)

HEALTHY_INTERFACE_STATUSES: frozenset[str] = frozenset({"up", "online", "healthy", "ok", "active", "connected"})
DEGRADED_INTERFACE_STATUSES: frozenset[str] = frozenset({"degraded", "warning", "err_disabled", "err-disabled", "flapping"})
DOWN_INTERFACE_STATUSES: frozenset[str] = frozenset({"down", "offline", "failed", "disconnected", "notconnect"})
ADMIN_DOWN_INTERFACE_STATUSES: frozenset[str] = frozenset({"admin_down", "admin-down", "administratively_down", "shutdown", "disabled"})
RECOGNIZED_INTERFACE_STATUSES: frozenset[str] = (
    HEALTHY_INTERFACE_STATUSES
    | DEGRADED_INTERFACE_STATUSES
    | DOWN_INTERFACE_STATUSES
    | ADMIN_DOWN_INTERFACE_STATUSES
)


def _validate_strict_float(value: Any, field_name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"'{field_name}' must be a numeric value (int or float), not {type(value).__name__}.")
    return float(value)


def _validate_non_negative_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"'{field_name}' must be a non-negative integer, not bool.")
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"'{field_name}' counter must be an integer value, got float {value}.")
        value = int(value)
    if not isinstance(value, int):
        raise ValueError(f"'{field_name}' must be an integer, not {type(value).__name__}.")
    if value < 0:
        raise ValueError(f"'{field_name}' counter cannot be negative (got {value}).")
    return value


# =====================================================================
# 2. INFRASTRUCTURE TELEMETRY INPUT MODELS
# =====================================================================


class InterfaceTelemetry(ProtocolBaseModel):
    """
    Telemetry record for a single network interface on a device.
    Supports cumulative counters, pre-calculated counter deltas, or previous counter
    baselines (with elapsed_seconds or previous_timestamp) for reliable rate calculation.
    """

    interface_id: str = Field(..., min_length=1, max_length=128, description="Unique interface name or identifier (e.g., 'Gi0/1', 'eth0').")
    status: Optional[str] = Field(default=None, min_length=1, max_length=64, description="Operational interface status (e.g., 'up', 'down').")
    segment_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Associated VLAN or network segment ID.")

    # Cumulative error counters
    in_errors: Optional[int] = Field(default=None, description="Cumulative inbound interface error counter.")
    out_errors: Optional[int] = Field(default=None, description="Cumulative outbound interface error counter.")
    interface_errors: Optional[int] = Field(default=None, description="Cumulative total interface error counter.")

    # Previous error counters (for delta/rate calculation)
    prev_in_errors: Optional[int] = Field(default=None, description="Previous cumulative inbound error counter.")
    prev_out_errors: Optional[int] = Field(default=None, description="Previous cumulative outbound error counter.")
    prev_interface_errors: Optional[int] = Field(default=None, description="Previous cumulative total interface error counter.")

    # Explicit window error deltas
    in_errors_delta: Optional[int] = Field(default=None, description="Inbound interface errors accumulated during the sample window.")
    out_errors_delta: Optional[int] = Field(default=None, description="Outbound interface errors accumulated during the sample window.")
    interface_errors_delta: Optional[int] = Field(default=None, description="Total interface errors accumulated during the sample window.")

    # Cumulative discard counters
    in_discards: Optional[int] = Field(default=None, description="Cumulative inbound packet discard counter.")
    out_discards: Optional[int] = Field(default=None, description="Cumulative outbound packet discard counter.")
    discards: Optional[int] = Field(default=None, description="Cumulative total interface discard counter.")

    # Previous discard counters
    prev_in_discards: Optional[int] = Field(default=None, description="Previous cumulative inbound discard counter.")
    prev_out_discards: Optional[int] = Field(default=None, description="Previous cumulative outbound discard counter.")
    prev_discards: Optional[int] = Field(default=None, description="Previous cumulative total interface discard counter.")

    # Explicit window discard deltas
    in_discards_delta: Optional[int] = Field(default=None, description="Inbound discards accumulated during the sample window.")
    out_discards_delta: Optional[int] = Field(default=None, description="Outbound discards accumulated during the sample window.")
    discards_delta: Optional[int] = Field(default=None, description="Total interface discards accumulated during the sample window.")

    # Egress queue drop counters & deltas
    egress_queue_drops: Optional[int] = Field(default=None, description="Cumulative egress/outbound queue drop counter.")
    out_queue_drops: Optional[int] = Field(default=None, description="Alias for cumulative outbound queue drop counter.")
    prev_egress_queue_drops: Optional[int] = Field(default=None, description="Previous cumulative egress queue drop counter.")
    prev_out_queue_drops: Optional[int] = Field(default=None, description="Previous cumulative outbound queue drop counter.")
    egress_queue_drops_delta: Optional[int] = Field(default=None, description="Egress queue drops accumulated during the sample window.")
    out_queue_drops_delta: Optional[int] = Field(default=None, description="Alias for outbound queue drops accumulated during the sample window.")

    # Optional timing context for rate calculations
    elapsed_seconds: Optional[float] = Field(default=None, description="Sample window duration in seconds (> 0) when calculating rates.")
    previous_timestamp: Optional[datetime] = Field(default=None, description="UTC timestamp of previous counter sample.")
    record_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Traceable telemetry record identifier.")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC timestamp of the observation.")

    @field_validator(
        "in_errors", "out_errors", "interface_errors",
        "prev_in_errors", "prev_out_errors", "prev_interface_errors",
        "in_errors_delta", "out_errors_delta", "interface_errors_delta",
        "in_discards", "out_discards", "discards",
        "prev_in_discards", "prev_out_discards", "prev_discards",
        "in_discards_delta", "out_discards_delta", "discards_delta",
        "egress_queue_drops", "out_queue_drops",
        "prev_egress_queue_drops", "prev_out_queue_drops",
        "egress_queue_drops_delta", "out_queue_drops_delta",
        mode="before",
    )
    @classmethod
    def validate_counters(cls, value: Any, info: Any) -> Optional[int]:
        return _validate_non_negative_int(value, info.field_name)

    @field_validator("elapsed_seconds", mode="before")
    @classmethod
    def validate_elapsed(cls, value: Any) -> Optional[float]:
        val = _validate_strict_float(value, "elapsed_seconds")
        if val is not None and val <= 0:
            raise ValueError("'elapsed_seconds' must be strictly positive (> 0).")
        return val

    @field_validator("status")
    @classmethod
    def validate_interface_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in RECOGNIZED_INTERFACE_STATUSES:
            allowed = ", ".join(sorted(RECOGNIZED_INTERFACE_STATUSES))
            raise ValueError(f"Unrecognized interface status '{value}'. Allowed values: [{allowed}].")
        return normalized

    @field_validator("timestamp")
    @classmethod
    def validate_ts(cls, value: datetime) -> datetime:
        return ensure_utc_timestamp(value)

    @field_validator("previous_timestamp")
    @classmethod
    def validate_prev_ts(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        return ensure_utc_timestamp(value)


class DeviceInfrastructureTelemetry(ProtocolBaseModel):
    """
    Infrastructure health telemetry for a single network device and its interfaces.
    """

    device_id: str = Field(..., min_length=1, max_length=128, description="Unique network device identifier (e.g., 'rtr-core-01', 'sw-agg-01').")
    status: Optional[Union[str, bool]] = Field(default=None, description="Operational device status (e.g., 'up', 'down', 'unreachable', 'degraded', or bool).")
    operational_status: Optional[Union[str, bool]] = Field(default=None, description="Alias for operational device status.")
    cpu_utilization: Optional[float] = Field(default=None, description="CPU utilization percentage in [0.0, 100.0].")
    cpu_utilization_pct: Optional[float] = Field(default=None, description="Alias for CPU utilization percentage in [0.0, 100.0].")
    memory_utilization: Optional[float] = Field(default=None, description="Memory utilization percentage in [0.0, 100.0].")
    memory_utilization_pct: Optional[float] = Field(default=None, description="Alias for memory utilization percentage in [0.0, 100.0].")
    segment_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Optional primary network segment or VLAN ID.")
    interfaces: list[Any] = Field(default_factory=list, description="List of per-interface telemetry records.")
    record_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Traceable telemetry record identifier.")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC timestamp of the observation.")

    # Optional flat interface fields when a record represents a single device+interface row
    interface_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    in_errors: Optional[int] = Field(default=None)
    out_errors: Optional[int] = Field(default=None)
    interface_errors: Optional[int] = Field(default=None)
    prev_in_errors: Optional[int] = Field(default=None)
    prev_out_errors: Optional[int] = Field(default=None)
    prev_interface_errors: Optional[int] = Field(default=None)
    in_errors_delta: Optional[int] = Field(default=None)
    out_errors_delta: Optional[int] = Field(default=None)
    interface_errors_delta: Optional[int] = Field(default=None)
    in_discards: Optional[int] = Field(default=None)
    out_discards: Optional[int] = Field(default=None)
    discards: Optional[int] = Field(default=None)
    prev_in_discards: Optional[int] = Field(default=None)
    prev_out_discards: Optional[int] = Field(default=None)
    prev_discards: Optional[int] = Field(default=None)
    in_discards_delta: Optional[int] = Field(default=None)
    out_discards_delta: Optional[int] = Field(default=None)
    discards_delta: Optional[int] = Field(default=None)
    egress_queue_drops: Optional[int] = Field(default=None)
    out_queue_drops: Optional[int] = Field(default=None)
    prev_egress_queue_drops: Optional[int] = Field(default=None)
    prev_out_queue_drops: Optional[int] = Field(default=None)
    egress_queue_drops_delta: Optional[int] = Field(default=None)
    out_queue_drops_delta: Optional[int] = Field(default=None)
    elapsed_seconds: Optional[float] = Field(default=None)
    previous_timestamp: Optional[datetime] = Field(default=None)

    @field_validator("cpu_utilization", "cpu_utilization_pct", "memory_utilization", "memory_utilization_pct", mode="before")
    @classmethod
    def validate_percentage(cls, value: Any, info: Any) -> Optional[float]:
        val = _validate_strict_float(value, info.field_name)
        if val is not None and not (0.0 <= val <= 100.0):
            raise ValueError(f"'{info.field_name}' must be between 0.0 and 100.0% (got {val}).")
        return val

    @field_validator("status", "operational_status", mode="before")
    @classmethod
    def validate_device_status(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bool):
            return "up" if value else "down"
        if not isinstance(value, str):
            raise ValueError(f"Device status must be a string or boolean, got {type(value).__name__}.")
        normalized = value.strip().lower()
        if normalized not in RECOGNIZED_DEVICE_STATUSES:
            allowed = ", ".join(sorted(RECOGNIZED_DEVICE_STATUSES))
            raise ValueError(f"Unrecognized device operational status '{value}'. Allowed values: [{allowed}].")
        return normalized

    @field_validator("interfaces", mode="before")
    @classmethod
    def validate_interfaces_list(cls, value: Any) -> list[Any]:
        if value is None:
            raise ValueError("'interfaces' must be a list when provided, not None.")
        if not isinstance(value, list):
            raise ValueError(f"'interfaces' must be a list of interface telemetry objects, got {type(value).__name__}.")
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_ts(cls, value: datetime) -> datetime:
        return ensure_utc_timestamp(value)

    @field_validator("previous_timestamp")
    @classmethod
    def validate_prev_ts(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        return ensure_utc_timestamp(value)

    @model_validator(mode="after")
    def consolidate_aliases(self) -> DeviceInfrastructureTelemetry:
        if self.cpu_utilization is None and self.cpu_utilization_pct is not None:
            self.cpu_utilization = self.cpu_utilization_pct
        if self.memory_utilization is None and self.memory_utilization_pct is not None:
            self.memory_utilization = self.memory_utilization_pct
        if self.status is None and self.operational_status is not None:
            self.status = self.operational_status
        return self


# =====================================================================
# 3. INFRASTRUCTURE HEALTH AGENT
# =====================================================================


class InfrastructureAgent:
    """
    Agent 2: Infrastructure Health Agent.

    Performs deterministic, explainable checks on network-device and interface health:
    - Device operational status (up, degraded, down/unreachable)
    - CPU utilization (%)
    - Memory utilization (%)
    - Interface errors (cumulative counters, window deltas, and rates when timestamps/deltas exist)
    - Interface discards (cumulative counters, window deltas, and rates)
    - Egress queue drops (cumulative counters, window deltas, and rates)

    Does NOT duplicate the Performance Agent's checks for latency, jitter, packet loss,
    throughput, or bandwidth utilization.
    """

    agent_name = AgentName.INFRASTRUCTURE

    def __init__(self, thresholds: Optional[Mapping[str, float]] = None) -> None:
        self.thresholds: dict[str, float] = {**DEFAULT_THRESHOLDS, **(dict(thresholds) if thresholds else {})}
        self._validate_thresholds()

    def _validate_thresholds(self) -> None:
        for name, value in self.thresholds.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"Threshold '{name}' must be a non-negative number, got {value!r}.")

        pairs = [
            ("cpu_warning_pct", "cpu_critical_pct"),
            ("memory_warning_pct", "memory_critical_pct"),
            ("interface_errors_warning", "interface_errors_critical"),
            ("interface_error_rate_warning_per_sec", "interface_error_rate_critical_per_sec"),
            ("interface_discards_warning", "interface_discards_critical"),
            ("interface_discard_rate_warning_per_sec", "interface_discard_rate_critical_per_sec"),
            ("egress_queue_drops_warning", "egress_queue_drops_critical"),
            ("egress_queue_drop_rate_warning_per_sec", "egress_queue_drop_rate_critical_per_sec"),
        ]
        for warn_key, crit_key in pairs:
            if self.thresholds[crit_key] < self.thresholds[warn_key]:
                raise ValueError(f"Critical threshold '{crit_key}' ({self.thresholds[crit_key]}) cannot be less than warning threshold '{warn_key}' ({self.thresholds[warn_key]}).")

    @staticmethod
    def _make_error(code: ErrorCode, message: str, **details: Any) -> AgentError:
        return AgentError(
            error_code=code,
            message=message,
            source_agent=AgentName.INFRASTRUCTURE,
            retryable=False,
            details=details,
        )

    def analyze(
        self,
        telemetry: Union[
            Sequence[Union[Mapping[str, Any], DeviceInfrastructureTelemetry]],
            Mapping[str, Any],
            DeviceInfrastructureTelemetry,
        ],
    ) -> AgentResponse:
        """
        Analyzes infrastructure telemetry across one or more devices and interfaces.
        Preserves valid records when malformed records are encountered (returning PARTIAL),
        and returns FAILED if no valid checks can be completed.
        """
        started = perf_counter()
        findings: list[AgentFinding] = []
        errors: list[AgentError] = []
        warnings: list[str] = []
        completed_checks: list[str] = []
        devices_evaluated: set[str] = set()

        raw_records = self._extract_records_list(telemetry, errors)
        if raw_records is None:
            return AgentResponse(
                agent_name=AgentName.INFRASTRUCTURE,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={"records_received": 0, "valid_checks": 0, "findings_generated": 0},
            )

        if len(raw_records) == 0:
            errors.append(
                self._make_error(
                    ErrorCode.MISSING_INPUT,
                    "No infrastructure telemetry records were supplied.",
                )
            )
            return AgentResponse(
                agent_name=AgentName.INFRASTRUCTURE,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={"records_received": 0, "valid_checks": 0, "findings_generated": 0},
            )

        for index, raw_record in enumerate(raw_records):
            self._process_record(
                index=index,
                raw_record=raw_record,
                findings=findings,
                errors=errors,
                warnings=warnings,
                completed_checks=completed_checks,
                devices_evaluated=devices_evaluated,
            )

        deduped_checks = list(dict.fromkeys(completed_checks))

        if not deduped_checks and not errors:
            errors.append(
                self._make_error(
                    ErrorCode.MISSING_INPUT,
                    "No evaluable infrastructure metrics or status fields were present in the supplied telemetry.",
                )
            )

        if errors and (findings or deduped_checks):
            status = ExecutionStatus.PARTIAL
            warnings.append(
                f"{len(errors)} telemetry record(s) or sub-record(s) failed validation; valid infrastructure checks were retained."
            )
        elif errors:
            status = ExecutionStatus.FAILED
        else:
            status = ExecutionStatus.SUCCESS

        return AgentResponse(
            agent_name=AgentName.INFRASTRUCTURE,
            status=status,
            findings=findings,
            completed_checks=deduped_checks,
            warnings=warnings,
            errors=errors,
            processing_time_ms=(perf_counter() - started) * 1000,
            execution_metadata={
                "records_received": len(raw_records),
                "devices_evaluated": sorted(devices_evaluated),
                "valid_checks": len(deduped_checks),
                "findings_generated": len(findings),
                "thresholds_used": dict(self.thresholds),
            },
        )

    def _extract_records_list(
        self,
        telemetry: Any,
        errors: list[AgentError],
    ) -> Optional[Sequence[Any]]:
        """Extracts a sequence of device/metric records from flexible top-level input formats."""
        if isinstance(telemetry, DeviceInfrastructureTelemetry):
            return [telemetry]
        if isinstance(telemetry, Mapping):
            if "devices" in telemetry:
                devices_val = telemetry["devices"]
                if not isinstance(devices_val, Sequence) or isinstance(devices_val, (str, bytes)):
                    errors.append(
                        self._make_error(
                            ErrorCode.MALFORMED_TELEMETRY,
                            "Top-level 'devices' field must be a sequence of device records.",
                        )
                    )
                    return None
                return devices_val
            if "telemetry" in telemetry:
                tel_val = telemetry["telemetry"]
                if not isinstance(tel_val, Sequence) or isinstance(tel_val, (str, bytes)):
                    errors.append(
                        self._make_error(
                            ErrorCode.MALFORMED_TELEMETRY,
                            "Top-level 'telemetry' field must be a sequence of telemetry records.",
                        )
                    )
                    return None
                return tel_val
            return [telemetry]
        if isinstance(telemetry, Sequence) and not isinstance(telemetry, (str, bytes)):
            return telemetry

        errors.append(
            self._make_error(
                ErrorCode.MALFORMED_TELEMETRY,
                f"Infrastructure telemetry input must be a sequence of records or a mapping, got {type(telemetry).__name__}.",
            )
        )
        return None

    def _process_record(
        self,
        index: int,
        raw_record: Any,
        findings: list[AgentFinding],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
        devices_evaluated: set[str],
    ) -> None:
        if isinstance(raw_record, DeviceInfrastructureTelemetry):
            device_rec = raw_record
            raw_interfaces = list(device_rec.interfaces)
        elif isinstance(raw_record, Mapping):
            if "metric_name" in raw_record and "value" in raw_record:
                self._process_flat_metric_record(
                    index=index,
                    row=raw_record,
                    findings=findings,
                    errors=errors,
                    warnings=warnings,
                    completed_checks=completed_checks,
                    devices_evaluated=devices_evaluated,
                )
                return

            raw_dict = dict(raw_record)
            raw_interfaces = raw_dict.pop("interfaces", [])
            if raw_interfaces is None or not isinstance(raw_interfaces, list):
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        f"Record at index {index} has invalid 'interfaces' container (must be a list).",
                        record_index=index,
                    )
                )
                return

            # If flat interface fields are provided directly on the device record, extract them as an interface entry
            flat_iface_keys = {
                "interface_id", "in_errors", "out_errors", "interface_errors",
                "prev_in_errors", "prev_out_errors", "prev_interface_errors",
                "in_errors_delta", "out_errors_delta", "interface_errors_delta",
                "in_discards", "out_discards", "discards",
                "prev_in_discards", "prev_out_discards", "prev_discards",
                "in_discards_delta", "out_discards_delta", "discards_delta",
                "egress_queue_drops", "out_queue_drops",
                "prev_egress_queue_drops", "prev_out_queue_drops",
                "egress_queue_drops_delta", "out_queue_drops_delta",
                "elapsed_seconds", "previous_timestamp",
            }
            has_flat_iface_metrics = any(
                k in raw_dict and raw_dict[k] is not None
                for k in flat_iface_keys - {"interface_id", "elapsed_seconds", "previous_timestamp"}
            )
            if raw_dict.get("interface_id") is not None or has_flat_iface_metrics:
                flat_iface: dict[str, Any] = {}
                for k in flat_iface_keys:
                    if k in raw_dict and raw_dict[k] is not None:
                        flat_iface[k] = raw_dict.pop(k)
                if "segment_id" in raw_dict and raw_dict["segment_id"] is not None:
                    flat_iface.setdefault("segment_id", raw_dict["segment_id"])
                if "record_id" in raw_dict and raw_dict["record_id"] is not None:
                    flat_iface.setdefault("record_id", raw_dict["record_id"])
                if "timestamp" in raw_dict and raw_dict["timestamp"] is not None:
                    flat_iface.setdefault("timestamp", raw_dict["timestamp"])
                raw_interfaces = [*raw_interfaces, flat_iface]

            try:
                device_rec = DeviceInfrastructureTelemetry.model_validate(raw_dict)
            except (ValidationError, ValueError, TypeError) as exc:
                code = self._classify_validation_error(exc, raw_dict)
                errors.append(
                    self._make_error(
                        code,
                        f"Device telemetry record at index {index} failed validation: {exc}",
                        record_index=index,
                        device_id=raw_dict.get("device_id") if isinstance(raw_dict.get("device_id"), str) else None,
                    )
                )
                return
        else:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"Telemetry record at index {index} must be a mapping or DeviceInfrastructureTelemetry, got {type(raw_record).__name__}.",
                    record_index=index,
                )
            )
            return

        device_checks_before = len(completed_checks)
        device_errors_before = len(errors)

        # Evaluate device-level operational status, CPU, and memory
        self._evaluate_device_status(device_rec, findings, completed_checks)
        self._evaluate_cpu(device_rec, findings, completed_checks)
        self._evaluate_memory(device_rec, findings, completed_checks)

        # Evaluate each interface independently so one malformed interface does not discard healthy device/interface data
        for iface_idx, raw_iface in enumerate(raw_interfaces):
            try:
                iface = (
                    raw_iface
                    if isinstance(raw_iface, InterfaceTelemetry)
                    else InterfaceTelemetry.model_validate(raw_iface)
                )
            except (ValidationError, ValueError, TypeError) as exc:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        f"Interface record at index {iface_idx} on device '{device_rec.device_id}' failed validation: {exc}",
                        record_index=index,
                        interface_index=iface_idx,
                        device_id=device_rec.device_id,
                    )
                )
                continue

            if iface.segment_id is None and device_rec.segment_id is not None:
                iface.segment_id = device_rec.segment_id
            if iface.record_id is None and device_rec.record_id is not None:
                iface.record_id = device_rec.record_id

            self._evaluate_interface(
                device_rec=device_rec,
                iface=iface,
                record_index=index,
                iface_index=iface_idx,
                findings=findings,
                errors=errors,
                warnings=warnings,
                completed_checks=completed_checks,
            )

        if len(completed_checks) > device_checks_before:
            devices_evaluated.add(device_rec.device_id)
        elif len(errors) == device_errors_before:
            # Record had a valid device_id but no metrics or interfaces at all;
            # do not claim the device is faulty, just record a non-fatal warning and no finding.
            warnings.append(
                f"Device '{device_rec.device_id}' (record {index}) contained no evaluable metrics or interface telemetry."
            )

    def _process_flat_metric_record(
        self,
        index: int,
        row: Mapping[str, Any],
        findings: list[AgentFinding],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
        devices_evaluated: set[str],
    ) -> None:
        """
        Supports flat metric records (e.g. {'device_id': 'r1', 'metric_name': 'cpu_utilization', 'value': 92, 'unit': '%'})
        in addition to structured device/interface dictionaries.
        """
        device_id = row.get("device_id")
        if not isinstance(device_id, str) or not device_id.strip():
            errors.append(
                self._make_error(
                    ErrorCode.MISSING_INPUT,
                    f"Flat telemetry record at index {index} is missing required 'device_id'.",
                    record_index=index,
                )
            )
            return

        raw_metric = str(row.get("metric_name", "")).strip().lower().replace("-", "_").replace(" ", "_")
        value = row.get("value")
        unit = str(row.get("unit", "")).strip() if row.get("unit") is not None else None
        interface_id = str(row["interface_id"]).strip() if row.get("interface_id") else None
        segment_id = str(row["segment_id"]).strip() if row.get("segment_id") else None
        record_id = str(row["record_id"]).strip() if row.get("record_id") else None
        ts = row.get("timestamp", utc_now())

        # Reject Performance Agent metrics explicitly
        performance_metrics = {
            "latency", "latency_ms", "rtt", "icmp_rtt", "icmp_rtt_p95",
            "jitter", "jitter_ms", "packet_loss", "packet_loss_rate", "packet_loss_pct",
            "throughput", "throughput_mbps", "bandwidth_utilization", "bandwidth_utilization_pct",
        }
        if raw_metric in performance_metrics:
            errors.append(
                self._make_error(
                    ErrorCode.UNKNOWN_METRIC_OR_UNIT,
                    f"Metric '{raw_metric}' at index {index} belongs to the Performance Agent, not the Infrastructure Agent.",
                    record_index=index,
                    metric_name=raw_metric,
                )
            )
            return

        converted: dict[str, Any] = {"device_id": device_id.strip()}
        if segment_id:
            converted["segment_id"] = segment_id
        if record_id:
            converted["record_id"] = record_id
        if ts is not None:
            converted["timestamp"] = ts

        if raw_metric in ("cpu", "cpu_utilization", "cpu_utilization_pct", "cpu_percent", "cpu_usage"):
            if unit is not None and unit not in ("%", "percent", "pct"):
                errors.append(
                    self._make_error(
                        ErrorCode.UNKNOWN_METRIC_OR_UNIT,
                        f"CPU utilization at index {index} requires '%' unit, got '{unit}'.",
                        record_index=index,
                    )
                )
                return
            converted["cpu_utilization"] = value
        elif raw_metric in ("memory", "memory_utilization", "memory_utilization_pct", "memory_percent", "memory_usage", "mem_utilization"):
            if unit is not None and unit not in ("%", "percent", "pct"):
                errors.append(
                    self._make_error(
                        ErrorCode.UNKNOWN_METRIC_OR_UNIT,
                        f"Memory utilization at index {index} requires '%' unit, got '{unit}'.",
                        record_index=index,
                    )
                )
                return
            converted["memory_utilization"] = value
        elif raw_metric in ("status", "device_status", "operational_status"):
            converted["status"] = value
        elif raw_metric in (
            "in_errors", "out_errors", "interface_errors",
            "in_errors_delta", "out_errors_delta", "interface_errors_delta",
            "in_discards", "out_discards", "discards",
            "in_discards_delta", "out_discards_delta", "discards_delta",
            "egress_queue_drops", "out_queue_drops",
            "egress_queue_drops_delta", "out_queue_drops_delta",
        ):
            iface_dict: dict[str, Any] = {
                "interface_id": interface_id or "unspecified-interface",
                raw_metric: value,
            }
            if row.get("elapsed_seconds") is not None:
                iface_dict["elapsed_seconds"] = row.get("elapsed_seconds")
            if row.get("previous_value") is not None:
                prev_map = {
                    "in_errors": "prev_in_errors",
                    "out_errors": "prev_out_errors",
                    "interface_errors": "prev_interface_errors",
                    "in_discards": "prev_in_discards",
                    "out_discards": "prev_out_discards",
                    "discards": "prev_discards",
                    "egress_queue_drops": "prev_egress_queue_drops",
                    "out_queue_drops": "prev_out_queue_drops",
                }
                if raw_metric in prev_map:
                    iface_dict[prev_map[raw_metric]] = row.get("previous_value")
            converted["interfaces"] = [iface_dict]
        else:
            errors.append(
                self._make_error(
                    ErrorCode.UNKNOWN_METRIC_OR_UNIT,
                    f"Unsupported infrastructure metric '{raw_metric}' at index {index}.",
                    record_index=index,
                    metric_name=raw_metric,
                )
            )
            return

        self._process_record(
            index=index,
            raw_record=converted,
            findings=findings,
            errors=errors,
            warnings=warnings,
            completed_checks=completed_checks,
            devices_evaluated=devices_evaluated,
        )

    @staticmethod
    def _classify_validation_error(exc: Exception, raw_dict: Mapping[str, Any]) -> ErrorCode:
        if not raw_dict.get("device_id"):
            return ErrorCode.MISSING_INPUT
        return ErrorCode.MALFORMED_TELEMETRY

    # -----------------------------------------------------------------
    # DEVICE-LEVEL CHECKS
    # -----------------------------------------------------------------

    def _evaluate_device_status(
        self,
        device: DeviceInfrastructureTelemetry,
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        if device.status is None:
            return

        status_str = str(device.status).lower()
        completed_checks.append(f"device_status:{device.device_id}")

        if status_str in HEALTHY_DEVICE_STATUSES:
            return

        if status_str in DOWN_DEVICE_STATUSES:
            severity = Severity.CRITICAL
            code = "DEVICE_DOWN"
            confidence = 0.98
            summary = f"Device {device.device_id} operational status is {status_str}."
            description = (
                f"Device '{device.device_id}' reported operational status '{status_str}' "
                f"(expected 'up'). The device is currently unreachable or non-operational."
            )
        else:
            severity = Severity.HIGH
            code = "DEVICE_DEGRADED"
            confidence = 0.88
            summary = f"Device {device.device_id} operational status is {status_str}."
            description = (
                f"Device '{device.device_id}' reported degraded operational status '{status_str}' "
                f"(expected 'up')."
            )

        evidence = Evidence(
            evidence_type=EvidenceType.DEVICE_STATUS,
            metric_name="device_operational_status",
            observed_value=status_str,
            expected_value="up",
            device_id=device.device_id,
            segment_id=device.segment_id,
            source_agent=AgentName.INFRASTRUCTURE,
            telemetry_record_id=device.record_id,
            description=f"Device '{device.device_id}' operational status observed as '{status_str}'.",
            timestamp=device.timestamp,
        )
        findings.append(
            AgentFinding(
                agent_source=AgentName.INFRASTRUCTURE,
                finding_code=code,
                finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                severity=severity,
                summary=summary,
                description=description,
                confidence=confidence,
                affected_devices=[device.device_id],
                affected_segments=[device.segment_id] if device.segment_id else [],
                evidence=[evidence],
                limitations=[
                    "Telemetry reflects reported device operational state; physical power or out-of-band management state requires separate verification."
                ],
                timestamp=device.timestamp,
            )
        )

    def _evaluate_cpu(
        self,
        device: DeviceInfrastructureTelemetry,
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        if device.cpu_utilization is None:
            return

        cpu = float(device.cpu_utilization)
        completed_checks.append(f"cpu_utilization:{device.device_id}")

        warn_threshold = self.thresholds["cpu_warning_pct"]
        crit_threshold = self.thresholds["cpu_critical_pct"]
        if cpu < warn_threshold:
            return

        is_critical = cpu >= crit_threshold
        severity = Severity.CRITICAL if is_critical else Severity.HIGH
        threshold_used = crit_threshold if is_critical else warn_threshold
        confidence = 0.92 if is_critical else 0.85

        evidence = Evidence(
            evidence_type=EvidenceType.METRIC,
            metric_name="cpu_utilization",
            observed_value=round(cpu, 4),
            unit="%",
            expected_value=round(warn_threshold, 4),
            device_id=device.device_id,
            segment_id=device.segment_id,
            source_agent=AgentName.INFRASTRUCTURE,
            telemetry_record_id=device.record_id,
            description=(
                f"CPU utilization on '{device.device_id}' measured {cpu:g}%, "
                f"exceeding the {threshold_used:g}% {'critical' if is_critical else 'warning'} threshold."
            ),
            timestamp=device.timestamp,
        )
        findings.append(
            AgentFinding(
                agent_source=AgentName.INFRASTRUCTURE,
                finding_code="HIGH_CPU_UTILIZATION",
                finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                severity=severity,
                summary=f"High CPU utilization ({cpu:g}%) on device {device.device_id}.",
                description=(
                    f"Device '{device.device_id}' reported CPU utilization of {cpu:g}%, "
                    f"which exceeds the configured warning threshold of {warn_threshold:g}% "
                    f"(critical threshold: {crit_threshold:g}%)."
                ),
                confidence=confidence,
                affected_devices=[device.device_id],
                affected_segments=[device.segment_id] if device.segment_id else [],
                evidence=[evidence],
                limitations=[
                    "Aggregate CPU utilization does not identify the specific control-plane process or traffic punt trigger."
                ],
                timestamp=device.timestamp,
            )
        )

    def _evaluate_memory(
        self,
        device: DeviceInfrastructureTelemetry,
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        if device.memory_utilization is None:
            return

        mem = float(device.memory_utilization)
        completed_checks.append(f"memory_utilization:{device.device_id}")

        warn_threshold = self.thresholds["memory_warning_pct"]
        crit_threshold = self.thresholds["memory_critical_pct"]
        if mem < warn_threshold:
            return

        is_critical = mem >= crit_threshold
        severity = Severity.CRITICAL if is_critical else Severity.HIGH
        threshold_used = crit_threshold if is_critical else warn_threshold
        confidence = 0.92 if is_critical else 0.85

        evidence = Evidence(
            evidence_type=EvidenceType.METRIC,
            metric_name="memory_utilization",
            observed_value=round(mem, 4),
            unit="%",
            expected_value=round(warn_threshold, 4),
            device_id=device.device_id,
            segment_id=device.segment_id,
            source_agent=AgentName.INFRASTRUCTURE,
            telemetry_record_id=device.record_id,
            description=(
                f"Memory utilization on '{device.device_id}' measured {mem:g}%, "
                f"exceeding the {threshold_used:g}% {'critical' if is_critical else 'warning'} threshold."
            ),
            timestamp=device.timestamp,
        )
        findings.append(
            AgentFinding(
                agent_source=AgentName.INFRASTRUCTURE,
                finding_code="HIGH_MEMORY_UTILIZATION",
                finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                severity=severity,
                summary=f"High memory utilization ({mem:g}%) on device {device.device_id}.",
                description=(
                    f"Device '{device.device_id}' reported memory utilization of {mem:g}%, "
                    f"which exceeds the configured warning threshold of {warn_threshold:g}% "
                    f"(critical threshold: {crit_threshold:g}%)."
                ),
                confidence=confidence,
                affected_devices=[device.device_id],
                affected_segments=[device.segment_id] if device.segment_id else [],
                evidence=[evidence],
                limitations=[
                    "Memory utilization percentage does not distinguish between control-plane leak and table growth."
                ],
                timestamp=device.timestamp,
            )
        )

    # -----------------------------------------------------------------
    # INTERFACE-LEVEL CHECKS
    # -----------------------------------------------------------------

    def _evaluate_interface(
        self,
        device_rec: DeviceInfrastructureTelemetry,
        iface: InterfaceTelemetry,
        record_index: int,
        iface_index: int,
        findings: list[AgentFinding],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        # 1. Interface operational status
        if iface.status is not None:
            completed_checks.append(f"interface_status:{device_rec.device_id}:{iface.interface_id}")
            if iface.status in DOWN_INTERFACE_STATUSES or iface.status in DEGRADED_INTERFACE_STATUSES:
                is_down = iface.status in DOWN_INTERFACE_STATUSES
                severity = Severity.HIGH if is_down else Severity.MEDIUM
                code = "INTERFACE_DOWN" if is_down else "INTERFACE_DEGRADED"
                evidence = Evidence(
                    evidence_type=EvidenceType.DEVICE_STATUS,
                    metric_name="interface_operational_status",
                    observed_value=iface.status,
                    expected_value="up",
                    device_id=device_rec.device_id,
                    interface_id=iface.interface_id,
                    segment_id=iface.segment_id,
                    source_agent=AgentName.INFRASTRUCTURE,
                    telemetry_record_id=iface.record_id,
                    description=(
                        f"Interface '{iface.interface_id}' on device '{device_rec.device_id}' "
                        f"reported operational status '{iface.status}'."
                    ),
                    timestamp=iface.timestamp,
                )
                findings.append(
                    AgentFinding(
                        agent_source=AgentName.INFRASTRUCTURE,
                        finding_code=code,
                        finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                        severity=severity,
                        summary=f"Interface {iface.interface_id} on {device_rec.device_id} is {iface.status}.",
                        description=(
                            f"Interface '{iface.interface_id}' on device '{device_rec.device_id}' "
                            f"reported operational status '{iface.status}' (expected 'up')."
                        ),
                        confidence=0.92 if is_down else 0.85,
                        affected_devices=[device_rec.device_id],
                        affected_segments=[iface.segment_id] if iface.segment_id else [],
                        evidence=[evidence],
                        timestamp=iface.timestamp,
                    )
                )

        # Compute optional sample window duration in seconds (only when valid timestamps/elapsed_seconds exist)
        window_seconds = self._resolve_window_seconds(iface, warnings, device_rec.device_id)

        # 2. Interface errors check
        self._evaluate_counter_group(
            device_rec=device_rec,
            iface=iface,
            group_name="interface_errors",
            finding_code="HIGH_INTERFACE_ERRORS",
            unit="errors",
            cumulative_values=[
                ("in_errors", iface.in_errors, iface.prev_in_errors),
                ("out_errors", iface.out_errors, iface.prev_out_errors),
                ("interface_errors", iface.interface_errors, iface.prev_interface_errors),
            ],
            explicit_deltas=[
                ("in_errors_delta", iface.in_errors_delta),
                ("out_errors_delta", iface.out_errors_delta),
                ("interface_errors_delta", iface.interface_errors_delta),
            ],
            warn_count_key="interface_errors_warning",
            crit_count_key="interface_errors_critical",
            warn_rate_key="interface_error_rate_warning_per_sec",
            crit_rate_key="interface_error_rate_critical_per_sec",
            window_seconds=window_seconds,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        # 3. Interface discards check
        self._evaluate_counter_group(
            device_rec=device_rec,
            iface=iface,
            group_name="interface_discards",
            finding_code="HIGH_INTERFACE_DISCARDS",
            unit="packets",
            cumulative_values=[
                ("in_discards", iface.in_discards, iface.prev_in_discards),
                ("out_discards", iface.out_discards, iface.prev_out_discards),
                ("discards", iface.discards, iface.prev_discards),
            ],
            explicit_deltas=[
                ("in_discards_delta", iface.in_discards_delta),
                ("out_discards_delta", iface.out_discards_delta),
                ("discards_delta", iface.discards_delta),
            ],
            warn_count_key="interface_discards_warning",
            crit_count_key="interface_discards_critical",
            warn_rate_key="interface_discard_rate_warning_per_sec",
            crit_rate_key="interface_discard_rate_critical_per_sec",
            window_seconds=window_seconds,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        # 4. Egress queue drops check
        self._evaluate_counter_group(
            device_rec=device_rec,
            iface=iface,
            group_name="egress_queue_drops",
            finding_code="HIGH_EGRESS_QUEUE_DROPS",
            unit="packets",
            cumulative_values=[
                ("egress_queue_drops", iface.egress_queue_drops, iface.prev_egress_queue_drops),
                ("out_queue_drops", iface.out_queue_drops, iface.prev_out_queue_drops),
            ],
            explicit_deltas=[
                ("egress_queue_drops_delta", iface.egress_queue_drops_delta),
                ("out_queue_drops_delta", iface.out_queue_drops_delta),
            ],
            warn_count_key="egress_queue_drops_warning",
            crit_count_key="egress_queue_drops_critical",
            warn_rate_key="egress_queue_drop_rate_warning_per_sec",
            crit_rate_key="egress_queue_drop_rate_critical_per_sec",
            window_seconds=window_seconds,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

    @staticmethod
    def _resolve_window_seconds(
        iface: InterfaceTelemetry,
        warnings: list[str],
        device_id: str,
    ) -> Optional[float]:
        if iface.elapsed_seconds is not None:
            return float(iface.elapsed_seconds)
        if iface.previous_timestamp is not None:
            delta_sec = (iface.timestamp - iface.previous_timestamp).total_seconds()
            if delta_sec > 0:
                return delta_sec
            warnings.append(
                f"Interface '{iface.interface_id}' on '{device_id}' has previous_timestamp >= timestamp; rate calculation skipped."
            )
        return None

    def _evaluate_counter_group(
        self,
        device_rec: DeviceInfrastructureTelemetry,
        iface: InterfaceTelemetry,
        group_name: str,
        finding_code: str,
        unit: str,
        cumulative_values: list[tuple[str, Optional[int], Optional[int]]],
        explicit_deltas: list[tuple[str, Optional[int]]],
        warn_count_key: str,
        crit_count_key: str,
        warn_rate_key: str,
        crit_rate_key: str,
        window_seconds: Optional[float],
        findings: list[AgentFinding],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        has_any_metric = any(curr is not None for _, curr, _ in cumulative_values) or any(
            d is not None for _, d in explicit_deltas
        )
        if not has_any_metric:
            return

        completed_checks.append(f"{group_name}:{device_rec.device_id}:{iface.interface_id}")

        # Determine if deltas can be computed from (current - previous) or explicit delta fields
        computed_deltas: list[tuple[str, int]] = []
        for name, d_val in explicit_deltas:
            if d_val is not None:
                computed_deltas.append((name, d_val))

        if not computed_deltas:
            for name, curr, prev in cumulative_values:
                if curr is not None and prev is not None:
                    if curr < prev:
                        warnings.append(
                            f"Counter reset/wrap detected for '{name}' on {device_rec.device_id}:{iface.interface_id} "
                            f"(current={curr} < previous={prev}); delta calculation skipped."
                        )
                    else:
                        computed_deltas.append((f"{name}_delta", curr - prev))

        warn_count = self.thresholds[warn_count_key]
        crit_count = self.thresholds[crit_count_key]
        warn_rate = self.thresholds[warn_rate_key]
        crit_rate = self.thresholds[crit_rate_key]
        human_label = group_name.replace("_", " ")

        # Case A: We have a valid counter delta over a sample window
        if computed_deltas:
            total_delta = sum(val for _, val in computed_deltas)
            primary_metric_name = computed_deltas[0][0] if len(computed_deltas) == 1 else f"{group_name}_delta"

            # If window_seconds is available, we can also compute an exact rate
            rate_per_sec: Optional[float] = (
                total_delta / window_seconds if window_seconds is not None and window_seconds > 0 else None
            )

            is_abnormal_delta = total_delta >= warn_count
            is_abnormal_rate = rate_per_sec is not None and rate_per_sec >= warn_rate
            if not is_abnormal_delta and not is_abnormal_rate:
                return

            is_critical = total_delta >= crit_count or (
                rate_per_sec is not None and rate_per_sec >= crit_rate
            )
            severity = Severity.CRITICAL if is_critical else Severity.HIGH
            confidence = 0.94 if rate_per_sec is not None else 0.90

            evidence_items: list[Evidence] = [
                Evidence(
                    evidence_type=EvidenceType.INTERFACE_COUNTER,
                    metric_name=primary_metric_name,
                    observed_value=int(total_delta),
                    unit=unit,
                    expected_value=int(warn_count),
                    device_id=device_rec.device_id,
                    interface_id=iface.interface_id,
                    segment_id=iface.segment_id,
                    source_agent=AgentName.INFRASTRUCTURE,
                    telemetry_record_id=iface.record_id,
                    description=(
                        f"Interface '{iface.interface_id}' on '{device_rec.device_id}' accumulated "
                        f"a counter delta of {total_delta} {unit} during the observation window."
                    ),
                    timestamp=iface.timestamp,
                )
            ]

            if rate_per_sec is not None:
                evidence_items.append(
                    Evidence(
                        evidence_type=EvidenceType.METRIC,
                        metric_name=f"{group_name}_rate_per_sec",
                        observed_value=round(rate_per_sec, 4),
                        unit=f"{unit}/s",
                        expected_value=round(warn_rate, 4),
                        device_id=device_rec.device_id,
                        interface_id=iface.interface_id,
                        segment_id=iface.segment_id,
                        source_agent=AgentName.INFRASTRUCTURE,
                        telemetry_record_id=iface.record_id,
                        description=(
                            f"Calculated {human_label} rate of {rate_per_sec:.4g} {unit}/s "
                            f"over {window_seconds:g}s window on '{device_rec.device_id}:{iface.interface_id}'."
                        ),
                        timestamp=iface.timestamp,
                    )
                )
                summary = (
                    f"Increasing {human_label} ({total_delta} {unit}, {rate_per_sec:.4g} {unit}/s) "
                    f"on {device_rec.device_id} interface {iface.interface_id}."
                )
                description = (
                    f"Interface '{iface.interface_id}' on device '{device_rec.device_id}' accumulated "
                    f"{total_delta} {unit} over {window_seconds:g}s (rate: {rate_per_sec:.4g} {unit}/s), "
                    f"exceeding the threshold ({warn_count:g} {unit} or {warn_rate:g} {unit}/s)."
                )
                limitations: list[str] = []
            else:
                summary = (
                    f"Increasing {human_label} (delta: {total_delta} {unit}) "
                    f"on {device_rec.device_id} interface {iface.interface_id}."
                )
                description = (
                    f"Interface '{iface.interface_id}' on device '{device_rec.device_id}' accumulated "
                    f"a counter delta of {total_delta} {unit}, exceeding the warning threshold of {warn_count:g} {unit}. "
                    f"No sample interval duration was provided, so per-second rate was not calculated."
                )
                limitations = [
                    "Counter delta verified across samples, but elapsed window duration was not supplied to compute an exact per-second rate."
                ]

            findings.append(
                AgentFinding(
                    agent_source=AgentName.INFRASTRUCTURE,
                    finding_code=finding_code,
                    finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                    severity=severity,
                    summary=summary,
                    description=description,
                    confidence=confidence,
                    affected_devices=[device_rec.device_id],
                    affected_segments=[iface.segment_id] if iface.segment_id else [],
                    evidence=evidence_items,
                    limitations=limitations,
                    timestamp=iface.timestamp,
                )
            )
            return

        # Case B: Only single-point cumulative counters are available (no previous counter or delta).
        # Never claim a cumulative counter is a rate!
        present_cumulatives = [(name, val) for name, val, _ in cumulative_values if val is not None]
        # Prefer specific directional counters (in_*, out_*) if present, otherwise aggregate counter
        directional = [(n, v) for n, v in present_cumulatives if n.startswith(("in_", "out_", "egress_"))]
        selected = directional if directional else present_cumulatives
        total_cumulative = sum(val for _, val in selected)

        if total_cumulative < warn_count:
            return

        is_critical = total_cumulative >= crit_count
        # Cumulative counters without baseline have slightly lower confidence and Medium/High severity
        severity = Severity.HIGH if is_critical else Severity.MEDIUM
        confidence = 0.78 if is_critical else 0.72
        primary_metric_name = selected[0][0] if len(selected) == 1 else group_name

        evidence = Evidence(
            evidence_type=EvidenceType.INTERFACE_COUNTER,
            metric_name=primary_metric_name,
            observed_value=int(total_cumulative),
            unit=unit,
            expected_value=int(warn_count),
            device_id=device_rec.device_id,
            interface_id=iface.interface_id,
            segment_id=iface.segment_id,
            source_agent=AgentName.INFRASTRUCTURE,
            telemetry_record_id=iface.record_id,
            description=(
                f"Cumulative counter '{primary_metric_name}' on '{device_rec.device_id}:{iface.interface_id}' "
                f"is {total_cumulative} {unit} (cumulative total since last counter reset, not a rate)."
            ),
            timestamp=iface.timestamp,
        )

        findings.append(
            AgentFinding(
                agent_source=AgentName.INFRASTRUCTURE,
                finding_code=finding_code,
                finding_type=FindingType.INFRASTRUCTURE_HEALTH,
                severity=severity,
                summary=(
                    f"Non-zero cumulative {human_label} ({total_cumulative} {unit}) "
                    f"on {device_rec.device_id} interface {iface.interface_id}."
                ),
                description=(
                    f"Interface '{iface.interface_id}' on device '{device_rec.device_id}' reports a "
                    f"cumulative {human_label} counter of {total_cumulative} {unit} (warning threshold: {warn_count:g} {unit}). "
                    f"Because only a single cumulative counter snapshot was provided without previous counter values or timestamps, "
                    f"this value represents a cumulative count and not a current rate."
                ),
                confidence=confidence,
                affected_devices=[device_rec.device_id],
                affected_segments=[iface.segment_id] if iface.segment_id else [],
                evidence=[evidence],
                limitations=[
                    "Observation is a single cumulative counter snapshot without a prior baseline or time delta; cannot confirm whether counts are actively increasing."
                ],
                timestamp=iface.timestamp,
            )
        )


def analyze_infrastructure(
    telemetry: Union[
        Sequence[Union[Mapping[str, Any], DeviceInfrastructureTelemetry]],
        Mapping[str, Any],
        DeviceInfrastructureTelemetry,
    ],
    thresholds: Optional[Mapping[str, float]] = None,
) -> AgentResponse:
    """Convenience entry point for orchestrator and tests to run the Infrastructure Health Agent."""
    return InfrastructureAgent(thresholds=thresholds).analyze(telemetry)


run_infrastructure_analysis = analyze_infrastructure
