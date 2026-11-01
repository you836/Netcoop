"""
backend/app/agents/common.py

Shared communication protocol, Pydantic v2 data models, and validation helpers
for the NetCoop AI Multi-Agent Network Fault Diagnosis system.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

# =====================================================================
# 1. PROTOCOL CONSTANTS & ENUMERATIONS
# =====================================================================

CURRENT_SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0"})

UPPER_SNAKE_CASE_REGEX = re.compile(r"^[A-Z][A-Z0-9_]*$")

PrimitiveValue = Union[float, int, str, bool]


class AgentName(str, Enum):
    """Identifiers for the five specialized agents and the central orchestrator."""

    ORCHESTRATOR = "orchestrator"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    CONNECTIVITY = "connectivity"
    CORRELATION = "correlation"
    REPORTING = "reporting"


class MessageType(str, Enum):
    """
    Defines the envelope type persisted by the orchestrator.
    Task requests and broadcasts are omitted because the orchestrator invokes
    Python agent methods directly in our modular monolith.
    """

    AGENT_RESPONSE = "agent_response"
    ERROR_REPORT = "error_report"


class ExecutionStatus(str, Enum):
    """
    Operational execution status of an agent run:
-     SUCCESS: Valid execution with no blocking errors (errors list must be empty).
-     PARTIAL: Usable output (findings or report) exists, but some checks were incomplete.
-     FAILED: No usable output was produced due to one or more operational errors.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class DiagnosisStatus(str, Enum):
    """
    Indicates whether the final DiagnosticReport reached a conclusive diagnosis:
-     IDENTIFIED: Clear root cause(s) supported by correlated evidence.
-     PARTIAL_HYPOTHESIS: Plausible root cause(s) identified, but key evidence is incomplete.
-     INCONCLUSIVE: Insufficient or contradictory evidence; root_causes and recommendations may be empty.
    """

    IDENTIFIED = "identified"
    PARTIAL_HYPOTHESIS = "partial_hypothesis"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    """Diagnostic severity level for findings, recommendations, and reports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    """Categorizes findings by the specialized diagnostic domain."""

    PERFORMANCE_DEGRADATION = "performance_degradation"
    INFRASTRUCTURE_HEALTH = "infrastructure_health"
    CONNECTIVITY_SCOPE = "connectivity_scope"
    ROOT_CAUSE_HYPOTHESIS = "root_cause_hypothesis"


class EvidenceType(str, Enum):
    """Distinguishes the structure and validation rules of an Evidence item."""

    METRIC = "metric"
    DEVICE_STATUS = "device_status"
    INTERFACE_COUNTER = "interface_counter"
    TOPOLOGY_LINK = "topology_link"


class ErrorCode(str, Enum):
    """Standardized operational error codes for agent and protocol failures."""

    MISSING_INPUT = "missing_input"
    MALFORMED_TELEMETRY = "malformed_telemetry"
    INVALID_MESSAGE = "invalid_message"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    UNKNOWN_METRIC_OR_UNIT = "unknown_metric_or_unit"
    LLM_API_FAILURE = "llm_api_failure"
    LLM_VALIDATION_FAILURE = "llm_validation_failure"
    MISSING_TOPOLOGY = "missing_topology"
    EXECUTION_TIMEOUT = "execution_timeout"
    INTERNAL_AGENT_ERROR = "internal_agent_error"


# =====================================================================
# 2. SHARED BASE MODEL & TIMESTAMP HELPERS
# =====================================================================


def utc_now() -> datetime:
    """Returns the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def ensure_utc_timestamp(value: datetime) -> datetime:
    """
    Requires timezone-aware datetime objects and normalizes them to UTC.
    Rejects naive datetimes to prevent cross-agent timezone ambiguity.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            "Timestamp must be timezone-aware (e.g., ISO-8601 with 'Z' or UTC offset)."
        )
    return value.astimezone(timezone.utc)


class ProtocolBaseModel(BaseModel):
    """
    Base model for all NetCoop AI protocol objects.
-     extra='forbid': Rejects unknown or hallucinated fields immediately.
-     str_strip_whitespace=True: Strips accidental leading/trailing whitespace.
-     validate_assignment=True: Re-runs validators when attributes are modified.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
    )


# =====================================================================
# 3. CORE DIAGNOSTIC MODELS
# =====================================================================


class Evidence(ProtocolBaseModel):
    """
    Represents a single verifiable piece of diagnostic evidence traceable to a
    telemetry record, topology snapshot, or service check.
    Scope fields (device_id, interface_id, segment_id, service_id) are optional
     overall so service-level or synthetic probe observations do not require fake IDs,
    while type-specific rules enforce appropriate structure per EvidenceType.
    """

    evidence_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this evidence item.",
    )
    evidence_type: EvidenceType = Field(
        ...,
        description="Category of evidence: metric, device_status, interface_counter, or topology_link.",
    )
    metric_name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Name of the metric, counter, device state, or topology relationship.",
    )
    observed_value: PrimitiveValue = Field(
        ...,
        description="Observed value: float/int for METRIC, int >= 0 for INTERFACE_COUNTER, str/bool for DEVICE_STATUS, str for TOPOLOGY_LINK.",
    )
    unit: Optional[str] = Field(
        default=None,
        max_length=32,
        description="Measurement unit (e.g., 'ms', '%', 'Mbps', 'packets'). Required for METRIC and INTERFACE_COUNTER.",
    )
    expected_value: Optional[PrimitiveValue] = Field(
        default=None,
        description="Expected threshold, SLA baseline, or normal state when available.",
    )
    device_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Network device ID, when applicable.",
    )
    interface_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Network interface ID, when applicable.",
    )
    segment_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Network segment, subnet, or VLAN ID, when applicable.",
    )
    service_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Application or synthetic service identifier for service-level observations.",
    )
    source_agent: AgentName = Field(
        ...,
        description="Agent that extracted or verified this evidence.",
    )
    telemetry_record_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional ID referencing the raw telemetry row or topology snapshot.",
    )
    description: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Human-readable explanation of what this evidence demonstrates.",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the evidence was observed.",
    )

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @model_validator(mode="after")
    def validate_evidence_semantics(self) -> Evidence:
        """
        Validates observed_value types, units, and required context for each EvidenceType:
1.         METRIC: numeric (int or float, not bool) observed_value and non-empty unit.
        2. INTERFACE_COUNTER: non-negative integer (int >= 0, not bool) observed_value,
           non-empty unit, and at least interface_id or device_id.
        3. DEVICE_STATUS: str or bool observed_value, and device_id must be present.
        4. TOPOLOGY_LINK: non-empty str observed_value, and at least one topological
           anchor (device_id, interface_id, or segment_id).
        """
        is_bool = isinstance(self.observed_value, bool)

        if self.evidence_type == EvidenceType.METRIC:
            if is_bool or not isinstance(self.observed_value, (int, float)):
                raise ValueError(
                    "METRIC evidence requires a numeric (int or float) observed_value."
                )
            if not self.unit:
                raise ValueError("METRIC evidence requires a non-empty 'unit'.")

        elif self.evidence_type == EvidenceType.INTERFACE_COUNTER:
            if (
                is_bool
                or not isinstance(self.observed_value, int)
                or self.observed_value < 0
            ):
                raise ValueError(
                    "INTERFACE_COUNTER evidence requires a non-negative integer observed_value."
                )
            if not self.unit:
                raise ValueError(
                    "INTERFACE_COUNTER evidence requires a non-empty 'unit' (e.g., 'packets', 'errors')."
                )
            if not self.interface_id and not self.device_id:
                raise ValueError(
                    "INTERFACE_COUNTER evidence requires 'interface_id' or 'device_id'."
                )

        elif self.evidence_type == EvidenceType.DEVICE_STATUS:
            if not isinstance(self.observed_value, (str, bool)) or (
                isinstance(self.observed_value, str) and not self.observed_value
            ):
                raise ValueError(
                    "DEVICE_STATUS evidence requires a non-empty string or boolean observed_value."
                )
            if not self.device_id:
                raise ValueError("DEVICE_STATUS evidence requires 'device_id'.")

        elif self.evidence_type == EvidenceType.TOPOLOGY_LINK:
            if not isinstance(self.observed_value, str) or not self.observed_value:
                raise ValueError(
                    "TOPOLOGY_LINK evidence requires a non-empty string observed_value describing the link or node relationship."
                )
            if not any([self.device_id, self.interface_id, self.segment_id]):
                raise ValueError(
                    "TOPOLOGY_LINK evidence requires at least one of 'device_id', 'interface_id', or 'segment_id'."
                )

        return self


class AgentFinding(ProtocolBaseModel):
    """
    Standardized diagnostic conclusion generated by an agent, backed by at least
    one verifiable Evidence record.
    """

    finding_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this finding.",
    )
    agent_source: AgentName = Field(
        ...,
        description="Specialized agent that produced this finding.",
    )
    finding_code: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Machine-readable code in UPPER_SNAKE_CASE (e.g., 'HIGH_LATENCY').",
    )
    finding_type: FindingType = Field(
        ...,
        description="Domain classification of the finding.",
    )
    severity: Severity = Field(
        ...,
        description="Diagnostic severity of the detected issue.",
    )
    summary: str = Field(
        ...,
        min_length=5,
        max_length=240,
        description="Concise one-line summary of the finding.",
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Detailed technical explanation of the finding and its context.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Heuristic diagnostic confidence in [0.0, 1.0], not a calibrated probability.",
    )
    affected_devices: list[str] = Field(
        default_factory=list,
        description="List of affected network device IDs, if known.",
    )
    affected_segments: list[str] = Field(
        default_factory=list,
        description="List of affected network segment or VLAN IDs, if known.",
    )
    evidence: list[Evidence] = Field(
        ...,
        min_length=1,
        description="Non-empty list of Evidence objects supporting this finding.",
    )
    supporting_finding_ids: list[UUID] = Field(
        default_factory=list,
        description="IDs of upstream AgentFindings that support this finding (used by Correlation Agent).",
    )
    contradicting_finding_ids: list[UUID] = Field(
        default_factory=list,
        description="IDs of upstream AgentFindings that contradict or weaken this hypothesis.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Known data gaps, missing metrics, or caveats affecting this finding.",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the finding was generated.",
    )

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @field_validator("finding_code")
    @classmethod
    def validate_finding_code_format(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not UPPER_SNAKE_CASE_REGEX.match(normalized):
            raise ValueError(
                f"finding_code must be UPPER_SNAKE_CASE (letters, digits, underscores), got '{value}'."
            )
        return normalized

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, value: float) -> float:
        return round(float(value), 4)


class Recommendation(ProtocolBaseModel):
    """
    Evidence-backed remediation or investigation step produced by the Reporting Agent.
    To prevent unsafe, unverified production changes from being presented as guaranteed
    fixes, every recommendation must link to specific findings and evidence IDs and
    provide concrete operator verification steps.
    """

    recommendation_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this recommendation.",
    )
    priority: Severity = Field(
        ...,
        description="Urgency level of the recommended step.",
    )
    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Short title of the recommended investigation or mitigation step.",
    )
    action: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Recommended operator action or mitigation procedure.",
    )
    target_devices: list[str] = Field(
        default_factory=list,
        description="Target network devices for inspection or mitigation.",
    )
    related_finding_ids: list[UUID] = Field(
        ...,
        min_length=1,
        description="IDs of the AgentFindings this recommendation addresses.",
    )
    supporting_evidence_ids: list[UUID] = Field(
        ...,
        min_length=1,
        description="IDs of specific Evidence records justifying this recommendation.",
    )
    requires_verification: bool = Field(
        default=True,
        description="Indicates that human/operator verification is required before applying changes in production.",
    )
    verification_steps: list[str] = Field(
        ...,
        min_length=1,
        description="Pre-check and post-check steps to verify the hypothesis before/after acting.",
    )
    rationale: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Explanation of how the cited evidence supports this action and what risks/uncertainties remain.",
    )


class DiagnosticReport(ProtocolBaseModel):
    """Final report with status and in-report reference validation."""

    report_id: UUID = Field(default_factory=uuid4, description="Unique report identifier.")
    incident_id: UUID = Field(..., description="Incident ID this report belongs to.")
    run_id: UUID = Field(..., description="Orchestrator diagnostic run ID.")
    diagnosis_status: DiagnosisStatus = Field(..., description="Conclusive, partial, or inconclusive diagnosis.")
    overall_severity: Severity = Field(..., description="Consolidated severity across findings.")
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Heuristic confidence, not a calibrated probability.")
    executive_summary: str = Field(..., min_length=10, max_length=3000)
    root_causes: list[AgentFinding] = Field(default_factory=list, description="Correlated root-cause findings; empty when inconclusive.")
    supporting_findings: list[AgentFinding] = Field(default_factory=list, description="Upstream findings retained for traceability.")
    recommendations: list[Recommendation] = Field(default_factory=list, description="Evidence-based recommendations; may be empty when inconclusive.")
    limitations_and_uncertainties: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)

    _validate_ts = field_validator("generated_at")(ensure_utc_timestamp)

    @field_validator("overall_confidence")
    @classmethod
    def round_overall_confidence(cls, value: float) -> float:
        return round(float(value), 4)

    @model_validator(mode="after")
    def validate_diagnosis_and_cross_references(self) -> DiagnosticReport:
        if self.diagnosis_status in (DiagnosisStatus.IDENTIFIED, DiagnosisStatus.PARTIAL_HYPOTHESIS) and not self.root_causes:
            raise ValueError(
                f"DiagnosticReport with diagnosis_status='{self.diagnosis_status.value}' "
                "must contain at least one root cause in 'root_causes'."
            )
        if self.diagnosis_status in (DiagnosisStatus.PARTIAL_HYPOTHESIS, DiagnosisStatus.INCONCLUSIVE) and not self.limitations_and_uncertainties:
            raise ValueError(
                f"DiagnosticReport with diagnosis_status='{self.diagnosis_status.value}' "
                "must specify at least one entry in 'limitations_and_uncertainties'."
            )

        all_findings = [*self.root_causes, *self.supporting_findings]
        available_finding_ids = {finding.finding_id for finding in all_findings}
        available_evidence_ids = {
            evidence.evidence_id for finding in all_findings for evidence in finding.evidence
        }

        for finding in all_findings:
            missing_supporting = [str(fid) for fid in finding.supporting_finding_ids if fid not in available_finding_ids]
            if missing_supporting:
                raise ValueError(
                    f"Finding '{finding.summary}' references unknown supporting_finding_ids: {missing_supporting}."
                )
            missing_contradicting = [str(fid) for fid in finding.contradicting_finding_ids if fid not in available_finding_ids]
            if missing_contradicting:
                raise ValueError(
                    f"Finding '{finding.summary}' references unknown contradicting_finding_ids: {missing_contradicting}."
                )

        for recommendation in self.recommendations:
            missing_findings = [str(fid) for fid in recommendation.related_finding_ids if fid not in available_finding_ids]
            if missing_findings:
                raise ValueError(
                    f"Recommendation '{recommendation.title}' references unknown related_finding_ids: {missing_findings}."
                )
            missing_evidence = [str(eid) for eid in recommendation.supporting_evidence_ids if eid not in available_evidence_ids]
            if missing_evidence:
                raise ValueError(
                    f"Recommendation '{recommendation.title}' references unknown supporting_evidence_ids: {missing_evidence}."
                )
        return self


# =====================================================================
# 4. ERROR, RESPONSE & MESSAGE ENVELOPE MODELS
# =====================================================================


class AgentError(ProtocolBaseModel):
    """
    Structured operational error representing software, telemetry, validation,
    or LLM failures. Network faults detected in telemetry are AgentFindings, NOT AgentErrors.
    """

    error_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this operational error instance.",
    )
    error_code: ErrorCode = Field(
        ...,
        description="Standardized machine-readable error classification.",
    )
    message: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="Human-readable description of the operational error.",
    )
    source_agent: AgentName = Field(
        ...,
        description="Agent (or orchestrator) where the error occurred.",
    )
    retryable: bool = Field(
        default=False,
        description="True if transient (e.g., Gemini API timeout/rate-limit) and safe to retry.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured diagnostic context (e.g., missing field names, exception info).",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the error occurred.",
    )

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)


class AgentResponse(ProtocolBaseModel):
    """Standardized execution result returned by every agent."""

    agent_name: AgentName = Field(..., description="Agent returning this response.")
    status: ExecutionStatus = Field(..., description="Execution status: success, partial, or failed.")
    findings: list[AgentFinding] = Field(default_factory=list)
    report: Optional[DiagnosticReport] = None
    completed_checks: list[str] = Field(default_factory=list, description="Checks successfully evaluated, including healthy checks with no findings.")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal execution warnings.")
    errors: list[AgentError] = Field(default_factory=list, description="Operational or data-completeness errors.")
    processing_time_ms: Optional[float] = Field(default=None, ge=0.0)
    execution_metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @field_validator("completed_checks")
    @classmethod
    def validate_completed_checks(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("completed_checks entries must be non-empty strings.")
        return cleaned

    @model_validator(mode="after")
    def validate_status_invariants(self) -> AgentResponse:
        has_usable_output = bool(self.findings) or self.report is not None
        has_completed_checks = bool(self.completed_checks)
        has_errors = bool(self.errors)
        has_warnings = bool(self.warnings)

        if self.status == ExecutionStatus.SUCCESS:
            if has_errors:
                raise ValueError("AgentResponse with status='success' cannot contain AgentErrors in 'errors'. Use 'warnings' for non-fatal notes, or status='partial' if checks failed.")
            if self.agent_name == AgentName.REPORTING and self.report is None:
                raise ValueError("Reporting Agent with status='success' must populate the 'report' field.")

        elif self.status == ExecutionStatus.PARTIAL:
            if self.agent_name == AgentName.REPORTING and self.report is None:
                raise ValueError("Reporting Agent with status='partial' must populate the 'report' field.")
            if not has_usable_output and not has_completed_checks:
                raise ValueError("AgentResponse with status='partial' must contain usable output ('findings' or 'report') or non-empty 'completed_checks'. Otherwise, use status='failed'.")
            if not has_errors and not has_warnings:
                raise ValueError("AgentResponse with status='partial' must record at least one entry in 'errors' or 'warnings'.")

        elif self.status == ExecutionStatus.FAILED:
            if has_usable_output:
                raise ValueError("AgentResponse with status='failed' must not contain 'findings' or 'report'. If usable output was produced alongside errors, use status='partial'.")
            if has_completed_checks:
                raise ValueError("AgentResponse with status='failed' must not contain 'completed_checks'. If any checks succeeded, use status='partial'.")
            if not has_errors:
                raise ValueError("AgentResponse with status='failed' must contain at least one AgentError in 'errors'.")
        return self


class AgentMessage(ProtocolBaseModel):
    """
    Top-level communication envelope created by the orchestrator to wrap an
    AgentResponse for inter-agent handoff and PostgreSQL persistence.
    """

    message_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this message (maps to agent_messages.id).",
    )
    incident_id: UUID = Field(
        ...,
        description="Identifier of the network incident being diagnosed.",
    )
    run_id: UUID = Field(
        ...,
        description="Identifier of the specific orchestrator diagnostic run.",
    )
    causation_id: Optional[UUID] = Field(
        default=None,
        description="Optional message_id of the upstream AgentMessage that triggered this step.",
    )
    sender_agent: AgentName = Field(
        ...,
        description="Agent that produced the enclosed response.",
    )
    receiver_agent: AgentName = Field(
        default=AgentName.ORCHESTRATOR,
        description="Intended recipient agent (typically 'orchestrator', 'correlation', or 'reporting').",
    )
    message_type: MessageType = Field(
        default=MessageType.AGENT_RESPONSE,
        description="Envelope classification ('agent_response' or 'error_report').",
    )
    schema_version: str = Field(
        default=CURRENT_SCHEMA_VERSION,
        description="Protocol schema version string (e.g., '1.0').",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC creation timestamp of the message (maps to agent_messages.created_at).",
    )
    payload: AgentResponse = Field(
        ...,
        description="Structured AgentResponse payload (maps to agent_messages.payload JSONB).",
    )

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value not in SUPPORTED_SCHEMA_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
            raise ValueError(
                f"Unsupported schema_version '{value}'. Supported versions: [{supported}]."
            )
        return value

    @model_validator(mode="after")
    def validate_envelope_consistency(self) -> AgentMessage:
        """
        Ensures envelope fields match the enclosed AgentResponse payload:
-         sender_agent must match payload.agent_name.
-         ERROR_REPORT messages must wrap a FAILED payload.
        """
        if self.sender_agent != self.payload.agent_name:
            raise ValueError(
                f"Envelope sender_agent ('{self.sender_agent.value}') must match "
                f"payload.agent_name ('{self.payload.agent_name.value}')."
            )
        if (
            self.message_type == MessageType.ERROR_REPORT
            and self.payload.status != ExecutionStatus.FAILED
        ):
            raise ValueError(
                "AgentMessage with message_type='error_report' must wrap a payload with status='failed'."
            )
        return self

    def to_json_dict(self) -> dict[str, Any]:
        """
        Serializes the AgentMessage into JSON-compatible Python primitives
        (UUIDs -> str, datetimes -> ISO-8601 UTC strings, Enums -> str).
        """
        return self.model_dump(mode="json")

    def to_db_record(self) -> dict[str, Any]:
        """
        Maps the AgentMessage directly to the PostgreSQL 'agent_messages' table columns:
        (id, incident_id, run_id, sender_agent, receiver_agent, message_type,
         schema_version, payload, created_at).
        """
        return {
            "id": self.message_id,
            "incident_id": self.incident_id,
            "run_id": self.run_id,
            "sender_agent": self.sender_agent.value,
            "receiver_agent": self.receiver_agent.value,
            "message_type": self.message_type.value,
            "schema_version": self.schema_version,
            "payload": self.payload.model_dump(mode="json"),
            "created_at": self.timestamp,
        }


# =====================================================================
# 5. PROTOCOL VALIDATION HELPER
# =====================================================================


def parse_incoming_message(
    raw_data: Union[dict[str, Any], str, bytes],
    expected_receiver: Optional[AgentName] = None,
) -> Union[AgentMessage, AgentError]:
    """
    Safely parses and validates a serialized dictionary or JSON string into an AgentMessage.
-     Checks schema_version and full Pydantic model invariants.
-     If 'expected_receiver' is provided, verifies that message.receiver_agent matches it.
-     Returns a structured AgentError on any validation or routing mismatch rather than
      raising an unhandled exception.
    """
    fallback_agent = expected_receiver or AgentName.ORCHESTRATOR

    if not isinstance(raw_data, (dict, str, bytes)):
        return AgentError(
            error_code=ErrorCode.INVALID_MESSAGE,
            message=f"Expected dict, str, or bytes for message parsing, got {type(raw_data).__name__}.",
            source_agent=fallback_agent,
            retryable=False,
        )

    try:
        if isinstance(raw_data, (str, bytes)):
            message = AgentMessage.model_validate_json(raw_data)
        else:
            message = AgentMessage.model_validate(raw_data)
    except ValidationError as exc:
        errors = exc.errors()
        is_schema_err = any(
            "schema_version" in str(err.get("loc", ())) for err in errors
        )
        error_code = (
            ErrorCode.UNSUPPORTED_SCHEMA
            if is_schema_err
            else ErrorCode.INVALID_MESSAGE
        )
        # Convert error details into JSON-safe strings so details dict is always serializable
        sanitized_errors = [
            {
                "loc": [str(part) for part in err.get("loc", ())],
                "msg": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in errors
        ]
        return AgentError(
            error_code=error_code,
            message=f"Incoming message failed protocol validation ({len(sanitized_errors)} error(s)).",
            source_agent=fallback_agent,
            retryable=False,
            details={"validation_errors": sanitized_errors},
        )

    if expected_receiver is not None and message.receiver_agent != expected_receiver:
        return AgentError(
            error_code=ErrorCode.INVALID_MESSAGE,
            message=(
                f"Message recipient mismatch: expected '{expected_receiver.value}', "
                f"but message receiver_agent is '{message.receiver_agent.value}'."
            ),
            source_agent=expected_receiver,
            retryable=False,
            details={
                "message_id": str(message.message_id),
                "expected_receiver": expected_receiver.value,
                "actual_receiver": message.receiver_agent.value,
            },
        )

    return message

