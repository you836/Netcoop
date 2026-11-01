"""Deterministic cross-agent fault correlation and root-cause hypothesis ranking for NetCoop AI (Agent 4)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from time import perf_counter
from typing import Any, Optional, Union
from uuid import UUID

from pydantic import Field, ValidationError, field_validator

from .common import (
    AgentError,
    AgentFinding,
    AgentMessage,
    AgentName,
    AgentResponse,
    DiagnosisStatus,
    DiagnosticReport,
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
# 1. CORRELATION CONSTANTS, WEIGHTS & THRESHOLDS
# =====================================================================

UPSTREAM_SPECIALIST_AGENTS: frozenset[AgentName] = frozenset(
    {
        AgentName.PERFORMANCE,
        AgentName.INFRASTRUCTURE,
        AgentName.CONNECTIVITY,
    }
)

DEFAULT_CORRELATION_CONFIG: dict[str, float] = {
    # Maximum allowed timestamp skew (seconds) before evidence is considered misaligned/stale
    "max_timestamp_skew_seconds": 900.0,
    # Minimum confidence and domain coverage to classify as IDENTIFIED vs PARTIAL_HYPOTHESIS
    "identified_min_confidence": 0.75,
    "partial_hypothesis_min_confidence": 0.40,
    # Scoring weights
    "base_single_domain_weight": 0.25,
    "cross_domain_infra_perf_bonus": 0.28,
    "cross_domain_connectivity_bonus": 0.16,
    "independent_evidence_weight_per_item": 0.05,
    "max_independent_evidence_bonus": 0.15,
    "high_severity_infra_bonus": 0.08,
    "shared_segment_bonus": 0.05,
    "contradiction_penalty_per_item": 0.22,
    "timestamp_skew_penalty": 0.15,
    "missing_agent_penalty_per_agent": 0.06,
    "max_confidence_cap": 0.95,
    "single_agent_confidence_cap": 0.62,
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

# Finding codes that represent normal/healthy or explicitly non-faulty counter-observations
NEGATIVE_OR_CONTRADICTING_FINDING_CODES: frozenset[str] = frozenset(
    {
        "NORMAL_PERFORMANCE",
        "HEALTHY_PERFORMANCE",
        "NORMAL_LATENCY",
        "NORMAL_PACKET_LOSS",
        "HEALTHY_DEVICE",
        "DEVICE_HEALTHY",
        "NORMAL_CPU_UTILIZATION",
        "NORMAL_MEMORY_UTILIZATION",
        "NO_INTERFACE_ERRORS",
        "NO_QUEUE_DROPS",
        "PATH_HEALTHY",
    }
)

# Finding codes that provide informational context rather than an active fault
INFORMATIONAL_FINDING_CODES: frozenset[str] = frozenset(
    {
        "ALTERNATE_PHYSICAL_PATH_IDENTIFIED",
        "REDUNDANT_PHYSICAL_LINK",
    }
)


# =====================================================================
# 2. CANDIDATE ROOT-CAUSE HYPOTHESIS MODEL
# =====================================================================


class RootCauseHypothesis(ProtocolBaseModel):
    """
    Internal structured representation of a candidate root-cause hypothesis
    evaluated and ranked by the Fault Correlation Agent.
    """

    candidate_id: str = Field(..., min_length=2, max_length=128, description="Deterministic identifier for the candidate hypothesis.")
    finding_code: str = Field(..., min_length=2, max_length=64, description="UPPER_SNAKE_CASE root cause code.")
    title: str = Field(..., min_length=5, max_length=240, description="Concise summary of the hypothesis.")
    description: str = Field(..., min_length=10, max_length=2000, description="Detailed technical explanation of the correlated hypothesis.")
    severity: Severity = Field(..., description="Consolidated severity of the candidate hypothesis.")
    focal_device_id: Optional[str] = Field(default=None, description="Primary suspected device ID, if device-scoped.")
    focal_segment_id: Optional[str] = Field(default=None, description="Primary network segment ID, if segment-scoped.")
    affected_devices: list[str] = Field(default_factory=list)
    affected_segments: list[str] = Field(default_factory=list)
    related_findings: list[AgentFinding] = Field(default_factory=list)
    supporting_finding_ids: list[UUID] = Field(default_factory=list)
    contradicting_finding_ids: list[UUID] = Field(default_factory=list)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    supporting_evidence: list[Evidence] = Field(default_factory=list)
    contributing_agents: list[AgentName] = Field(default_factory=list)
    independent_telemetry_keys: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    timestamp_skew_seconds: float = Field(default=0.0, ge=0.0)
    reference_timestamp: Optional[datetime] = Field(default=None)
    confidence: float = Field(..., ge=0.0, le=1.0)
    score_explanation: str = Field(..., min_length=5, max_length=1000)

    @field_validator("confidence")
    @classmethod
    def round_conf(cls, value: float) -> float:
        return round(float(value), 4)

    def to_agent_finding(self) -> AgentFinding:
        """Converts this ranked candidate hypothesis into a shared-protocol AgentFinding."""
        limitations_merged = list(dict.fromkeys([*self.limitations, *self.missing_evidence]))
        full_description = f"{self.description} [Score rationale: {self.score_explanation}]"
        if len(full_description) > 2000:
            full_description = full_description[:1997] + "..."
        finding_kwargs: dict[str, Any] = {}
        if self.reference_timestamp is not None:
            finding_kwargs["timestamp"] = self.reference_timestamp
        return AgentFinding(
            agent_source=AgentName.CORRELATION,
            finding_code=self.finding_code,
            finding_type=FindingType.ROOT_CAUSE_HYPOTHESIS,
            severity=self.severity,
            summary=self.title,
            description=full_description,
            confidence=self.confidence,
            affected_devices=self.affected_devices,
            affected_segments=self.affected_segments,
            evidence=self.supporting_evidence,
            supporting_finding_ids=self.supporting_finding_ids,
            contradicting_finding_ids=self.contradicting_finding_ids,
            limitations=limitations_merged,
            **finding_kwargs,
        )


# =====================================================================
# 3. PURE SCORING & DEDUPLICATION HELPERS
# =====================================================================


def _dedup_findings(findings: Sequence[AgentFinding]) -> list[AgentFinding]:
    """Deduplicates a sequence of AgentFinding objects while preserving order."""
    seen: set[UUID] = set()
    result: list[AgentFinding] = []
    for f in findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            result.append(f)
    return result


def deduplicate_independent_evidence(findings: Sequence[AgentFinding]) -> tuple[list[Evidence], list[str], int]:
    """
    Collects unique Evidence records across `findings` and deduplicates observations
    that originate from the exact same underlying telemetry record (`telemetry_record_id`)
    or identical `(source_agent, evidence_type, metric_name, device_id, interface_id, segment_id, observed_value)`
    so that multiple findings referencing the same raw telemetry row are never double-counted.

    Returns:
        (unique_evidence_objects, independent_source_keys, duplicate_references_skipped)
    """
    unique_evidence: list[Evidence] = []
    seen_evidence_ids: set[UUID] = set()
    independent_keys: list[str] = []
    seen_telemetry_keys: set[str] = set()
    duplicates_skipped = 0

    for finding in findings:
        for ev in finding.evidence:
            if ev.evidence_id not in seen_evidence_ids:
                seen_evidence_ids.add(ev.evidence_id)
                unique_evidence.append(ev)

            if ev.telemetry_record_id:
                tel_key = f"rec:{ev.telemetry_record_id}"
            else:
                tel_key = (
                    f"obs:{ev.source_agent.value}:{ev.evidence_type.value}:{ev.metric_name}:"
                    f"{ev.device_id or ''}:{ev.interface_id or ''}:{ev.segment_id or ''}:{ev.observed_value}"
                )

            if tel_key in seen_telemetry_keys:
                duplicates_skipped += 1
            else:
                seen_telemetry_keys.add(tel_key)
                independent_keys.append(tel_key)

    return unique_evidence, independent_keys, duplicates_skipped


def compute_timestamp_skew_seconds(findings: Sequence[AgentFinding]) -> float:
    """Computes the maximum timestamp span in seconds across all evidence and findings in a group."""
    timestamps: list[datetime] = []
    for f in findings:
        timestamps.append(ensure_utc_timestamp(f.timestamp))
        for ev in f.evidence:
            timestamps.append(ensure_utc_timestamp(ev.timestamp))
    if len(timestamps) < 2:
        return 0.0
    earliest = min(timestamps)
    latest = max(timestamps)
    return max(0.0, (latest - earliest).total_seconds())


def _has_explicit_timestamp(finding: AgentFinding) -> bool:
    """
    Returns True only if the finding and its evidence carry explicit observation
    timestamps rather than timestamps defaulted to utc_now() during ingestion.
    """
    if "timestamp" not in finding.model_fields_set:
        return False
    for ev in finding.evidence:
        if "timestamp" not in ev.model_fields_set:
            return False
    for lim in finding.limitations:
        low = lim.lower()
        if (
            "omitted an explicit observation timestamp" in low
            or "defaulted to ingestion time" in low
            or "missing timestamp" in low
        ):
            return False
    return True


def _finding_effective_timestamp(finding: AgentFinding) -> datetime:
    """Returns the earliest UTC timestamp across a finding and its attached evidence."""
    ts_list = [ensure_utc_timestamp(finding.timestamp)]
    for ev in finding.evidence:
        ts_list.append(ensure_utc_timestamp(ev.timestamp))
    return min(ts_list)


def _partition_findings_by_freshness(
    cand_findings: Sequence[AgentFinding],
    all_incident_findings: Sequence[AgentFinding],
    max_skew_seconds: float,
) -> tuple[list[AgentFinding], list[AgentFinding], list[AgentFinding], float, Optional[datetime]]:
    """
    Partitions candidate findings into:
      - current_findings: temporally aligned with the incident/candidate reference timestamp (<= max_skew_seconds)
      - stale_findings: explicit-timestamp findings older than ref_time by > max_skew_seconds
      - missing_ts_findings: telemetry findings whose observation timestamp was omitted and defaulted to utc_now()
      - skew_sec: maximum timestamp skew (in seconds) across the candidate and incident reference time
      - ref_time: resolved reference timestamp for the candidate
    """
    # Structural topology findings from ConnectivityAgent do not carry time-series sample timestamps
    # unless explicitly provided; treat them as structural context rather than missing-timestamp telemetry.
    structural_conn: list[AgentFinding] = []
    telemetry_cand: list[AgentFinding] = []
    for f in cand_findings:
        if f.agent_source == AgentName.CONNECTIVITY and not _has_explicit_timestamp(f):
            structural_conn.append(f)
        else:
            telemetry_cand.append(f)

    explicit_cand: list[AgentFinding] = []
    missing_ts_cand: list[AgentFinding] = []
    for f in telemetry_cand:
        if _has_explicit_timestamp(f):
            explicit_cand.append(f)
        else:
            missing_ts_cand.append(f)

    # If some telemetry findings omitted timestamps (defaulted to utc_now()) and other telemetry findings
    # in the same call have timestamps within 5s of that live utc_now() timestamp, both were generated
    # using live default timestamps in the same invocation rather than historical vs current timestamps.
    if missing_ts_cand and explicit_cand:
        missing_latest = max(_finding_effective_timestamp(f) for f in missing_ts_cand)
        all_within_live_window = all(
            abs((_finding_effective_timestamp(f) - missing_latest).total_seconds()) <= 5.0
            for f in explicit_cand
        )
        if all_within_live_window:
            skew_sec = compute_timestamp_skew_seconds(telemetry_cand)
            ref_time = max((_finding_effective_timestamp(f) for f in telemetry_cand), default=None)
            return list(cand_findings), [], missing_ts_cand, skew_sec, ref_time

    explicit_incident = [
        f
        for f in all_incident_findings
        if (f.agent_source != AgentName.CONNECTIVITY or _has_explicit_timestamp(f))
        and _has_explicit_timestamp(f)
    ]

    if explicit_cand or explicit_incident:
        ref_pool = explicit_cand if explicit_cand else explicit_incident
        cand_latest = max(_finding_effective_timestamp(f) for f in ref_pool)
        inc_latest = max(
            (_finding_effective_timestamp(f) for f in explicit_incident),
            default=cand_latest,
        )
        ref_time = max(cand_latest, inc_latest)

        current_telemetry: list[AgentFinding] = []
        stale_findings: list[AgentFinding] = []
        max_age = 0.0
        for f in explicit_cand:
            age = max(0.0, (ref_time - _finding_effective_timestamp(f)).total_seconds())
            if age > max_age:
                max_age = age
            if age <= max_skew_seconds:
                current_telemetry.append(f)
            else:
                stale_findings.append(f)

        explicit_skew = (
            compute_timestamp_skew_seconds(explicit_cand)
            if len(explicit_cand) >= 2
            else max_age
        )
        skew_sec = max(explicit_skew, max_age)
        current_findings = (
            [*current_telemetry, *structural_conn]
            if (current_telemetry or not stale_findings)
            else list( current_telemetry)
        )
        return current_findings, stale_findings, missing_ts_cand, skew_sec, ref_time

    # All telemetry findings on the candidate omitted explicit timestamps and defaulted to utc_now()
    skew_sec = compute_timestamp_skew_seconds(telemetry_cand)
    ref_time = max((_finding_effective_timestamp(f) for f in cand_findings), default=None)
    return list(cand_findings), [], missing_ts_cand, skew_sec, ref_time


def score_hypothesis_confidence(
    *,
    contributing_agents: set[AgentName],
    independent_evidence_count: int,
    has_direct_infra_fault: bool,
    has_perf_degradation: bool,
    has_connectivity_link: bool,
    has_shared_segment: bool,
    max_infra_severity: Optional[Severity],
    contradiction_count: int,
    timestamp_skew_seconds: float,
    missing_agents_count: int,
    config: Mapping[str, float],
) -> tuple[float, str]:
    """
    Deterministic, explainable heuristic confidence calculation in [0.05, 0.95].
    Never simply counts agreeing agents; weights domain alignment, independent telemetry
    records, severity, timestamp consistency, missing upstream agents, and contradictions.
    """
    score = 0.0
    parts: list[str] = []

    if has_direct_infra_fault and has_perf_degradation:
        base = config["base_single_domain_weight"] + config["cross_domain_infra_perf_bonus"]
        score += base
        parts.append(f"infra+perf alignment (+{base:.2f})")
    elif has_direct_infra_fault:
        base = config["base_single_domain_weight"] + 0.12
        score += base
        parts.append(f"direct infrastructure fault (+{base:.2f})")
    elif has_perf_degradation and has_connectivity_link:
        base = config["base_single_domain_weight"] + 0.10
        score += base
        parts.append(f"perf+connectivity scope (+{base:.2f})")
    else:
        base = config["base_single_domain_weight"]
        score += base
        parts.append(f"single-domain symptom (+{base:.2f})")

    if has_connectivity_link and (has_direct_infra_fault or has_perf_degradation):
        conn_bonus = config["cross_domain_connectivity_bonus"]
        score += conn_bonus
        parts.append(f"topological relationship verified (+{conn_bonus:.2f})")

    if has_shared_segment:
        seg_bonus = config["shared_segment_bonus"]
        score += seg_bonus
        parts.append(f"shared segment alignment (+{seg_bonus:.2f})")

    if max_infra_severity in (Severity.CRITICAL, Severity.HIGH):
        sev_bonus = config["high_severity_infra_bonus"] if max_infra_severity == Severity.CRITICAL else config["high_severity_infra_bonus"] * 0.5
        score += sev_bonus
        parts.append(f"infra severity {max_infra_severity.value} (+{sev_bonus:.2f})")

    # Independent evidence bonus (capped so many metrics from 1 agent cannot inflate score to 1.0)
    extra_indep = max(0, independent_evidence_count - 1)
    indep_bonus = min(
        config["max_independent_evidence_bonus"],
        extra_indep * config["independent_evidence_weight_per_item"],
    )
    if indep_bonus > 0:
        score += indep_bonus
        parts.append(f"{independent_evidence_count} independent telemetry records (+{indep_bonus:.2f})")

    # Penalties for timestamp skew
    if timestamp_skew_seconds > config["max_timestamp_skew_seconds"]:
        skew_pen = config["timestamp_skew_penalty"]
        score -= skew_pen
        parts.append(f"timestamp skew {timestamp_skew_seconds:.0f}s (-{skew_pen:.2f})")

    # Penalties for missing upstream specialist agents
    if missing_agents_count > 0:
        miss_pen = missing_agents_count * config["missing_agent_penalty_per_agent"]
        score -= miss_pen
        parts.append(f"{missing_agents_count} missing/failed upstream agent(s) (-{miss_pen:.2f})")

    # Penalties for contradicting findings
    if contradiction_count > 0:
        contra_pen = contradiction_count * config["contradiction_penalty_per_item"]
        score -= contra_pen
        parts.append(f"{contradiction_count} contradicting observation(s) (-{contra_pen:.2f})")

    # Enforce single-agent cap so a single agent alone never reaches high certainty
    if len(contributing_agents) <= 1:
        if score > config["single_agent_confidence_cap"]:
            score = config["single_agent_confidence_cap"]
            parts.append(f"capped at {config['single_agent_confidence_cap']:.2f} (single agent source)")

    bounded = max(0.05, min(config["max_confidence_cap"], score))
    return round(bounded, 4), "; ".join(parts)


# =====================================================================
# 4. FAULT CORRELATION AGENT
# =====================================================================


class CorrelationAgent:
    """
    Agent 4: Fault Correlation Agent.

    Consumes upstream `AgentResponse` or `AgentMessage` envelopes from the
    Performance, Infrastructure, and Connectivity agents, validates cross-references
    and incident/run consistency, synthesizes and ranks competing root-cause
    hypotheses, and produces an `AgentResponse` (plus optional `DiagnosticReport` preview).
    """

    agent_name = AgentName.CORRELATION

    def __init__(self, config: Optional[Mapping[str, float]] = None) -> None:
        self.config: dict[str, float] = {
            **DEFAULT_CORRELATION_CONFIG,
            **(dict(config) if config else {}),
        }
        for k, v in self.config.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"Correlation config '{k}' must be a non-negative number, got {v!r}.")

    @staticmethod
    def _make_error(code: ErrorCode, message: str, **details: Any) -> AgentError:
        return AgentError(
            error_code=code,
            message=message,
            source_agent=AgentName.CORRELATION,
            retryable=False,
            details=details,
        )

    def analyze(
        self,
        upstream_input: Union[
            Sequence[Union[AgentResponse, AgentMessage, Mapping[str, Any]]],
            Mapping[str, Any],
        ],
        *,
        incident_id: Optional[UUID] = None,
        run_id: Optional[UUID] = None,
    ) -> AgentResponse:
        """
        Correlates upstream agent responses into ranked `ROOT_CAUSE_HYPOTHESIS` findings.
        """
        started = perf_counter()
        errors: list[AgentError] = []
        warnings: list[str] = []
        completed_checks: list[str] = []

        parsed_responses, resolved_incident_id, resolved_run_id = self._parse_and_validate_inputs(
            upstream_input=upstream_input,
            explicit_incident_id=incident_id,
            explicit_run_id=run_id,
            errors=errors,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        if not parsed_responses:
            if not errors:
                errors.append(
                    self._make_error(
                        ErrorCode.MISSING_INPUT,
                        "No valid upstream agent responses were supplied for fault correlation.",
                    )
                )
            return AgentResponse(
                agent_name=AgentName.CORRELATION,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={
                    "diagnosis_status": DiagnosisStatus.INCONCLUSIVE.value,
                    "upstream_agents_received": [],
                    "hypotheses_generated": 0,
                },
            )

        # Track upstream agent statuses, missing agents, and limitations
        received_agents: set[AgentName] = set()
        usable_agents: set[AgentName] = set()
        failed_agents: set[AgentName] = set()
        partial_agents: set[AgentName] = set()
        global_limitations: list[str] = []
        all_valid_findings: list[AgentFinding] = []
        healthy_completed_checks: dict[AgentName, set[str]] = {}

        for resp in parsed_responses:
            received_agents.add(resp.agent_name)
            healthy_completed_checks.setdefault(resp.agent_name, set()).update(resp.completed_checks)

            if resp.status == ExecutionStatus.FAILED:
                failed_agents.add(resp.agent_name)
                err_msgs = "; ".join(e.message for e in resp.errors) if resp.errors else "unspecified error"
                lim = f"Upstream '{resp.agent_name.value}' agent FAILED ({err_msgs}); its domain telemetry is unavailable."
                global_limitations.append(lim)
                warnings.append(lim)
                continue

            usable_agents.add(resp.agent_name)
            if resp.status == ExecutionStatus.PARTIAL:
                partial_agents.add(resp.agent_name)
                lim = f"Upstream '{resp.agent_name.value}' agent returned PARTIAL status ({len(resp.errors)} error(s), {len(resp.warnings)} warning(s))."
                global_limitations.append(lim)
                warnings.append(lim)

            for w in resp.warnings:
                if w not in warnings:
                    warnings.append(f"[{resp.agent_name.value}] {w}")

            # Validate each finding and its evidence before accepting it
            for f_idx, finding in enumerate(resp.findings):
                if not self._validate_upstream_finding(
                    resp_agent=resp.agent_name,
                    finding=finding,
                    finding_index=f_idx,
                    errors=errors,
                ):
                    continue
                all_valid_findings.append(finding)

        missing_agents = sorted(
            (UPSTREAM_SPECIALIST_AGENTS - usable_agents),
            key=lambda a: a.value,
        )
        for ma in missing_agents:
            if ma not in failed_agents:
                lim = f"No response received from upstream '{ma.value}' agent; correlation lacks '{ma.value}' domain visibility."
                global_limitations.append(lim)
                warnings.append(lim)

        completed_checks.append("upstream_response_validation")

        # If no usable agent succeeded or partially succeeded, return FAILED
        if not usable_agents:
            if not errors:
                errors.append(
                    self._make_error(
                        ErrorCode.MISSING_INPUT,
                        "All supplied upstream agent responses had status='failed'; correlation cannot proceed.",
                    )
                )
            return AgentResponse(
                agent_name=AgentName.CORRELATION,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={
                    "diagnosis_status": DiagnosisStatus.INCONCLUSIVE.value,
                    "upstream_agents_received": sorted(a.value for a in received_agents),
                    "failed_agents": sorted(a.value for a in failed_agents),
                },
            )

        # Separate positive fault/scope findings from explicit negative/healthy findings
        positive_findings: list[AgentFinding] = []
        negative_findings: list[AgentFinding] = []
        info_findings: list[AgentFinding] = []

        for f in all_valid_findings:
            if f.finding_code in NEGATIVE_OR_CONTRADICTING_FINDING_CODES:
                negative_findings.append(f)
            elif f.finding_code in INFORMATIONAL_FINDING_CODES or f.severity == Severity.INFO:
                info_findings.append(f)
            else:
                positive_findings.append(f)

        # Build candidate root-cause hypotheses deterministically
        completed_checks.append("cross_agent_hypothesis_generation")
        completed_checks.append("evidence_deduplication_and_traceability")
        completed_checks.append("contradiction_and_timestamp_consistency_check")

        hypotheses = self._synthesize_hypotheses(
            positive_findings=positive_findings,
            negative_findings=negative_findings,
            info_findings=info_findings,
            healthy_completed_checks=healthy_completed_checks,
            missing_agents=missing_agents,
            global_limitations=global_limitations,
            warnings=warnings,
        )

        completed_checks.append("hypothesis_ranking_and_scoring")

        # Determine overall DiagnosisStatus
        diagnosis_status = self._determine_diagnosis_status(
            hypotheses=hypotheses,
            usable_agents=usable_agents,
            missing_agents=missing_agents,
        )

        correlation_findings = [h.to_agent_finding() for h in hypotheses]

        # Determine ExecutionStatus of the Correlation Agent
        has_incomplete_context = bool(errors) or bool(failed_agents) or bool(partial_agents) or bool(missing_agents)
        if has_incomplete_context and (correlation_findings or completed_checks):
            exec_status = ExecutionStatus.PARTIAL
            if errors and not warnings:
                warnings.append(f"{len(errors)} upstream validation error(s) encountered during correlation.")
        elif errors and not correlation_findings and not completed_checks:
            exec_status = ExecutionStatus.FAILED
        else:
            exec_status = ExecutionStatus.SUCCESS

        deduped_checks = list(dict.fromkeys(completed_checks))

        return AgentResponse(
            agent_name=AgentName.CORRELATION,
            status=exec_status,
            findings=correlation_findings,
            completed_checks=deduped_checks,
            warnings=warnings,
            errors=errors,
            processing_time_ms=(perf_counter() - started) * 1000,
            execution_metadata={
                "incident_id": str(resolved_incident_id) if resolved_incident_id else None,
                "run_id": str(resolved_run_id) if resolved_run_id else None,
                "diagnosis_status": diagnosis_status.value,
                "overall_confidence": hypotheses[0].confidence if hypotheses else 0.0,
                "upstream_agents_received": sorted(a.value for a in received_agents),
                "usable_agents": sorted(a.value for a in usable_agents),
                "missing_or_failed_agents": [a.value for a in missing_agents],
                "upstream_findings_count": len(all_valid_findings),
                "supporting_findings": [f.model_dump(mode="json") for f in all_valid_findings],
                "supporting_finding_ids": [str(f.finding_id) for f in all_valid_findings],
                "ranked_hypotheses": [
                    {
                        "candidate_id": h.candidate_id,
                        "finding_code": h.finding_code,
                        "confidence": h.confidence,
                        "severity": h.severity.value,
                        "affected_devices": h.affected_devices,
                        "affected_segments": h.affected_segments,
                        "supporting_finding_ids": [str(fid) for fid in h.supporting_finding_ids],
                        "contradicting_finding_ids": [str(fid) for fid in h.contradicting_finding_ids],
                        "supporting_evidence_ids": [str(eid) for eid in h.supporting_evidence_ids],
                        "independent_evidence_count": len(h.independent_telemetry_keys),
                        "timestamp_skew_seconds": h.timestamp_skew_seconds,
                        "score_explanation": h.score_explanation,
                        "missing_evidence": h.missing_evidence,
                    }
                    for h in hypotheses
                ],
                "limitations_and_uncertainties": list(dict.fromkeys(global_limitations)),
            },
        )

    # -----------------------------------------------------------------
    # INPUT PARSING & CONSISTENCY VALIDATION
    # -----------------------------------------------------------------

    def _parse_and_validate_inputs(
        self,
        upstream_input: Any,
        explicit_incident_id: Optional[UUID],
        explicit_run_id: Optional[UUID],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
    ) -> tuple[list[AgentResponse], Optional[UUID], Optional[UUID]]:
        raw_items: list[Any] = []
        resolved_incident_id = explicit_incident_id
        resolved_run_id = explicit_run_id

        if isinstance(upstream_input, (AgentResponse, AgentMessage)):
            raw_items = [upstream_input]
        elif isinstance(upstream_input, Mapping):
            if "incident_id" in upstream_input and upstream_input["incident_id"] is not None:
                try:
                    inc_val = upstream_input["incident_id"]
                    resolved_incident_id = inc_val if isinstance(inc_val, UUID) else UUID(str(inc_val))
                except ValueError:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Invalid top-level incident_id '{upstream_input['incident_id']}'.",
                        )
                    )
            if "run_id" in upstream_input and upstream_input["run_id"] is not None:
                try:
                    r_val = upstream_input["run_id"]
                    resolved_run_id = r_val if isinstance(r_val, UUID) else UUID(str(r_val))
                except ValueError:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Invalid top-level run_id '{upstream_input['run_id']}'.",
                        )
                    )

            if "responses" in upstream_input and isinstance(upstream_input["responses"], Sequence):
                raw_items = list(upstream_input["responses"])
            elif "messages" in upstream_input and isinstance(upstream_input["messages"], Sequence):
                raw_items = list(upstream_input["messages"])
            elif any(k in upstream_input for k in ("performance", "infrastructure", "connectivity")):
                for key in ("performance", "infrastructure", "connectivity"):
                    if key in upstream_input and upstream_input[key] is not None:
                        raw_items.append(upstream_input[key])
            elif "agent_name" in upstream_input or "payload" in upstream_input:
                raw_items = [upstream_input]
            else:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        "Mapping input to CorrelationAgent must contain 'responses', 'messages', or agent keys ('performance', 'infrastructure', 'connectivity').",
                    )
                )
                return [], resolved_incident_id, resolved_run_id
        elif isinstance(upstream_input, Sequence) and not isinstance(upstream_input, (str, bytes)):
            raw_items = list(upstream_input)
        else:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"Correlation input must be a sequence of AgentResponse/AgentMessage objects or a mapping, got {type(upstream_input).__name__}.",
                )
            )
            return [], resolved_incident_id, resolved_run_id

        valid_responses: list[AgentResponse] = []

        for idx, item in enumerate(raw_items):
            item_incident_id: Optional[UUID] = None
            item_run_id: Optional[UUID] = None
            resp: Optional[AgentResponse] = None

            try:
                if isinstance(item, AgentMessage):
                    item_incident_id = item.incident_id
                    item_run_id = item.run_id
                    resp = item.payload
                elif isinstance(item, AgentResponse):
                    resp = item
                    item_incident_id, item_run_id = self._extract_ids_from_metadata(resp.execution_metadata)
                elif isinstance(item, Mapping):
                    if "payload" in item and "sender_agent" in item:
                        msg = AgentMessage.model_validate(item)
                        item_incident_id = msg.incident_id
                        item_run_id = msg.run_id
                        resp = msg.payload
                    else:
                        raw_copy = dict(item)
                        raw_inc = raw_copy.pop("incident_id", None)
                        raw_run = raw_copy.pop("run_id", None)
                        resp = AgentResponse.model_validate(raw_copy)
                        meta_inc, meta_run = self._extract_ids_from_metadata(resp.execution_metadata)
                        if raw_inc is not None:
                            item_incident_id = raw_inc if isinstance(raw_inc, UUID) else UUID(str(raw_inc))
                        else:
                            item_incident_id = meta_inc
                        if raw_run is not None:
                            item_run_id = raw_run if isinstance(raw_run, UUID) else UUID(str(raw_run))
                        else:
                            item_run_id = meta_run
                else:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Upstream item at index {idx} must be an AgentResponse, AgentMessage, or dict, got {type(item).__name__}.",
                            item_index=idx,
                        )
                    )
                    continue
            except (ValidationError, ValueError, TypeError) as exc:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Upstream response at index {idx} failed protocol validation: {exc}",
                        item_index=idx,
                    )
                )
                continue

            # Validate agent identity: must be one of the upstream specialist agents
            if resp.agent_name not in UPSTREAM_SPECIALIST_AGENTS:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Upstream response at index {idx} has unsupported agent_name '{resp.agent_name.value}'; "
                        f"expected one of {[a.value for a in sorted(UPSTREAM_SPECIALIST_AGENTS, key=lambda x: x.value)]}.",
                        item_index=idx,
                        agent_name=resp.agent_name.value,
                    )
                )
                continue

            # Validate incident_id and run_id consistency across upstream responses
            if item_incident_id is not None:
                if resolved_incident_id is None:
                    resolved_incident_id = item_incident_id
                elif item_incident_id != resolved_incident_id:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Inconsistent incident_id in '{resp.agent_name.value}' response at index {idx}: "
                            f"expected '{resolved_incident_id}', got '{item_incident_id}'. Response rejected.",
                            item_index=idx,
                            expected_incident_id=str(resolved_incident_id),
                            actual_incident_id=str(item_incident_id),
                        )
                    )
                    continue

            if item_run_id is not None:
                if resolved_run_id is None:
                    resolved_run_id = item_run_id
                elif item_run_id != resolved_run_id:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Inconsistent run_id in '{resp.agent_name.value}' response at index {idx}: "
                            f"expected '{resolved_run_id}', got '{item_run_id}'. Response rejected.",
                            item_index=idx,
                            expected_run_id=str(resolved_run_id),
                            actual_run_id=str(item_run_id),
                        )
                    )
                    continue

            valid_responses.append(resp)

        return valid_responses, resolved_incident_id, resolved_run_id

    @staticmethod
    def _extract_ids_from_metadata(meta: Mapping[str, Any]) -> tuple[Optional[UUID], Optional[UUID]]:
        inc_id: Optional[UUID] = None
        run_id: Optional[UUID] = None
        if meta.get("incident_id"):
            try:
                val = meta["incident_id"]
                inc_id = val if isinstance(val, UUID) else UUID(str(val))
            except ValueError:
                pass
        if meta.get("run_id"):
            try:
                val = meta["run_id"]
                run_id = val if isinstance(val, UUID) else UUID(str(val))
            except ValueError:
                pass
        return inc_id, run_id

    def _validate_upstream_finding(
        self,
        resp_agent: AgentName,
        finding: AgentFinding,
        finding_index: int,
        errors: list[AgentError],
    ) -> bool:
        """
        Verifies that an upstream finding's `agent_source` matches the response's `agent_name`,
        that its `evidence` list is non-empty, and that each `Evidence.source_agent` matches.
        """
        if finding.agent_source != resp_agent:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Finding '{finding.finding_code}' (index {finding_index}) has agent_source='{finding.agent_source.value}' "
                    f"which does not match response agent_name='{resp_agent.value}'.",
                    finding_id=str(finding.finding_id),
                )
            )
            return False

        if not finding.evidence:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Finding '{finding.finding_code}' (index {finding_index}) has no supporting evidence.",
                    finding_id=str(finding.finding_id),
                )
            )
            return False

        for ev in finding.evidence:
            if ev.source_agent != resp_agent:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Evidence '{ev.evidence_id}' in finding '{finding.finding_code}' has source_agent='{ev.source_agent.value}' "
                        f"mismatching finding agent '{resp_agent.value}'.",
                        finding_id=str(finding.finding_id),
                        evidence_id=str(ev.evidence_id),
                    )
                )
                return False

        return True

    # -----------------------------------------------------------------
    # CORRELATION & HYPOTHESIS SYNTHESIS ENGINE
    # -----------------------------------------------------------------

    def _synthesize_hypotheses(
        self,
        *,
        positive_findings: list[AgentFinding],
        negative_findings: list[AgentFinding],
        info_findings: list[AgentFinding],
        healthy_completed_checks: dict[AgentName, set[str]],
        missing_agents: list[AgentName],
        global_limitations: list[str],
        warnings: list[str],
    ) -> list[RootCauseHypothesis]:
        if not positive_findings:
            return []

        perf_findings = [f for f in positive_findings if f.agent_source == AgentName.PERFORMANCE]
        infra_findings = [f for f in positive_findings if f.agent_source == AgentName.INFRASTRUCTURE]
        conn_findings = [f for f in positive_findings if f.agent_source == AgentName.CONNECTIVITY]

        # Extract all devices and segments mentioned across positive findings
        candidate_devices: set[str] = set()
        candidate_segments: set[str] = set()

        for f in positive_findings:
            for d in f.affected_devices:
                candidate_devices.add(d)
            for s in f.affected_segments:
                candidate_segments.add(s)
            for ev in f.evidence:
                if ev.device_id:
                    candidate_devices.add(ev.device_id)
                if ev.segment_id:
                    candidate_segments.add(ev.segment_id)

        candidates: list[RootCauseHypothesis] = []
        covered_finding_ids: set[UUID] = set()

        # 1. Device-centric hypotheses (shared device, link/interface fault on device, or direct device fault)
        for dev_id in sorted(candidate_devices):
            dev_infra = [
                f for f in infra_findings
                if dev_id in f.affected_devices or any(ev.device_id == dev_id for ev in f.evidence)
            ]
            dev_conn = [
                f for f in conn_findings
                if dev_id in f.affected_devices or any(ev.device_id == dev_id for ev in f.evidence)
            ]

            # Determine all devices/segments topologically linked to dev_id via Connectivity findings
            topologically_linked_devices: set[str] = {dev_id}
            topologically_linked_segments: set[str] = set()
            for cf in dev_conn:
                topologically_linked_devices.update(cf.affected_devices)
                topologically_linked_segments.update(cf.affected_segments)
            for inf in dev_infra:
                topologically_linked_segments.update(inf.affected_segments)

            # Performance findings match dev_id if they directly reference dev_id, OR if dev_id has
            # an infrastructure/connectivity finding that scopes those devices/segments to dev_id.
            dev_perf: list[AgentFinding] = []
            for pf in perf_findings:
                pf_devs = set(pf.affected_devices) | {ev.device_id for ev in pf.evidence if ev.device_id}
                pf_segs = set(pf.affected_segments) | {ev.segment_id for ev in pf.evidence if ev.segment_id}
                direct_match = dev_id in pf_devs
                topo_match = bool(dev_conn or dev_infra) and (
                    bool(pf_devs & topologically_linked_devices)
                    or bool(pf_segs & topologically_linked_segments)
                )
                if direct_match or topo_match:
                    dev_perf.append(pf)

            # Only form a device candidate if dev_id has direct infra fault, or is a shared dependency,
            # or has direct performance degradation without a better upstream infra device
            is_shared_hub = any(cf.finding_code == "SHARED_TOPOLOGY_DEPENDENCY" and cf.affected_devices and cf.affected_devices[0] == dev_id for cf in dev_conn)
            has_link_or_path_fault = any(cf.finding_code in {"LINK_FAILURE_IMPACT_SCOPE", "PATH_INTERRUPTED"} for cf in dev_conn)

            if not dev_infra and not is_shared_hub and not has_link_or_path_fault:
                # If dev_id only appears as a leaf victim inside someone else's connectivity blast radius, skip creating a false root-cause on the victim unless it has direct perf findings and no infra findings exist anywhere
                direct_perf_only = [
                    pf for pf in dev_perf
                    if dev_id in pf.affected_devices or any(ev.device_id == dev_id for ev in pf.evidence)
                ]
                if not direct_perf_only:
                    continue

            related = _dedup_findings([*dev_infra, *dev_perf, *dev_conn])
            if not related:
                continue

            hyp = self._build_device_hypothesis(
                dev_id=dev_id,
                dev_infra=dev_infra,
                dev_perf=dev_perf,
                dev_conn=dev_conn,
                all_incident_findings=[*positive_findings, *negative_findings, *info_findings],
                info_findings=info_findings,
                negative_findings=negative_findings,
                healthy_completed_checks=healthy_completed_checks,
                missing_agents=missing_agents,
                global_limitations=global_limitations,
                warnings=warnings,
            )
            candidates.append(hyp)
            covered_finding_ids.update(hyp.supporting_finding_ids)

        # 2. Segment-centric hypotheses (when findings share a segment_id not already fully explained by a specific device infrastructure fault, or when multiple findings align on a segment)
        for seg_id in sorted(candidate_segments):
            seg_findings = [
                f for f in positive_findings
                if seg_id in f.affected_segments or any(ev.segment_id == seg_id for ev in f.evidence)
            ]
            if not seg_findings:
                continue

            # If a device hypothesis already covers all of these exact findings with an infrastructure fault, avoid duplicating an identical weaker hypothesis unless there are multiple findings on the segment
            already_covered = all(f.finding_id in covered_finding_ids for f in seg_findings)
            if already_covered and len(seg_findings) < 2:
                continue
            # Also if a device candidate already has the exact same supporting_finding_ids set, skip duplicate
            seg_fids = {f.finding_id for f in seg_findings}
            if any(set(c.supporting_finding_ids) == seg_fids for c in candidates):
                continue

            hyp = self._build_segment_hypothesis(
                seg_id=seg_id,
                seg_findings=seg_findings,
                all_incident_findings=[*positive_findings, *negative_findings, *info_findings],
                negative_findings=negative_findings,
                healthy_completed_checks=healthy_completed_checks,
                missing_agents=missing_agents,
                global_limitations=global_limitations,
                warnings=warnings,
            )
            candidates.append(hyp)
            covered_finding_ids.update(hyp.supporting_finding_ids)

        # 3. Unscoped / service-level performance findings (e.g. probe observations with no device_id or segment_id)
        unscoped_findings = [
            f for f in positive_findings if f.finding_id not in covered_finding_ids
        ]
        if unscoped_findings:
            hyp = self._build_unscoped_hypothesis(
                unscoped_findings=unscoped_findings,
                negative_findings=negative_findings,
                missing_agents=missing_agents,
                global_limitations=global_limitations,
            )
            candidates.append(hyp)

        # Sort candidates deterministically:
        # 1. Higher confidence
        # 2. More contributing specialist agents
        # 3. Higher severity rank
        # 4. Specificity tie-breaker (prefer direct device/interface failure over generic segment roll-up when tied)
        # 5. More independent telemetry records
        # 6. Candidate ID (alphabetical tie-breaker)
        candidates.sort(
            key=lambda c: (
                c.confidence,
                len(c.contributing_agents),
                SEVERITY_RANK.get(c.severity, 0),
                self._hypothesis_specificity_rank(c),
                len(c.independent_telemetry_keys),
                c.candidate_id,
            ),
            reverse=True,
        )

        # Filter out strictly dominated shadow candidates:
        # If candidate A has both Infra + Perf + Conn on the shared root cause device,
        # and candidate B is merely a single-domain leaf symptom whose findings are a strict subset of A's supporting_finding_ids,
        # retain B only if B has its own distinct infrastructure fault or link fault.
        filtered_candidates: list[RootCauseHypothesis] = []
        for cand in candidates:
            cand_fids = set(cand.supporting_finding_ids)
            cand_has_own_infra = any(
                f.agent_source == AgentName.INFRASTRUCTURE
                and (cand.focal_device_id in f.affected_devices if cand.focal_device_id else True)
                for f in cand.related_findings
            )
            is_strict_subset_of_stronger = any(
                cand_fids < set(stronger.supporting_finding_ids)
                and stronger.confidence > cand.confidence
                and not cand_has_own_infra
                for stronger in filtered_candidates
            )
            if not is_strict_subset_of_stronger:
                filtered_candidates.append(cand)

        return filtered_candidates

    @staticmethod
    def _hypothesis_specificity_rank(c: RootCauseHypothesis) -> int:
        """
        Tie-breaker rank used only when confidence, contributing agent count, and severity are equal.
        Prefers a specific device/interface fault over a generic segment roll-up when evidence
        directly identifies a failed device or interface, without overriding genuinely stronger
        shared-segment hypotheses.
        """
        if c.focal_device_id is not None:
            if c.finding_code == "PROBABLE_DEVICE_OUTAGE":
                return 3
            if c.finding_code in {
                "PROBABLE_INTERFACE_OR_LINK_FAULT",
                "PROBABLE_CONGESTION_OR_RESOURCE_CONTENTION",
                "PROBABLE_DEVICE_RESOURCE_EXHAUSTION",
                "PROBABLE_LINK_OR_PATH_INTERRUPTION",
            }:
                return 2
        return 0

    def _build_device_hypothesis(
        self,
        *,
        dev_id: str,
        dev_infra: list[AgentFinding],
        dev_perf: list[AgentFinding],
        dev_conn: list[AgentFinding],
        all_incident_findings: list[AgentFinding],
        info_findings: list[AgentFinding],
        negative_findings: list[AgentFinding],
        healthy_completed_checks: dict[AgentName, set[str]],
        missing_agents: list[AgentName],
        global_limitations: list[str],
        warnings: list[str],
    ) -> RootCauseHypothesis:
        # Include relevant informational findings (e.g. alternate physical link involving dev_id)
        dev_info = [
            f for f in info_findings
            if dev_id in f.affected_devices or any(ev.device_id == dev_id for ev in f.evidence)
        ]
        pos_cand = _dedup_findings([*dev_infra, *dev_perf, *dev_conn])
        related_findings = _dedup_findings([*pos_cand, *dev_info])
        supporting_finding_ids = [f.finding_id for f in related_findings]

        # Partition candidate findings into current vs stale vs missing-timestamp observations
        current_findings, stale_findings, missing_ts_findings, skew_sec, ref_time = (
            _partition_findings_by_freshness(
                cand_findings=pos_cand,
                all_incident_findings=all_incident_findings,
                max_skew_seconds=self.config["max_timestamp_skew_seconds"],
            )
        )
        current_ids = {f.finding_id for f in current_findings}
        stale_ids = {f.finding_id for f in stale_findings}
        missing_ts_ids = {f.finding_id for f in missing_ts_findings}
        has_mixed_explicit_and_missing = (
            bool(missing_ts_findings)
            and (len(current_findings) + len(stale_findings) < len(pos_cand))
        )

        if stale_findings:
            active_infra = [f for f in dev_infra if f.finding_id in current_ids]
            active_perf = [f for f in dev_perf if f.finding_id in current_ids]
            active_conn = [f for f in dev_conn if f.finding_id in current_ids]
        else:
            active_infra = list(dev_infra)
            active_perf = list(dev_perf)
            active_conn = list(dev_conn)

        stale_infra = [
            f
            for f in dev_infra
            if f.finding_id in stale_ids
        ]

        # Identify contradictions scoped to this device or its segments
        contradicting_findings = self._find_contradicting_findings(
            focal_device_id=dev_id,
            focal_segment_ids={s for f in related_findings for s in f.affected_segments},
            positive_findings=current_findings if current_findings else related_findings,
            negative_findings=negative_findings,
        )
        contradicting_ids = [cf.finding_id for cf in contradicting_findings]

        # Also check if Infrastructure Agent ran healthy checks on dev_id while Performance/Connectivity blames dev_id
        implicit_contradictions = 0
        infra_checks = healthy_completed_checks.get(AgentName.INFRASTRUCTURE, set())
        device_had_healthy_infra_checks = any(chk.endswith(f":{dev_id}") for chk in infra_checks)
        if not active_infra and not stale_infra and device_had_healthy_infra_checks and (active_perf or active_conn):
            implicit_contradictions += 1

        total_contradictions = len(contradicting_ids) + implicit_contradictions

        unique_evidence, indep_keys, dup_skipped = deduplicate_independent_evidence(related_findings)
        if dup_skipped > 0:
            warnings.append(
                f"Deduplicated {dup_skipped} duplicate evidence reference(s) on candidate '{dev_id}' to prevent double-counting."
            )

        if skew_sec > self.config["max_timestamp_skew_seconds"]:
            warnings.append(
                f"Evidence timestamps for candidate '{dev_id}' span {skew_sec:.0f}s "
                f"(exceeding max skew threshold of {self.config['max_timestamp_skew_seconds']:.0f}s)."
            )
        if missing_ts_findings:
            warnings.append(
                f"Candidate '{dev_id}' includes {len(missing_ts_findings)} finding(s) with missing source timestamps defaulted to utc_now(); temporal alignment is unverified."
            )

        active_pos = [*active_infra, *active_perf, *active_conn]
        _, aligned_indep_keys, _ = deduplicate_independent_evidence(active_pos)
        active_contributing_agents = {f.agent_source for f in active_pos}
        all_contributing_agents = {f.agent_source for f in pos_cand}

        conn_codes = {f.finding_code for f in active_conn}
        has_link_or_hub_scope = bool(
            conn_codes & {"LINK_FAILURE_IMPACT_SCOPE", "PATH_INTERRUPTED", "SHARED_TOPOLOGY_DEPENDENCY"}
        )

        affected_devices: list[str] = [dev_id]
        affected_segments: list[str] = []
        for f in (related_findings if (active_infra or has_link_or_hub_scope) else [*dev_perf, *dev_infra]):
            for d in f.affected_devices:
                if d not in affected_devices:
                    affected_devices.append(d)
        for f in related_findings:
            for s in f.affected_segments:
                if s not in affected_segments:
                    affected_segments.append(s)

        max_infra_sev = (
            max((f.severity for f in active_infra), key=lambda s: SEVERITY_RANK[s])
            if active_infra
            else None
        )
        overall_sev = max(
            (f.severity for f in (active_pos if active_pos else pos_cand)),
            key=lambda s: SEVERITY_RANK[s],
        )

        # Classify root cause code & description based on current/aligned evidence
        infra_codes = {f.finding_code for f in active_infra}
        conn_codes = {f.finding_code for f in active_conn}

        if "DEVICE_DOWN" in infra_codes:
            code = "PROBABLE_DEVICE_OUTAGE"
            title = f"Probable device outage on {dev_id} impacting connected paths/segments."
        elif "HIGH_EGRESS_QUEUE_DROPS" in infra_codes or "HIGH_QUEUE_DROPS" in infra_codes:
            code = "PROBABLE_CONGESTION_OR_RESOURCE_CONTENTION"
            title = f"Probable congestion and egress queue drops on {dev_id}."
        elif "HIGH_INTERFACE_ERRORS" in infra_codes or "HIGH_INTERFACE_DISCARDS" in infra_codes or "INTERFACE_DOWN" in infra_codes:
            code = "PROBABLE_INTERFACE_OR_LINK_FAULT"
            title = f"Probable interface or physical link fault on {dev_id}."
        elif "HIGH_CPU_UTILIZATION" in infra_codes or "HIGH_MEMORY_UTILIZATION" in infra_codes:
            code = "PROBABLE_DEVICE_RESOURCE_EXHAUSTION"
            title = f"Probable control/forwarding resource exhaustion on {dev_id}."
        elif "LINK_FAILURE_IMPACT_SCOPE" in conn_codes or "PATH_INTERRUPTED" in conn_codes:
            code = "PROBABLE_LINK_OR_PATH_INTERRUPTION"
            title = f"Probable link or path interruption involving {dev_id}."
        elif "SHARED_TOPOLOGY_DEPENDENCY" in conn_codes and not active_perf:
            code = "UNVERIFIED_SHARED_DEPENDENCY_HYPOTHESIS"
            title = f"Unverified shared topological dependency hypothesis on {dev_id}."
        elif "SHARED_TOPOLOGY_DEPENDENCY" in conn_codes and not stale_infra:
            code = "UNVERIFIED_SHARED_DEPENDENCY_HYPOTHESIS"
            title = f"Unverified shared topological dependency hypothesis on {dev_id}."
        elif active_perf:
            code = "LOCALIZED_PERFORMANCE_DEGRADATION"
            title = (
                f"Performance degradation observed on {dev_id} without confirmed current infrastructure fault."
                if stale_infra
                else f"Performance degradation observed on {dev_id} without confirmed infrastructure fault."
            )
        elif stale_findings or (has_mixed_explicit_and_missing and missing_ts_findings):
            code = "UNVERIFIED_STALE_INFRASTRUCTURE_OBSERVATION"
            title = f"Stale or temporally unverified infrastructure observation on {dev_id} requiring fresh telemetry."
        else:
            code = "LOCALIZED_PERFORMANCE_DEGRADATION"
            title = f"Performance degradation observed on {dev_id} without confirmed infrastructure fault."

        missing_ev: list[str] = []
        if not active_infra:
            if stale_infra:
                missing_ev.append(
                    f"Fresh, contemporaneous CPU/infrastructure telemetry for '{dev_id}' (existing infrastructure observation is stale or temporally mismatched by {skew_sec:.0f}s)."
                )
            elif device_had_healthy_infra_checks:
                missing_ev.append(
                    f"Infrastructure telemetry on '{dev_id}' was checked and reported normal; no local CPU/memory/counter fault confirmed on '{dev_id}'."
                )
            else:
                missing_ev.append(
                    f"Missing infrastructure health telemetry (CPU, memory, interface counters) for '{dev_id}'."
                )
        if not active_perf:
            missing_ev.append(
                f"No current end-to-end performance degradation telemetry (latency, packet loss, jitter) linked to '{dev_id}'."
            )
        if not active_conn:
            missing_ev.append(
                f"No topology connectivity scope findings confirming downstream dependencies for '{dev_id}'."
            )
        if missing_ts_findings:
            missing_ev.append(
                f"Explicit source observation timestamp(s) for {len(missing_ts_findings)} finding(s) on '{dev_id}' that defaulted to utc_now()."
            )

        confidence, score_explanation = score_hypothesis_confidence(
            contributing_agents=active_contributing_agents,
            independent_evidence_count=len(aligned_indep_keys),
            has_direct_infra_fault=bool(active_infra),
            has_perf_degradation=bool(active_perf),
            has_connectivity_link=bool(active_conn),
            has_shared_segment=bool(affected_segments) and bool(active_pos),
            max_infra_severity=max_infra_sev,
            contradiction_count=total_contradictions,
            timestamp_skew_seconds=skew_sec,
            missing_agents_count=len(missing_agents),
            config=self.config,
        )

        if not active_pos:
            confidence = min(confidence, 0.35)
            score_explanation = f"{score_explanation}; capped at 0.35 (only stale/temporally unverified evidence)"

        if has_mixed_explicit_and_missing:
            confidence = round(max(0.05, confidence - 0.12), 4)
            score_explanation = f"{score_explanation}; mixed explicit and missing/defaulted timestamps (-0.12)"
            if code == "PROBABLE_DEVICE_RESOURCE_EXHAUSTION":
                confidence = min(confidence, 0.65)
                score_explanation = f"{score_explanation}; capped at 0.65 due to unverified timestamp alignment on resource exhaustion hypothesis"

        limitations = list(global_limitations)
        if skew_sec > self.config["max_timestamp_skew_seconds"]:
            limitations.append(
                f"Evidence timestamps across findings differ by {skew_sec:.0f}s (exceeding {self.config['max_timestamp_skew_seconds']:.0f}s max skew), weakening temporal correlation certainty."
            )
        if stale_infra:
            limitations.append(
                f"Stale infrastructure telemetry on '{dev_id}' ({[f.finding_code for f in stale_infra]}) differs from current incident observations by {skew_sec:.0f}s and cannot establish a current resource-exhaustion fault without collecting fresh CPU/infrastructure telemetry."
            )
        if missing_ts_findings:
            limitations.append(
                f"Temporal uncertainty: {len(missing_ts_findings)} observation(s) on '{dev_id}' omitted an explicit source timestamp and defaulted to ingestion time (utc_now); actual observation time is unverified."
            )
        if contradicting_findings or implicit_contradictions > 0:
            limitations.append(
                f"Hypothesis has {total_contradictions} contradicting or healthy counter-observation(s) on '{dev_id}'."
            )
        for info_f in dev_info:
            for lim in info_f.limitations:
                if lim not in limitations:
                    limitations.append(lim)

        stale_desc_note = (
            f" Historical infrastructure finding(s) {[f.finding_code for f in stale_infra]} were recorded {skew_sec:.0f}s "
            f"before current incident telemetry (exceeding max skew {self.config['max_timestamp_skew_seconds']:.0f}s) "
            f"and are preserved as historical context only; collect fresh CPU/infrastructure telemetry before confirming current resource exhaustion."
            if stale_infra
            else ""
        )
        missing_ts_desc_note = (
            f" Note: {len(missing_ts_findings)} finding(s) omitted an explicit source timestamp and defaulted to utc_now()."
            if missing_ts_findings
            else ""
        )

        description = (
            f"Correlated hypothesis centered on device '{dev_id}' supported by "
            f"{len(related_findings)} finding(s) across {[a.value for a in sorted(all_contributing_agents, key=lambda x: x.value)]} "
            f"and {len(aligned_indep_keys)} temporally aligned independent telemetry observation(s) "
            f"({len(indep_keys)} total including historical context). "
            f"Affected devices: {affected_devices}; affected segments: {affected_segments or ['none']}.{stale_desc_note}{missing_ts_desc_note}"
        )

        return RootCauseHypothesis(
            candidate_id=f"device:{dev_id}:{code.lower()}",
            finding_code=code,
            title=title,
            description=description,
            severity=overall_sev,
            focal_device_id=dev_id,
            affected_devices=affected_devices,
            affected_segments=affected_segments,
            related_findings=related_findings,
            supporting_finding_ids=supporting_finding_ids,
            contradicting_finding_ids=contradicting_ids,
            supporting_evidence_ids=[ev.evidence_id for ev in unique_evidence],
            supporting_evidence=unique_evidence,
            contributing_agents=sorted(active_contributing_agents, key=lambda a: a.value),
            independent_telemetry_keys=aligned_indep_keys,
            missing_evidence=missing_ev,
            limitations=list(dict.fromkeys(limitations)),
            timestamp_skew_seconds=skew_sec,
            reference_timestamp=ref_time,
            confidence=confidence,
            score_explanation=score_explanation,
        )

    def _build_segment_hypothesis(
        self,
        *,
        seg_id: str,
        seg_findings: list[AgentFinding],
        all_incident_findings: list[AgentFinding],
        negative_findings: list[AgentFinding],
        healthy_completed_checks: dict[AgentName, set[str]],
        missing_agents: list[AgentName],
        global_limitations: list[str],
        warnings: list[str],
    ) -> RootCauseHypothesis:
        current_findings, stale_findings, missing_ts_findings, skew_sec, ref_time = (
            _partition_findings_by_freshness(
                cand_findings=seg_findings,
                all_incident_findings=all_incident_findings,
                max_skew_seconds=self.config["max_timestamp_skew_seconds"],
            )
        )
        current_ids = {f.finding_id for f in current_findings}
        has_mixed_explicit_and_missing = (
            bool(missing_ts_findings)
            and (len(current_findings) + len(stale_findings) < len(seg_findings))
        )

        if stale_findings:
            active_seg = [f for f in seg_findings if f.finding_id in current_ids]
        else:
            active_seg = list(seg_findings)

        seg_infra = [f for f in active_seg if f.agent_source == AgentName.INFRASTRUCTURE]
        seg_perf = [f for f in active_seg if f.agent_source == AgentName.PERFORMANCE]
        seg_conn = [f for f in active_seg if f.agent_source == AgentName.CONNECTIVITY]
        stale_seg_infra = [
            f for f in seg_findings
            if f.agent_source == AgentName.INFRASTRUCTURE and f not in seg_infra
        ]

        contradicting_findings = self._find_contradicting_findings(
            focal_device_id=None,
            focal_segment_ids={seg_id},
            positive_findings=current_findings if current_findings else seg_findings,
            negative_findings=negative_findings,
        )
        contradicting_ids = [cf.finding_id for cf in contradicting_findings]

        unique_evidence, indep_keys, dup_skipped = deduplicate_independent_evidence(seg_findings)
        _, aligned_indep_keys, _ = deduplicate_independent_evidence(active_seg)
        if dup_skipped > 0:
            warnings.append(
                f"Deduplicated {dup_skipped} duplicate evidence reference(s) on segment '{seg_id}'."
            )

        if skew_sec > self.config["max_timestamp_skew_seconds"]:
            warnings.append(
                f"Evidence timestamps on segment '{seg_id}' span {skew_sec:.0f}s."
            )

        contributing_agents = {f.agent_source for f in active_seg}
        affected_devices: list[str] = []
        for f in seg_findings:
            for d in f.affected_devices:
                if d not in affected_devices:
                    affected_devices.append(d)

        max_infra_sev = (
            max((f.severity for f in seg_infra), key=lambda s: SEVERITY_RANK[s])
            if seg_infra
            else None
        )
        overall_sev = max(
            (f.severity for f in (active_seg if active_seg else seg_findings)),
            key=lambda s: SEVERITY_RANK[s],
        )

        if seg_infra and seg_perf:
            code = "SHARED_SEGMENT_INFRASTRUCTURE_DEGRADATION"
            title = f"Shared segment {seg_id} degradation correlated with device infrastructure fault."
        else:
            code = "SHARED_SEGMENT_DEGRADATION"
            title = f"Shared network segment {seg_id} anomaly across {len(seg_findings)} finding(s)."

        missing_ev: list[str] = []
        if not seg_infra:
            if stale_seg_infra:
                missing_ev.append(
                    f"Fresh device-level infrastructure telemetry in segment '{seg_id}' (existing infrastructure observation is stale by {skew_sec:.0f}s)."
                )
            else:
                missing_ev.append(
                    f"No device-level infrastructure fault (CPU, memory, interface errors, queue drops) confirmed in segment '{seg_id}'."
                )
        if not seg_conn:
            missing_ev.append(
                f"No topological link/switch mapping confirming the physical point of attachment for segment '{seg_id}'."
            )

        confidence, score_explanation = score_hypothesis_confidence(
            contributing_agents=contributing_agents,
            independent_evidence_count=len(aligned_indep_keys),
            has_direct_infra_fault=bool(seg_infra),
            has_perf_degradation=bool(seg_perf),
            has_connectivity_link=bool(seg_conn),
            has_shared_segment=bool(active_seg),
            max_infra_severity=max_infra_sev,
            contradiction_count=len(contradicting_ids),
            timestamp_skew_seconds=skew_sec,
            missing_agents_count=len(missing_agents),
            config=self.config,
        )

        if not active_seg:
            confidence = min(confidence, 0.35)
        if has_mixed_explicit_and_missing:
            confidence = round(max(0.05, confidence - 0.12), 4)
            score_explanation = f"{score_explanation}; mixed explicit and missing/defaulted timestamps (-0.12)"

        limitations = list(global_limitations)
        if skew_sec > self.config["max_timestamp_skew_seconds"]:
            limitations.append(
                f"Evidence timestamps in segment '{seg_id}' differ by {skew_sec:.0f}s."
            )
        if stale_seg_infra:
            limitations.append(
                f"Stale infrastructure telemetry in segment '{seg_id}' differs from current observations by {skew_sec:.0f}s; collect fresh telemetry before confirming current resource exhaustion."
            )
        if missing_ts_findings:
            limitations.append(
                f"Temporal uncertainty: {len(missing_ts_findings)} observation(s) in segment '{seg_id}' omitted an explicit source timestamp and defaulted to utc_now()."
            )

        return RootCauseHypothesis(
            candidate_id=f"segment:{seg_id}:{code.lower()}",
            finding_code=code,
            title=title,
            description=(
                f"Multiple findings align on network segment '{seg_id}' across "
                f"{[a.value for a in sorted(contributing_agents, key=lambda x: x.value)]}. "
                f"Affected devices in segment: {affected_devices or ['unspecified']}."
            ),
            severity=overall_sev,
            focal_segment_id=seg_id,
            affected_devices=affected_devices,
            affected_segments=[seg_id],
            related_findings=seg_findings,
            supporting_finding_ids=[f.finding_id for f in seg_findings],
            contradicting_finding_ids=contradicting_ids,
            supporting_evidence_ids=[ev.evidence_id for ev in unique_evidence],
            supporting_evidence=unique_evidence,
            contributing_agents=sorted(contributing_agents, key=lambda a: a.value),
            independent_telemetry_keys=aligned_indep_keys,
            missing_evidence=missing_ev,
            limitations=list(dict.fromkeys(limitations)),
            timestamp_skew_seconds=skew_sec,
            reference_timestamp=ref_time,
            confidence=confidence,
            score_explanation=score_explanation,
        )

    def _build_unscoped_hypothesis(
        self,
        *,
        unscoped_findings: list[AgentFinding],
        negative_findings: list[AgentFinding],
        missing_agents: list[AgentName],
        global_limitations: list[str],
    ) -> RootCauseHypothesis:
        unique_evidence, indep_keys, _ = deduplicate_independent_evidence(unscoped_findings)
        skew_sec = compute_timestamp_skew_seconds(unscoped_findings)
        contributing_agents = {f.agent_source for f in unscoped_findings}
        overall_sev = max((f.severity for f in unscoped_findings), key=lambda s: SEVERITY_RANK[s])

        confidence, score_explanation = score_hypothesis_confidence(
            contributing_agents=contributing_agents,
            independent_evidence_count=len(indep_keys),
            has_direct_infra_fault=any(f.agent_source == AgentName.INFRASTRUCTURE for f in unscoped_findings),
            has_perf_degradation=any(f.agent_source == AgentName.PERFORMANCE for f in unscoped_findings),
            has_connectivity_link=False,
            has_shared_segment=False,
            max_infra_severity=None,
            contradiction_count=0,
            timestamp_skew_seconds=skew_sec,
            missing_agents_count=len(missing_agents),
            config=self.config,
        )
        # Cap unscoped symptoms without device or segment identifiers so they stay inconclusive/low-confidence
        confidence = min(confidence, 0.35)

        return RootCauseHypothesis(
            candidate_id="unscoped:unattributed_symptom",
            finding_code="UNSCOPED_SYMPTOM_HYPOTHESIS",
            title="Unscoped symptom detected without device or segment attribution.",
            description=(
                "Anomalous observations were reported without device_id or segment_id scope, "
                "preventing topological or infrastructure root-cause isolation."
            ),
            severity=overall_sev,
            affected_devices=[],
            affected_segments=[],
            related_findings=unscoped_findings,
            supporting_finding_ids=[f.finding_id for f in unscoped_findings],
            contradicting_finding_ids=[],
            supporting_evidence_ids=[ev.evidence_id for ev in unique_evidence],
            supporting_evidence=unique_evidence,
            contributing_agents=sorted(contributing_agents, key=lambda a: a.value),
            independent_telemetry_keys=indep_keys,
            missing_evidence=[
                "Missing device_id and segment_id attribution on reported telemetry.",
                "Missing infrastructure and topology correlation anchors.",
            ],
            limitations=[
                *global_limitations,
                "Cannot isolate a specific network device or link without topological scope.",
            ],
            timestamp_skew_seconds=skew_sec,
            confidence=confidence,
            score_explanation=f"{score_explanation}; capped at 0.35 due to missing device/segment scope",
        )

    def _find_contradicting_findings(
        self,
        *,
        focal_device_id: Optional[str],
        focal_segment_ids: set[str],
        positive_findings: list[AgentFinding],
        negative_findings: list[AgentFinding],
    ) -> list[AgentFinding]:
        """
        Finds upstream findings that contradict a candidate hypothesis on the same
        device/segment and within the active time window.
        """
        contradictions: list[AgentFinding] = []
        pos_timestamps = [ensure_utc_timestamp(f.timestamp) for f in positive_findings]
        ref_time = max(pos_timestamps) if pos_timestamps else utc_now()

        for nf in negative_findings:
            nf_devs = set(nf.affected_devices) | {ev.device_id for ev in nf.evidence if ev.device_id}
            nf_segs = set(nf.affected_segments) | {ev.segment_id for ev in nf.evidence if ev.segment_id}

            same_device = focal_device_id is not None and focal_device_id in nf_devs
            same_segment = bool(focal_segment_ids and (focal_segment_ids & nf_segs))
            if not same_device and not same_segment:
                continue

            # Only count as a contradiction if within the relevant time window
            time_diff = abs((ensure_utc_timestamp(nf.timestamp) - ref_time).total_seconds())
            if time_diff <= self.config["max_timestamp_skew_seconds"]:
                contradictions.append(nf)

        return contradictions

    def _determine_diagnosis_status(
        self,
        *,
        hypotheses: list[RootCauseHypothesis],
        usable_agents: set[AgentName],
        missing_agents: list[AgentName],
    ) -> DiagnosisStatus:
        """
        Determines whether the correlation outcome is IDENTIFIED, PARTIAL_HYPOTHESIS, or INCONCLUSIVE.
        """
        if not hypotheses:
            return DiagnosisStatus.INCONCLUSIVE

        top = hypotheses[0]
        if top.confidence < self.config["partial_hypothesis_min_confidence"]:
            return DiagnosisStatus.INCONCLUSIVE

        has_infra_support = AgentName.INFRASTRUCTURE in top.contributing_agents
        has_multi_agent = len(top.contributing_agents) >= 2
        has_no_contradictions = len(top.contradicting_finding_ids) == 0
        skew_ok = top.timestamp_skew_seconds <= self.config["max_timestamp_skew_seconds"]

        # Avoid claiming IDENTIFIED if two competing unrelated hypotheses are nearly tied
        nearly_tied_competitor = (
            len(hypotheses) >= 2
            and (top.confidence - hypotheses[1].confidence) < 0.08
            and hypotheses[1].focal_device_id != top.focal_device_id
            and not (
                set(top.supporting_finding_ids)
                & set(hypotheses[1].supporting_finding_ids)
            )
            and not (
                set(top.affected_devices)
                & set(hypotheses[1].affected_devices)
            )
        )

        if (
            top.confidence >= self.config["identified_min_confidence"]
            and has_infra_support
            and has_multi_agent
            and has_no_contradictions
            and skew_ok
            and not nearly_tied_competitor
        ):
            return DiagnosisStatus.IDENTIFIED

        return DiagnosisStatus.PARTIAL_HYPOTHESIS

    def build_diagnostic_report(
        self,
        correlation_response: AgentResponse,
        upstream_responses: Sequence[AgentResponse],
        *,
        incident_id: UUID,
        run_id: UUID,
    ) -> DiagnosticReport:
        """
        Helper that packages the correlation findings and all upstream supporting findings
        into a validated `DiagnosticReport` satisfying all `common.py` cross-reference invariants.
        """
        supporting_findings: list[AgentFinding] = []
        seen_fids: set[UUID] = set()
        for resp in upstream_responses:
            if resp.status == ExecutionStatus.FAILED:
                continue
            for f in resp.findings:
                if f.finding_id not in seen_fids:
                    seen_fids.add(f.finding_id)
                    supporting_findings.append(f)

        meta = correlation_response.execution_metadata
        raw_diag_status = meta.get("diagnosis_status", DiagnosisStatus.INCONCLUSIVE.value)
        diagnosis_status = DiagnosisStatus(raw_diag_status)

        if diagnosis_status == DiagnosisStatus.INCONCLUSIVE or not correlation_response.findings:
            root_causes: list[AgentFinding] = []
            diagnosis_status = DiagnosisStatus.INCONCLUSIVE
            overall_conf = float(meta.get("overall_confidence", 0.2))
            overall_sev = (
                max((f.severity for f in supporting_findings), key=lambda s: SEVERITY_RANK[s])
                if supporting_findings
                else Severity.INFO
            )
            exec_summary = (
                "Available cross-agent telemetry is insufficient or too contradictory to isolate "
                "a verified root cause."
            )
        else:
            root_causes = list(correlation_response.findings)
            overall_conf = root_causes[0].confidence
            overall_sev = max((f.severity for f in root_causes), key=lambda s: SEVERITY_RANK[s])
            top_rc = root_causes[0]
            exec_summary = (
                f"Diagnosis status: {diagnosis_status.value}. Top hypothesis: {top_rc.summary} "
                f"(confidence={top_rc.confidence:.2f}, severity={top_rc.severity.value})."
            )

        limitations = list(meta.get("limitations_and_uncertainties", []))
        for rc in root_causes:
            for lim in rc.limitations:
                if lim not in limitations:
                    limitations.append(lim)
        if diagnosis_status in (DiagnosisStatus.PARTIAL_HYPOTHESIS, DiagnosisStatus.INCONCLUSIVE) and not limitations:
            limitations.append(
                "Key corroborating telemetry or control-plane verification remains incomplete."
            )

        return DiagnosticReport(
            incident_id=incident_id,
            run_id=run_id,
            diagnosis_status=diagnosis_status,
            overall_severity=overall_sev,
            overall_confidence=overall_conf,
            executive_summary=exec_summary,
            root_causes=root_causes,
            supporting_findings=supporting_findings,
            recommendations=[],
            limitations_and_uncertainties=limitations,
        )


def correlate_findings(
    upstream_input: Union[
        Sequence[Union[AgentResponse, AgentMessage, Mapping[str, Any]]],
        Mapping[str, Any],
    ],
    *,
    incident_id: Optional[UUID] = None,
    run_id: Optional[UUID] = None,
    config: Optional[Mapping[str, float]] = None,
) -> AgentResponse:
    """Convenience entry point for orchestrator and tests to run the Fault Correlation Agent."""
    return CorrelationAgent(config=config).analyze(
        upstream_input,
        incident_id=incident_id,
        run_id=run_id,
    )


run_correlation_analysis = correlate_findings
