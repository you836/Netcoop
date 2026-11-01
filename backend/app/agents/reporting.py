"""Deterministic recommendation synthesis and diagnostic report generation for NetCoop AI (Agent 5)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from time import perf_counter
from typing import Any, Optional, Union
from uuid import UUID

from pydantic import ValidationError

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
    Recommendation,
    Severity,
)

# =====================================================================
# 1. CONSTANTS & SEVERITY ORDERING
# =====================================================================

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

CPU_FINDING_CODES: frozenset[str] = frozenset(
    {
        "HIGH_CPU_UTILIZATION",
        "PROBABLE_DEVICE_RESOURCE_EXHAUSTION",
    }
)

MEMORY_FINDING_CODES: frozenset[str] = frozenset(
    {
        "HIGH_MEMORY_UTILIZATION",
    }
)

INTERFACE_ERROR_FINDING_CODES: frozenset[str] = frozenset(
    {
        "HIGH_INTERFACE_ERRORS",
        "HIGH_INTERFACE_DISCARDS",
        "INTERFACE_DOWN",
        "INTERFACE_DEGRADED",
        "PROBABLE_INTERFACE_OR_LINK_FAULT",
    }
)

QUEUE_DROP_FINDING_CODES: frozenset[str] = frozenset(
    {
        "HIGH_EGRESS_QUEUE_DROPS",
        "HIGH_QUEUE_DROPS",
        "PROBABLE_CONGESTION_OR_RESOURCE_CONTENTION",
        "PROBABLE_CONGESTION",
    }
)

DEVICE_DOWN_FINDING_CODES: frozenset[str] = frozenset(
    {
        "DEVICE_DOWN",
        "DEVICE_DEGRADED",
        "PROBABLE_DEVICE_OUTAGE",
    }
)

PERFORMANCE_FINDING_CODES: frozenset[str] = frozenset(
    {
        "HIGH_LATENCY",
        "HIGH_LATENCY_MS",
        "HIGH_PACKET_LOSS",
        "HIGH_PACKET_LOSS_RATE",
        "HIGH_JITTER",
        "HIGH_JITTER_MS",
        "HIGH_BANDWIDTH_UTILIZATION",
        "LOW_THROUGHPUT",
        "LOCALIZED_PERFORMANCE_DEGRADATION",
        "SHARED_SEGMENT_DEGRADATION",
        "SHARED_SEGMENT_INFRASTRUCTURE_DEGRADATION",
    }
)

TOPOLOGY_UNCERTAINTY_FINDING_CODES: frozenset[str] = frozenset(
    {
        "ALTERNATE_PHYSICAL_PATH_IDENTIFIED",
        "REDUNDANT_PHYSICAL_LINK",
        "CONTRADICTORY_TOPOLOGY_LINK",
        "LINK_FAILURE_IMPACT_SCOPE",
        "DEVICE_FAILURE_IMPACT_SCOPE",
        "SHARED_TOPOLOGY_DEPENDENCY",
        "PATH_INTERRUPTED",
        "PROBABLE_LINK_OR_PATH_INTERRUPTION",
        "UNVERIFIED_SHARED_DEPENDENCY_HYPOTHESIS",
    }
)


# =====================================================================
# 2. DETERMINISTIC RECOMMENDATION RULES
# =====================================================================


def build_recommendation_for_domain(
    *,
    domain_key: str,
    related_findings: Sequence[AgentFinding],
    available_evidence_ids: set[UUID],
    has_unverified_backup_path: bool,
    has_stale_telemetry: bool = False,
) -> Optional[Recommendation]:
    """
    Generates a single safe, advisory, evidence-backed `Recommendation` for a specific
    diagnostic domain (`cpu`, `memory`, `interface_errors`, `queue_drops`, `device_down`,
    `performance`, or `topology`).

    Never generates recommendations without valid `related_finding_ids` and
    `supporting_evidence_ids` present in the report.
    Never recommends unconditional traffic shifting or failover to an unverified path.
    """
    if not related_findings:
        return None

    finding_ids = [f.finding_id for f in related_findings]
    evidence_ids: list[UUID] = []
    target_devices: list[str] = []
    target_interfaces: list[str] = []
    target_segments: list[str] = []

    for f in related_findings:
        for d in f.affected_devices:
            if d not in target_devices:
                target_devices.append(d)
        for s in f.affected_segments:
            if s not in target_segments:
                target_segments.append(s)
        for ev in f.evidence:
            if ev.evidence_id in available_evidence_ids and ev.evidence_id not in evidence_ids:
                evidence_ids.append(ev.evidence_id)
            if ev.device_id and ev.device_id not in target_devices:
                target_devices.append(ev.device_id)
            if ev.interface_id and ev.interface_id not in target_interfaces:
                target_interfaces.append(ev.interface_id)
            if ev.segment_id and ev.segment_id not in target_segments:
                target_segments.append(ev.segment_id)

    if not evidence_ids:
        return None

    max_sev = max((f.severity for f in related_findings), key=lambda s: SEVERITY_RANK[s])
    priority = (
        Severity.HIGH
        if max_sev in (Severity.CRITICAL, Severity.HIGH)
        else Severity.MEDIUM
        if max_sev == Severity.MEDIUM
        else Severity.LOW
    )

    dev_label = ", ".join(target_devices) if target_devices else "affected device(s)"
    iface_label = f" (interface(s): {', '.join(target_interfaces)})" if target_interfaces else ""
    seg_label = f" across segment(s) {', '.join(target_segments)}" if target_segments else ""
    backup_caveat = (
        " Do not shift traffic to any alternate physical link until STP forwarding, VLAN trunking, and routing readiness are independently verified."
        if has_unverified_backup_path
        else ""
    )

    if domain_key == "device_down":
        return Recommendation(
            priority=priority,
            title=f"Verify power, management reachability, and upstream links for {dev_label}",
            action=(
                f"Advisory investigation: Verify out-of-band management reachability, power supply status, "
                f"and upstream physical link states for {dev_label}{seg_label}. Check change-management "
                f"logs for recent maintenance windows or reloads before attempting any failover.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Check out-of-band console or management reachability to {dev_label}.",
                "Verify physical power and optical/copper link-light status on adjacent switches/routers.",
                "Confirm whether a scheduled maintenance window or reload occurred recently.",
                "After reachability is restored, verify interface status and routing/STP convergence.",
            ],
            rationale=(
                f"Telemetry reported non-operational device status on {dev_label}; operator verification "
                f"is required to distinguish power/hardware failure from management-plane isolation."
            ),
        )

    if domain_key == "queue_drops":
        return Recommendation(
            priority=priority,
            title=f"Inspect egress queue utilization and QoS congestion on {dev_label}",
            action=(
                f"Advisory investigation: Inspect outbound queue counters, buffer allocation, and QoS class-map "
                f"drop rates on {dev_label}{iface_label}{seg_label}. Identify top traffic flows or microbursts "
                f"contributing to egress congestion before modifying any QoS policies or shifting traffic.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Compare egress queue drop counter deltas on {dev_label}{iface_label} across consecutive polling intervals.",
                "Inspect per-queue/QoS class utilization and active traffic rates on the egress interface.",
                "Verify standby/alternate path STP state, trunk configuration, and available capacity before considering any traffic engineering.",
                "Post-check: Confirm queue drop rate returns to baseline and downstream latency/loss stabilizes.",
            ],
            rationale=(
                f"Elevated outbound queue drops on {dev_label}{iface_label} indicate egress buffer contention; "
                f"flow-level verification is needed to confirm the traffic trigger prior to remediation."
            ),
        )

    if domain_key == "cpu":
        if has_stale_telemetry:
            return Recommendation(
                priority=priority,
                title=f"Collect fresh CPU and infrastructure telemetry to verify current load on {dev_label}",
                action=(
                    f"Advisory investigation: Available CPU telemetry on {dev_label}{seg_label} is stale or temporally "
                    f"mismatched with current incident observations. Collect fresh CPU utilization, memory, and interface "
                    f"counter telemetry before confirming current resource exhaustion, then review active CPU process "
                    f"utilization and control-plane policing (CoPP) counters if current load remains elevated.{backup_caveat}"
                ),
                target_devices=target_devices,
                related_finding_ids=finding_ids,
                supporting_evidence_ids=evidence_ids,
                requires_verification=True,
                verification_steps=[
                    f"Collect fresh, contemporaneous CPU and infrastructure telemetry from {dev_label} aligned with the active incident window before confirming resource exhaustion.",
                    f"Inspect top CPU-consuming processes on {dev_label} using read-only diagnostic commands if fresh telemetry confirms elevated CPU.",
                    "Verify whether CPU utilization remains elevated across consecutive 1-minute and 5-minute windows.",
                    "Check control-plane punt counters and routing protocol churn logs.",
                ],
                rationale=(
                    f"Previously recorded CPU utilization on {dev_label} is stale relative to current incident telemetry; "
                    f"fresh CPU and infrastructure measurements are required before confirming active resource exhaustion."
                ),
            )
        return Recommendation(
            priority=priority,
            title=f"Inspect CPU-intensive processes and control-plane load on {dev_label}",
            action=(
                f"Advisory investigation: Review active CPU process utilization, control-plane policing (CoPP) "
                f"counters, and punted traffic on {dev_label}{seg_label}. Do not restart processes or shift "
                f"traffic without first confirming which process is consuming CPU cycles.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Inspect top CPU-consuming processes on {dev_label} using read-only diagnostic commands.",
                "Verify whether CPU utilization remains elevated across consecutive 1-minute and 5-minute windows.",
                "Check control-plane punt counters and routing protocol churn logs.",
                "Post-check: Confirm CPU utilization drops below warning thresholds after addressing the verified trigger.",
            ],
            rationale=(
                f"CPU utilization on {dev_label} exceeded configured thresholds; aggregate CPU telemetry "
                f"requires process-level inspection to determine the exact control- or data-plane cause."
            ),
        )

    if domain_key == "memory":
        return Recommendation(
            priority=priority,
            title=f"Inspect memory allocation and table growth on {dev_label}",
            action=(
                f"Advisory investigation: Inspect per-process memory allocation, RIB/FIB table sizes, and buffer "
                f"pools on {dev_label}{seg_label}. Verify whether memory usage is steadily growing (leak) or "
                f"driven by routing/MAC table scale before taking corrective action."
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Check free memory and largest process memory holders on {dev_label}.",
                "Compare current memory utilization against historical baselines to check for continuous growth.",
                "Post-check: Verify available memory stabilizes within normal operational bounds.",
            ],
            rationale=(
                f"Memory utilization on {dev_label} exceeded threshold limits; operator inspection is needed "
                f"to distinguish software memory leaks from legitimate table growth."
            ),
        )

    if domain_key == "interface_errors":
        return Recommendation(
            priority=priority,
            title=f"Inspect interface error/discard counters and physical media on {dev_label}",
            action=(
                f"Advisory investigation: Inspect physical layer diagnostics (CRC/framing errors, optical DOM/transceiver "
                f"power levels, cabling, and duplex settings) on {dev_label}{iface_label}{seg_label}. Compare counter "
                f"deltas over a known time window to confirm whether errors are actively accumulating.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Sample interface error and discard counters on {dev_label}{iface_label} over two consecutive intervals to verify active increments.",
                "Check transceiver optical light levels (Rx/Tx dBm) or cable integrity on both ends of the link.",
                "If an alternate link exists, verify its STP/routing forwarding readiness before scheduling media maintenance.",
                "Post-check: Verify error counter deltas remain zero over a post-check window.",
            ],
            rationale=(
                f"Interface error or discard observations on {dev_label}{iface_label} point to potential physical "
                f"media degradation, transceiver issues, or framing mismatches requiring read-only verification."
            ),
        )

    if domain_key == "performance":
        return Recommendation(
            priority=priority,
            title=f"Recheck latency, packet loss, jitter, and throughput{seg_label}",
            action=(
                f"Advisory investigation: Re-verify end-to-end latency, packet loss, jitter, and throughput "
                f"measurements for {dev_label}{seg_label}. Compare probe measurements across adjacent segments "
                f"and correlate with interface counter deltas before making routing or QoS adjustments."
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Run non-intrusive probe checks across {dev_label}{seg_label} to confirm whether degradation persists.",
                "Compare path performance metrics against upstream device CPU and interface queue counters.",
                "Post-check: Verify RTT, jitter, and packet loss return below SLA thresholds.",
            ],
            rationale=(
                f"Performance telemetry exceeded baseline thresholds for {dev_label}{seg_label}; "
                f"corroborating path and device measurements are required to confirm ongoing impact."
            ),
        )

    if domain_key == "topology":
        return Recommendation(
            priority=Severity.LOW if max_sev == Severity.INFO else priority,
            title=f"Verify physical link state, STP forwarding, and routing readiness on {dev_label}",
            action=(
                f"Advisory investigation: Verify LLDP/CDP neighbor adjacency, Spanning Tree Protocol (STP) port "
                f"forwarding state, VLAN trunk consistency, and routing table entries for {dev_label}{seg_label}. "
                f"Do not shift production traffic onto an alternate physical connection until active forwarding "
                f"readiness is confirmed."
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Confirm physical link status and LLDP/CDP neighbor entries on {dev_label}{iface_label}.",
                "Verify STP port state (forwarding vs blocking/discarding) and allowed VLAN lists on trunk interfaces.",
                "Verify active routing table (RIB/FIB) next-hop reachability before any failover decision.",
            ],
            rationale=(
                "Topological adjacency or alternate physical link records do not by themselves prove active L2/L3 "
                "forwarding readiness; operator verification prevents blackholing traffic."
            ),
        )

    if domain_key == "wireless_rf":
        return Recommendation(
            priority=priority,
            title=f"Collect wireless RF telemetry (RSSI, SNR, channel utilization, retry rates) for {dev_label}",
            action=(
                f"Advisory investigation: Current telemetry does not include radio-frequency (RF) measurements. "
                f"Collect wireless RF telemetry—specifically client RSSI, SNR, channel utilization, noise floor, "
                f"and 802.11 retry rates—on {dev_label}{seg_label} before attributing degradation to an RF fault "
                f"or adjusting transmit power and channel assignments.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Collect client RSSI and SNR distributions on {dev_label}{seg_label} from the wireless controller or access point.",
                "Inspect 2.4 GHz / 5 GHz / 6 GHz channel utilization, noise floor, and co-channel interference.",
                "Verify 802.11 frame retry rates, PHY data rates, and client reassociation counters.",
                "Correlate wireless RF measurements with wired switch uplink counters before changing RF configuration.",
            ],
            rationale=(
                f"End-to-end latency, jitter, and packet loss on {dev_label}{seg_label} do not by themselves confirm "
                f"a radio-layer fault without RF telemetry (RSSI, SNR, channel utilization, and retry rates)."
            ),
        )

    if domain_key == "service_dns_dhcp":
        return Recommendation(
            priority=priority,
            title=f"Collect DNS/DHCP protocol telemetry (query failures, response codes, DHCP pool utilization, acknowledgement timeouts) for {dev_label}",
            action=(
                f"Advisory investigation: Service-scoped probe latency and packet loss do not by themselves prove "
                f"a DNS or DHCP protocol failure. Collect protocol-level telemetry—specifically DNS query failures, "
                f"response codes (RCODEs such as SERVFAIL/REFUSED/NXDOMAIN), DHCP pool utilization, and DORA/DHCPACK "
                f"acknowledgement timeouts—for {dev_label}{seg_label} before restarting service daemons or changing routing.{backup_caveat}"
            ),
            target_devices=target_devices,
            related_finding_ids=finding_ids,
            supporting_evidence_ids=evidence_ids,
            requires_verification=True,
            verification_steps=[
                f"Collect DNS query failure counts, resolution latency, and response codes (RCODEs) on {dev_label}.",
                "Inspect DHCP pool utilization, active lease exhaustion, and DORA/DHCPACK acknowledgement timeouts.",
                "Verify DNS/DHCP service daemon health, socket buffer queues, and host system logs.",
                "Confirm intermediate switch and router interface counters remain error-free.",
            ],
            rationale=(
                f"Service-scoped probe degradation toward {dev_label}{seg_label} requires protocol-level DNS/DHCP "
                f"telemetry (query failures, response codes, DHCP pool utilization, and acknowledgement timeouts) "
                f"to confirm or rule out an application-layer service fault."
            ),
        )

    return None


# =====================================================================
# 3. RECOMMENDATION & REPORTING AGENT (AGENT 5)
# =====================================================================


class ReportingAgent:
    """
    Agent 5: Recommendation & Reporting Agent.

    Consumes the validated output of the Fault Correlation Agent (and optional
    upstream specialist responses) to produce a cross-reference-validated
    `DiagnosticReport` and `AgentResponse` with deterministic, safe, evidence-backed
    operator recommendations and a human-readable executive summary.
    """

    agent_name = AgentName.REPORTING

    @staticmethod
    def _make_error(code: ErrorCode, message: str, **details: Any) -> AgentError:
        return AgentError(
            error_code=code,
            message=message,
            source_agent=AgentName.REPORTING,
            retryable=False,
            details=details,
        )

    def analyze(
        self,
        correlation_input: Union[
            AgentResponse,
            AgentMessage,
            DiagnosticReport,
            Mapping[str, Any],
        ],
        upstream_responses: Optional[
            Sequence[Union[AgentResponse, AgentMessage, Mapping[str, Any]]]
        ] = None,
        *,
        incident_id: Optional[UUID] = None,
        run_id: Optional[UUID] = None,
    ) -> AgentResponse:
        """
        Validates correlation findings, evidence references, and upstream supporting findings,
        synthesizes safe recommendations, and returns an `AgentResponse` with `report` populated.
        """
        started = perf_counter()
        errors: list[AgentError] = []
        warnings: list[str] = []
        completed_checks: list[str] = []

        parsed = self._parse_and_validate_input(
            correlation_input=correlation_input,
            upstream_responses=upstream_responses,
            explicit_incident_id=incident_id,
            explicit_run_id=run_id,
            errors=errors,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        if parsed is None:
            return AgentResponse(
                agent_name=AgentName.REPORTING,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={"report_generated": False},
            )

        (
            resolved_incident_id,
            resolved_run_id,
            diagnosis_status,
            overall_confidence,
            root_causes,
            supporting_findings,
            limitations,
            corr_status,
        ) = parsed

        completed_checks.append("correlation_input_validation")

        # Validate that all root_causes and supporting_findings have valid internal references
        # and no dangling finding_ids or evidence_ids
        all_findings = [*root_causes, *supporting_findings]
        available_finding_ids: set[UUID] = {f.finding_id for f in all_findings}
        available_evidence_ids: set[UUID] = {
            ev.evidence_id for f in all_findings for ev in f.evidence
        }

        if not self._validate_cross_references(
            root_causes=root_causes,
            supporting_findings=supporting_findings,
            available_finding_ids=available_finding_ids,
            available_evidence_ids=available_evidence_ids,
            errors=errors,
        ):
            return AgentResponse(
                agent_name=AgentName.REPORTING,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={"report_generated": False},
            )

        completed_checks.append("cross_reference_integrity_check")

        # Generate deterministic, safe, evidence-backed recommendations
        recommendations = self._generate_recommendations(
            diagnosis_status=diagnosis_status,
            root_causes=root_causes,
            supporting_findings=supporting_findings,
            available_evidence_ids=available_evidence_ids,
            limitations=limitations,
        )
        completed_checks.append("recommendation_synthesis")
        completed_checks.append("recommendation_safety_verification")

        # Aggregate affected devices, affected segments, contradictory finding IDs, and alternative causes
        affected_devices = self._collect_affected_devices(root_causes, supporting_findings)
        affected_segments = self._collect_affected_segments(root_causes, supporting_findings)
        contradictory_finding_ids = self._collect_contradicting_finding_ids(root_causes)
        alternative_causes = root_causes[1:] if len(root_causes) > 1 else []

        # Determine overall_severity preserving root causes (or supporting findings when inconclusive)
        if root_causes:
            overall_severity = max(
                (f.severity for f in root_causes),
                key=lambda s: SEVERITY_RANK[s],
            )
        elif supporting_findings:
            overall_severity = max(
                (f.severity for f in supporting_findings),
                key=lambda s: SEVERITY_RANK[s],
            )
        else:
            overall_severity = Severity.INFO

        # Ensure PARTIAL_HYPOTHESIS and INCONCLUSIVE always have non-empty limitations_and_uncertainties
        if diagnosis_status in (DiagnosisStatus.PARTIAL_HYPOTHESIS, DiagnosisStatus.INCONCLUSIVE) and not limitations:
            limitations.append(
                "Available telemetry does not establish a single conclusive root cause without further operator verification."
            )

        # Build concise, accurate human-readable executive summary
        executive_summary = self._build_executive_summary(
            diagnosis_status=diagnosis_status,
            overall_confidence=overall_confidence,
            root_causes=root_causes,
            alternative_causes=alternative_causes,
            supporting_findings=supporting_findings,
            contradictory_finding_ids=contradictory_finding_ids,
            affected_devices=affected_devices,
            affected_segments=affected_segments,
            recommendations=recommendations,
            limitations=limitations,
        )
        completed_checks.append("executive_summary_generation")

        try:
            report = DiagnosticReport(
                incident_id=resolved_incident_id,
                run_id=resolved_run_id,
                diagnosis_status=diagnosis_status,
                overall_severity=overall_severity,
                overall_confidence=overall_confidence,
                executive_summary=executive_summary,
                root_causes=root_causes,
                supporting_findings=supporting_findings,
                recommendations=recommendations,
                limitations_and_uncertainties=limitations,
            )
        except ValidationError as exc:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Generated DiagnosticReport failed protocol validation: {exc}",
                )
            )
            return AgentResponse(
                agent_name=AgentName.REPORTING,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={"report_generated": False},
            )

        completed_checks.append("diagnostic_report_validation")

        # Determine ExecutionStatus of the Reporting Agent:
        # PARTIAL if the upstream correlation response was PARTIAL or if reporting encountered non-fatal errors;
        # informational warnings alone do not downgrade a complete report from SUCCESS to PARTIAL.
        has_partial_context = (
            corr_status == ExecutionStatus.PARTIAL
            or bool(errors)
        )
        exec_status = ExecutionStatus.PARTIAL if has_partial_context else ExecutionStatus.SUCCESS

        suspected_root_cause = root_causes[0].summary if root_causes else None
        evidence_sources = sorted(
            {
                ev.source_agent.value
                for f in all_findings
                for ev in f.evidence
            }
        )

        return AgentResponse(
            agent_name=AgentName.REPORTING,
            status=exec_status,
            findings=[],
            report=report,
            completed_checks=list(dict.fromkeys(completed_checks)),
            warnings=warnings,
            errors=errors,
            processing_time_ms=(perf_counter() - started) * 1000,
            execution_metadata={
                "incident_id": str(resolved_incident_id),
                "run_id": str(resolved_run_id),
                "status": diagnosis_status.value,
                "diagnosis_status": diagnosis_status.value,
                "suspected_root_cause": suspected_root_cause,
                "confidence": report.overall_confidence,
                "affected_devices": affected_devices,
                "affected_segments": affected_segments,
                "root_cause_ids": [str(f.finding_id) for f in root_causes],
                "alternative_causes": [
                    {
                        "finding_id": str(alt.finding_id),
                        "finding_code": alt.finding_code,
                        "summary": alt.summary,
                        "confidence": alt.confidence,
                        "severity": alt.severity.value,
                        "affected_devices": alt.affected_devices,
                        "affected_segments": alt.affected_segments,
                    }
                    for alt in alternative_causes
                ],
                "supporting_finding_ids": [str(f.finding_id) for f in supporting_findings],
                "contradicting_finding_ids": [str(fid) for fid in contradictory_finding_ids],
                "recommended_action_ids": [str(r.recommendation_id) for r in recommendations],
                "limitations": limitations,
                "evidence_sources": evidence_sources,
            },
        )

    # -----------------------------------------------------------------
    # INPUT PARSING & VALIDATION
    # -----------------------------------------------------------------

    def _parse_and_validate_input(
        self,
        correlation_input: Any,
        upstream_responses: Optional[Sequence[Any]],
        explicit_incident_id: Optional[UUID],
        explicit_run_id: Optional[UUID],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
    ) -> Optional[
        tuple[
            UUID,
            UUID,
            DiagnosisStatus,
            float,
            list[AgentFinding],
            list[AgentFinding],
            list[str],
            ExecutionStatus,
        ]
    ]:
        # Case 1: Already a DiagnosticReport or dict matching DiagnosticReport
        if isinstance(correlation_input, DiagnosticReport):
            return self._unpack_existing_report(
                correlation_input,
                explicit_incident_id=explicit_incident_id,
                explicit_run_id=explicit_run_id,
                errors=errors,
            )

        corr_resp: Optional[AgentResponse] = None
        envelope_incident_id: Optional[UUID] = None
        envelope_run_id: Optional[UUID] = None
        extra_supporting: list[AgentFinding] = []
        custom_diagnosis_status: Optional[DiagnosisStatus] = None
        custom_confidence: Optional[float] = None
        custom_limitations: list[str] = []

        if isinstance(correlation_input, AgentMessage):
            envelope_incident_id = correlation_input.incident_id
            envelope_run_id = correlation_input.run_id
            corr_resp = correlation_input.payload
        elif isinstance(correlation_input, AgentResponse):
            corr_resp = correlation_input
        elif isinstance(correlation_input, Mapping):
            raw_map = dict(correlation_input)
            if "payload" in raw_map and "sender_agent" in raw_map:
                try:
                    msg = AgentMessage.model_validate(raw_map)
                    envelope_incident_id = msg.incident_id
                    envelope_run_id = msg.run_id
                    corr_resp = msg.payload
                except (ValidationError, ValueError, TypeError) as exc:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Correlation AgentMessage failed protocol validation: {exc}",
                        )
                    )
                    return None
            elif "agent_name" in raw_map and "status" in raw_map:
                raw_inc = raw_map.pop("incident_id", None)
                raw_run = raw_map.pop("run_id", None)
                raw_supp = raw_map.pop("supporting_findings", None)
                try:
                    corr_resp = AgentResponse.model_validate(raw_map)
                    if raw_inc is not None:
                        envelope_incident_id = raw_inc if isinstance(raw_inc, UUID) else UUID(str(raw_inc))
                    if raw_run is not None:
                        envelope_run_id = raw_run if isinstance(raw_run, UUID) else UUID(str(raw_run))
                    if raw_supp is not None:
                        if not isinstance(raw_supp, Sequence) or isinstance(raw_supp, (str, bytes)):
                            raise ValueError("'supporting_findings' must be a sequence of AgentFinding objects.")
                        for sf in raw_supp:
                            extra_supporting.append(
                                sf if isinstance(sf, AgentFinding) else AgentFinding.model_validate(sf)
                            )
                except (ValidationError, ValueError, TypeError) as exc:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Correlation AgentResponse dictionary failed validation: {exc}",
                        )
                    )
                    return None
            elif "correlation_response" in raw_map or "root_causes" in raw_map or "diagnosis_status" in raw_map:
                return self._parse_structured_reporting_dict(
                    raw_map=raw_map,
                    upstream_responses=upstream_responses,
                    explicit_incident_id=explicit_incident_id,
                    explicit_run_id=explicit_run_id,
                    errors=errors,
                    warnings=warnings,
                )
            else:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        "Unrecognized mapping structure for ReportingAgent input.",
                    )
                )
                return None
        else:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"ReportingAgent input must be an AgentResponse, AgentMessage, DiagnosticReport, or mapping, got {type(correlation_input).__name__}.",
                )
            )
            return None

        if corr_resp.agent_name != AgentName.CORRELATION:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"ReportingAgent requires input from 'correlation' agent, got '{corr_resp.agent_name.value}'.",
                )
            )
            return None

        if corr_resp.status == ExecutionStatus.FAILED:
            errors.append(
                self._make_error(
                    ErrorCode.MISSING_INPUT,
                    "Upstream Correlation Agent response has status='failed'; cannot generate a diagnostic report.",
                )
            )
            return None

        for w in corr_resp.warnings:
            if w not in warnings:
                warnings.append(w)

        meta = corr_resp.execution_metadata

        # Resolve and validate incident_id & run_id
        resolved_inc = self._resolve_uuid(
            explicit_id=explicit_incident_id,
            envelope_id=envelope_incident_id,
            meta_val=meta.get("incident_id"),
            field_name="incident_id",
            errors=errors,
        )
        resolved_run = self._resolve_uuid(
            explicit_id=explicit_run_id,
            envelope_id=envelope_run_id,
            meta_val=meta.get("run_id"),
            field_name="run_id",
            errors=errors,
        )
        if resolved_inc is None or resolved_run is None:
            return None

        # Extract supporting findings from metadata and/or explicit upstream_responses
        supporting_findings: list[AgentFinding] = []
        seen_supp_ids: set[UUID] = set()

        for sf in extra_supporting:
            if sf.finding_id not in seen_supp_ids:
                seen_supp_ids.add(sf.finding_id)
                supporting_findings.append(sf)

        meta_supp = meta.get("supporting_findings", [])
        if isinstance(meta_supp, Sequence) and not isinstance(meta_supp, (str, bytes)):
            for idx, raw_sf in enumerate(meta_supp):
                try:
                    sf = raw_sf if isinstance(raw_sf, AgentFinding) else AgentFinding.model_validate(raw_sf)
                    if sf.finding_id not in seen_supp_ids:
                        seen_supp_ids.add(sf.finding_id)
                        supporting_findings.append(sf)
                except (ValidationError, ValueError, TypeError) as exc:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Supporting finding at index {idx} in correlation metadata failed validation: {exc}",
                        )
                    )
                    return None

        if upstream_responses is not None:
            if not isinstance(upstream_responses, Sequence) or isinstance(upstream_responses, (str, bytes)):
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        "'upstream_responses' must be a sequence of AgentResponse/AgentMessage objects.",
                    )
                )
                return None
            for u_idx, u_item in enumerate(upstream_responses):
                try:
                    if isinstance(u_item, AgentMessage):
                        if u_item.incident_id != resolved_inc or u_item.run_id != resolved_run:
                            errors.append(
                                self._make_error(
                                    ErrorCode.INVALID_MESSAGE,
                                    f"Upstream message at index {u_idx} has mismatched incident_id or run_id.",
                                )
                            )
                            return None
                        u_resp = u_item.payload
                    elif isinstance(u_item, AgentResponse):
                        u_resp = u_item
                    elif isinstance(u_item, Mapping):
                        u_resp = AgentResponse.model_validate(u_item)
                    else:
                        raise TypeError(f"Unsupported upstream response type {type(u_item).__name__}")
                except (ValidationError, ValueError, TypeError) as exc:
                    errors.append(
                        self._make_error(
                            ErrorCode.INVALID_MESSAGE,
                            f"Upstream response at index {u_idx} failed validation: {exc}",
                        )
                    )
                    return None

                if u_resp.status == ExecutionStatus.FAILED:
                    continue
                for sf in u_resp.findings:
                    if sf.finding_id not in seen_supp_ids:
                        seen_supp_ids.add(sf.finding_id)
                        supporting_findings.append(sf)

        # Extract root causes from correlation findings (must be ROOT_CAUSE_HYPOTHESIS)
        root_causes: list[AgentFinding] = []
        for rc_idx, f in enumerate(corr_resp.findings):
            if f.finding_type != FindingType.ROOT_CAUSE_HYPOTHESIS or f.agent_source != AgentName.CORRELATION:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Correlation finding at index {rc_idx} must have agent_source='correlation' and "
                        f"finding_type='root_cause_hypothesis'.",
                        finding_id=str(f.finding_id),
                    )
                )
                return None
            root_causes.append(f)

        # Resolve diagnosis_status preserving correlation conclusion
        raw_diag_status = meta.get("diagnosis_status")
        if raw_diag_status is not None:
            try:
                diagnosis_status = (
                    raw_diag_status
                    if isinstance(raw_diag_status, DiagnosisStatus)
                    else DiagnosisStatus(str(raw_diag_status))
                )
            except ValueError:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Invalid diagnosis_status '{raw_diag_status}' in correlation metadata.",
                    )
                )
                return None
        else:
            diagnosis_status = (
                DiagnosisStatus.PARTIAL_HYPOTHESIS
                if root_causes
                else DiagnosisStatus.INCONCLUSIVE
            )

        # Enforce DiagnosisStatus invariants:
        # - INCONCLUSIVE reports must not force root causes
        # - IDENTIFIED / PARTIAL_HYPOTHESIS must have at least one root cause
        if diagnosis_status == DiagnosisStatus.INCONCLUSIVE:
            root_causes = []
        elif not root_causes:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Correlation output specifies diagnosis_status='{diagnosis_status.value}' "
                    f"but contains no root-cause findings.",
                )
            )
            return None

        # Resolve overall_confidence preserving correlation confidence
        if "overall_confidence" in meta and meta["overall_confidence"] is not None:
            raw_conf = meta["overall_confidence"]
            if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)) or not (0.0 <= float(raw_conf) <= 1.0):
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Invalid overall_confidence '{raw_conf}' in correlation metadata; must be in [0.0, 1.0].",
                    )
                )
                return None
            overall_confidence = round(float(raw_conf), 4)
        elif root_causes:
            overall_confidence = root_causes[0].confidence
        else:
            overall_confidence = 0.0

        # Collect limitations and missing information
        limitations: list[str] = []
        meta_lims = meta.get("limitations_and_uncertainties", [])
        if isinstance(meta_lims, Sequence) and not isinstance(meta_lims, (str, bytes)):
            for item in meta_lims:
                if isinstance(item, str) and item.strip() and item.strip() not in limitations:
                    limitations.append(item.strip())

        for rc in root_causes:
            for lim in rc.limitations:
                if lim not in limitations:
                    limitations.append(lim)
        for sf in supporting_findings:
            for lim in sf.limitations:
                if lim not in limitations:
                    limitations.append(lim)

        return (
            resolved_inc,
            resolved_run,
            diagnosis_status,
            overall_confidence,
            root_causes,
            supporting_findings,
            limitations,
            corr_resp.status,
        )

    def _parse_structured_reporting_dict(
        self,
        *,
        raw_map: dict[str, Any],
        upstream_responses: Optional[Sequence[Any]],
        explicit_incident_id: Optional[UUID],
        explicit_run_id: Optional[UUID],
        errors: list[AgentError],
        warnings: list[str],
    ) -> Optional[
        tuple[
            UUID,
            UUID,
            DiagnosisStatus,
            float,
            list[AgentFinding],
            list[AgentFinding],
            list[str],
            ExecutionStatus,
        ]
    ]:
        if "correlation_response" in raw_map:
            inc = explicit_incident_id
            if inc is None and raw_map.get("incident_id") is not None:
                try:
                    v = raw_map["incident_id"]
                    inc = v if isinstance(v, UUID) else UUID(str(v))
                except ValueError:
                    errors.append(self._make_error(ErrorCode.INVALID_MESSAGE, "Invalid incident_id."))
                    return None
            run = explicit_run_id
            if run is None and raw_map.get("run_id") is not None:
                try:
                    v = raw_map["run_id"]
                    run = v if isinstance(v, UUID) else UUID(str(v))
                except ValueError:
                    errors.append(self._make_error(ErrorCode.INVALID_MESSAGE, "Invalid run_id."))
                    return None
            up_res = upstream_responses or raw_map.get("upstream_responses")
            return self._parse_and_validate_input(
                correlation_input=raw_map["correlation_response"],
                upstream_responses=up_res,
                explicit_incident_id=inc,
                explicit_run_id=run,
                errors=errors,
                warnings=warnings,
                completed_checks=[],
            )

        # Direct dictionary with diagnosis_status, root_causes, supporting_findings, confidence, etc.
        resolved_inc = self._resolve_uuid(
            explicit_id=explicit_incident_id,
            envelope_id=None,
            meta_val=raw_map.get("incident_id"),
            field_name="incident_id",
            errors=errors,
        )
        resolved_run = self._resolve_uuid(
            explicit_id=explicit_run_id,
            envelope_id=None,
            meta_val=raw_map.get("run_id"),
            field_name="run_id",
            errors=errors,
        )
        if resolved_inc is None or resolved_run is None:
            return None

        raw_status = raw_map.get("diagnosis_status") or raw_map.get("status")
        if raw_status is None:
            errors.append(self._make_error(ErrorCode.MISSING_INPUT, "Missing 'diagnosis_status' in reporting input."))
            return None
        try:
            diagnosis_status = (
                raw_status
                if isinstance(raw_status, DiagnosisStatus)
                else DiagnosisStatus(str(raw_status))
            )
        except ValueError:
            errors.append(self._make_error(ErrorCode.INVALID_MESSAGE, f"Invalid diagnosis_status '{raw_status}'."))
            return None

        try:
            raw_rcs = raw_map.get("root_causes", [])
            if not isinstance(raw_rcs, Sequence) or isinstance(raw_rcs, (str, bytes)):
                raise ValueError("'root_causes' must be a list of AgentFinding objects.")
            root_causes = [
                rc if isinstance(rc, AgentFinding) else AgentFinding.model_validate(rc)
                for rc in raw_rcs
            ]

            raw_sfs = raw_map.get("supporting_findings", [])
            if not isinstance(raw_sfs, Sequence) or isinstance(raw_sfs, (str, bytes)):
                raise ValueError("'supporting_findings' must be a list of AgentFinding objects.")
            supporting_findings = [
                sf if isinstance(sf, AgentFinding) else AgentFinding.model_validate(sf)
                for sf in raw_sfs
            ]
        except (ValidationError, ValueError, TypeError) as exc:
            errors.append(self._make_error(ErrorCode.INVALID_MESSAGE, f"Finding validation failed: {exc}"))
            return None

        if diagnosis_status in (DiagnosisStatus.IDENTIFIED, DiagnosisStatus.PARTIAL_HYPOTHESIS) and not root_causes:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"diagnosis_status='{diagnosis_status.value}' requires at least one root cause.",
                )
            )
            return None

        if diagnosis_status == DiagnosisStatus.INCONCLUSIVE:
            root_causes = []

        raw_conf = raw_map.get("overall_confidence", raw_map.get("confidence"))
        if raw_conf is not None:
            if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)) or not (0.0 <= float(raw_conf) <= 1.0):
                errors.append(self._make_error(ErrorCode.INVALID_MESSAGE, f"Confidence '{raw_conf}' out of range [0.0, 1.0]."))
                return None
            overall_confidence = round(float(raw_conf), 4)
        elif root_causes:
            overall_confidence = root_causes[0].confidence
        else:
            overall_confidence = 0.0

        limitations: list[str] = list(raw_map.get("limitations_and_uncertainties") or raw_map.get("limitations") or [])
        for rc in root_causes:
            for lim in rc.limitations:
                if lim not in limitations:
                    limitations.append(lim)
        for sf in supporting_findings:
            for lim in sf.limitations:
                if lim not in limitations:
                    limitations.append(lim)

        return (
            resolved_inc,
            resolved_run,
            diagnosis_status,
            overall_confidence,
            root_causes,
            supporting_findings,
            limitations,
            ExecutionStatus.SUCCESS,
        )

    def _unpack_existing_report(
        self,
        report: DiagnosticReport,
        *,
        explicit_incident_id: Optional[UUID],
        explicit_run_id: Optional[UUID],
        errors: list[AgentError],
    ) -> Optional[
        tuple[
            UUID,
            UUID,
            DiagnosisStatus,
            float,
            list[AgentFinding],
            list[AgentFinding],
            list[str],
            ExecutionStatus,
        ]
    ]:
        if explicit_incident_id is not None and explicit_incident_id != report.incident_id:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Explicit incident_id '{explicit_incident_id}' mismatches report.incident_id '{report.incident_id}'.",
                )
            )
            return None
        if explicit_run_id is not None and explicit_run_id != report.run_id:
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Explicit run_id '{explicit_run_id}' mismatches report.run_id '{report.run_id}'.",
                )
            )
            return None

        return (
            report.incident_id,
            report.run_id,
            report.diagnosis_status,
            report.overall_confidence,
            list(report.root_causes),
            list(report.supporting_findings),
            list(report.limitations_and_uncertainties),
            ExecutionStatus.SUCCESS,
        )

    def _resolve_uuid(
        self,
        *,
        explicit_id: Optional[UUID],
        envelope_id: Optional[UUID],
        meta_val: Any,
        field_name: str,
        errors: list[AgentError],
    ) -> Optional[UUID]:
        meta_uuid: Optional[UUID] = None
        if meta_val is not None:
            try:
                meta_uuid = meta_val if isinstance(meta_val, UUID) else UUID(str(meta_val))
            except ValueError:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Invalid UUID for '{field_name}' in metadata: '{meta_val}'.",
                    )
                )
                return None

        candidates = [c for c in (explicit_id, envelope_id, meta_uuid) if c is not None]
        if not candidates:
            errors.append(
                self._make_error(
                    ErrorCode.MISSING_INPUT,
                    f"Missing required '{field_name}' for DiagnosticReport generation.",
                )
            )
            return None

        first = candidates[0]
        if any(c != first for c in candidates):
            errors.append(
                self._make_error(
                    ErrorCode.INVALID_MESSAGE,
                    f"Inconsistent '{field_name}' values across envelope, metadata, and parameters.",
                )
            )
            return None
        return first

    def _validate_cross_references(
        self,
        *,
        root_causes: list[AgentFinding],
        supporting_findings: list[AgentFinding],
        available_finding_ids: set[UUID],
        available_evidence_ids: set[UUID],
        errors: list[AgentError],
    ) -> bool:
        all_findings = [*root_causes, *supporting_findings]
        for finding in all_findings:
            missing_supp = [
                str(fid)
                for fid in finding.supporting_finding_ids
                if fid not in available_finding_ids
            ]
            if missing_supp:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Finding '{finding.finding_code}' ({finding.finding_id}) references dangling "
                        f"supporting_finding_ids not present in report: {missing_supp}.",
                        finding_id=str(finding.finding_id),
                        dangling_supporting_finding_ids=missing_supp,
                    )
                )
                return False

            missing_contra = [
                str(fid)
                for fid in finding.contradicting_finding_ids
                if fid not in available_finding_ids
            ]
            if missing_contra:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Finding '{finding.finding_code}' ({finding.finding_id}) references dangling "
                        f"contradicting_finding_ids not present in report: {missing_contra}.",
                        finding_id=str(finding.finding_id),
                        dangling_contradicting_finding_ids=missing_contra,
                    )
                )
                return False

            if not finding.evidence:
                errors.append(
                    self._make_error(
                        ErrorCode.INVALID_MESSAGE,
                        f"Finding '{finding.finding_code}' ({finding.finding_id}) has no supporting evidence.",
                        finding_id=str(finding.finding_id),
                    )
                )
                return False

        return True

    # -----------------------------------------------------------------
    # RECOMMENDATION & SUMMARY SYNTHESIS
    # -----------------------------------------------------------------

    def _generate_recommendations(
        self,
        *,
        diagnosis_status: DiagnosisStatus,
        root_causes: list[AgentFinding],
        supporting_findings: list[AgentFinding],
        available_evidence_ids: set[UUID],
        limitations: Optional[Sequence[str]] = None,
    ) -> list[Recommendation]:
        # An inconclusive diagnosis with no findings needs no forced recommendations
        if diagnosis_status == DiagnosisStatus.INCONCLUSIVE and not supporting_findings:
            return []

        all_findings = [*root_causes, *supporting_findings]
        if not all_findings:
            return []

        has_unverified_backup_path = any(
            f.finding_code in {"ALTERNATE_PHYSICAL_PATH_IDENTIFIED", "REDUNDANT_PHYSICAL_LINK"}
            or any(ev.metric_name == "redundant_physical_aggregation_link" for ev in f.evidence)
            for f in all_findings
        )

        explicit_ts = [
            f.timestamp
            for f in all_findings
            if "timestamp" in f.model_fields_set and f.agent_source in {AgentName.PERFORMANCE, AgentName.INFRASTRUCTURE}
        ]
        ts_skew_exceeded = (
            (max(explicit_ts) - min(explicit_ts)).total_seconds() > 900.0
            if len(explicit_ts) >= 2
            else False
        )

        has_stale_telemetry = (
            any(
                "stale" in lim.lower()
                or "differ by" in lim.lower()
                or ("exceeding" in lim.lower() and "skew" in lim.lower())
                for f in all_findings
                for lim in f.limitations
            )
            or any(
                "stale" in lim.lower()
                or "differ by" in lim.lower()
                or ("exceeding" in lim.lower() and "skew" in lim.lower())
                for lim in (limitations or [])
            )
            or any(
                f.finding_code == "UNVERIFIED_STALE_INFRASTRUCTURE_OBSERVATION"
                for f in all_findings
            )
            or ts_skew_exceeded
        )

        # Group findings into actionable rule domains strictly based on actual finding codes & evidence
        domain_buckets: dict[str, list[AgentFinding]] = {
            "device_down": [],
            "queue_drops": [],
            "cpu": [],
            "memory": [],
            "interface_errors": [],
            "wireless_rf": [],
            "service_dns_dhcp": [],
            "performance": [],
            "topology": [],
        }

        for f in all_findings:
            code = f.finding_code
            ev_metrics = {ev.metric_name.lower() for ev in f.evidence}
            devs_lower = [d.lower() for d in f.affected_devices] + [
                ev.device_id.lower() for ev in f.evidence if ev.device_id
            ]
            segs_lower = [s.lower() for s in f.affected_segments] + [
                ev.segment_id.lower() for ev in f.evidence if ev.segment_id
            ]
            svcs_lower = [
                ev.service_id.lower() for ev in f.evidence if ev.service_id
            ]

            if code in DEVICE_DOWN_FINDING_CODES or "device_operational_status" in ev_metrics and any(
                str(ev.observed_value).lower() in {"down", "unreachable", "offline", "failed", "degraded"}
                for ev in f.evidence
                if ev.metric_name == "device_operational_status"
            ):
                domain_buckets["device_down"].append(f)

            if code in QUEUE_DROP_FINDING_CODES or any("queue_drop" in m for m in ev_metrics):
                domain_buckets["queue_drops"].append(f)

            if (
                code in CPU_FINDING_CODES
                or code == "UNVERIFIED_STALE_INFRASTRUCTURE_OBSERVATION"
                or "cpu_utilization" in ev_metrics
            ):
                domain_buckets["cpu"].append(f)

            if code in MEMORY_FINDING_CODES or "memory_utilization" in ev_metrics:
                domain_buckets["memory"].append(f)

            if code in INTERFACE_ERROR_FINDING_CODES or any(
                "error" in m or "discard" in m or m == "interface_operational_status"
                for m in ev_metrics
            ):
                domain_buckets["interface_errors"].append(f)

            is_wireless_context = (
                any(d.startswith("ap-") or "wifi" in d or "wlan" in d or "wireless" in d for d in devs_lower)
                or any(s.startswith("wlan-") or "wifi" in s or "wireless" in s or "ssid" in s for s in segs_lower)
                or any("access_point" in str(ev.observed_value).lower() or "access_point" in ev.description.lower() for ev in f.evidence)
            )
            if is_wireless_context and (
                code in PERFORMANCE_FINDING_CODES
                or f.finding_type in (FindingType.PERFORMANCE_DEGRADATION, FindingType.ROOT_CAUSE_HYPOTHESIS)
            ):
                domain_buckets["wireless_rf"].append(f)

            is_dns_dhcp_service_context = (
                any("dns" in sv or "dhcp" in sv for sv in svcs_lower)
                or any("dns" in d or "dhcp" in d for d in devs_lower)
                or any("dns" in s or "dhcp" in s for s in segs_lower)
            )
            if is_dns_dhcp_service_context and (
                code in PERFORMANCE_FINDING_CODES
                or f.finding_type in (FindingType.PERFORMANCE_DEGRADATION, FindingType.ROOT_CAUSE_HYPOTHESIS)
            ):
                domain_buckets["service_dns_dhcp"].append(f)

            if code in PERFORMANCE_FINDING_CODES or f.finding_type == FindingType.PERFORMANCE_DEGRADATION:
                domain_buckets["performance"].append(f)

            if code in TOPOLOGY_UNCERTAINTY_FINDING_CODES or f.finding_type == FindingType.CONNECTIVITY_SCOPE:
                domain_buckets["topology"].append(f)

        ordered_domains = [
            "device_down",
            "queue_drops",
            "cpu",
            "memory",
            "interface_errors",
            "wireless_rf",
            "service_dns_dhcp",
            "performance",
            "topology",
        ]

        recommendations: list[Recommendation] = []
        for dom in ordered_domains:
            bucket = domain_buckets[dom]
            if not bucket:
                continue
            rec = build_recommendation_for_domain(
                domain_key=dom,
                related_findings=bucket,
                available_evidence_ids=available_evidence_ids,
                has_unverified_backup_path=has_unverified_backup_path,
                has_stale_telemetry=has_stale_telemetry,
            )
            if rec is not None:
                recommendations.append(rec)

        return recommendations

    @staticmethod
    def _collect_affected_devices(
        root_causes: Sequence[AgentFinding],
        supporting_findings: Sequence[AgentFinding],
    ) -> list[str]:
        devices: list[str] = []
        for f in [*root_causes, *supporting_findings]:
            for d in f.affected_devices:
                if d not in devices:
                    devices.append(d)
            for ev in f.evidence:
                if ev.device_id and ev.device_id not in devices:
                    devices.append(ev.device_id)
        return devices

    @staticmethod
    def _collect_affected_segments(
        root_causes: Sequence[AgentFinding],
        supporting_findings: Sequence[AgentFinding],
    ) -> list[str]:
        segments: list[str] = []
        for f in [*root_causes, *supporting_findings]:
            for s in f.affected_segments:
                if s not in segments:
                    segments.append(s)
            for ev in f.evidence:
                if ev.segment_id and ev.segment_id not in segments:
                    segments.append(ev.segment_id)
        return segments

    @staticmethod
    def _collect_contradicting_finding_ids(root_causes: Sequence[AgentFinding]) -> list[UUID]:
        contra: list[UUID] = []
        for rc in root_causes:
            for fid in rc.contradicting_finding_ids:
                if fid not in contra:
                    contra.append(fid)
        return contra

    @staticmethod
    def _build_executive_summary(
        *,
        diagnosis_status: DiagnosisStatus,
        overall_confidence: float,
        root_causes: list[AgentFinding],
        alternative_causes: list[AgentFinding],
        supporting_findings: list[AgentFinding],
        contradictory_finding_ids: list[UUID],
        affected_devices: list[str],
        affected_segments: list[str],
        recommendations: list[Recommendation],
        limitations: list[str],
    ) -> str:
        """
        Builds a structured, operator-friendly explanation covering:
        1. What was detected & diagnosis status
        2. Why the system suspects this cause (or why it is inconclusive)
        3. Affected devices and network segments
        4. Supporting (and contradicting) evidence
        5. Alternative hypotheses & what remains uncertain
        6. Next operator verification steps
        """
        dev_str = ", ".join(affected_devices) if affected_devices else "none identified"
        seg_str = ", ".join(affected_segments) if affected_segments else "none identified"

        if diagnosis_status == DiagnosisStatus.INCONCLUSIVE or not root_causes:
            supp_count = len(supporting_findings)
            lim_str = "; ".join(limitations[:2]) if limitations else "insufficient corroborating telemetry"
            summary = (
                f"[INCONCLUSIVE DIAGNOSIS | Confidence: {overall_confidence:.2f}] "
                f"1. Detection: Evaluated {supp_count} upstream finding(s), which were insufficient to isolate a probable root cause. "
                f"2. Scope: Devices observed: {dev_str}; segments observed: {seg_str}. "
                f"3. Uncertainty: {lim_str}. "
                f"4. Next Steps: Collect missing domain telemetry and verify device/path state before taking corrective action."
            )
            return summary[:3000]

        primary = root_causes[0]
        ev_summaries = [
            f"{ev.metric_name}={ev.observed_value}{ev.unit or ''}"
            for ev in primary.evidence[:4]
        ]
        ev_str = ", ".join(ev_summaries) if ev_summaries else "linked upstream evidence"

        contra_str = (
            f" Contradicting observations retained: {len(contradictory_finding_ids)} finding(s)."
            if contradictory_finding_ids
            else ""
        )
        alt_str = (
            f" Alternative hypotheses ({len(alternative_causes)}): "
            + "; ".join(f"{alt.finding_code} ({alt.confidence:.2f})" for alt in alternative_causes[:2])
            + "."
            if alternative_causes
            else " No competing root-cause hypotheses identified."
        )
        lim_str = (
            "; ".join(limitations[:2])
            if limitations
            else "Heuristic correlation; operator verification required before production changes."
        )
        next_step_str = (
            recommendations[0].title
            if recommendations
            else "Verify device and interface state using read-only operator checks."
        )

        summary = (
            f"[{diagnosis_status.value.upper()} | Confidence: {overall_confidence:.2f} | Severity: {primary.severity.value.upper()}] "
            f"1. Detected: {primary.summary} ({primary.finding_code}). "
            f"2. Rationale: Correlated across {len(primary.supporting_finding_ids)} supporting finding(s). "
            f"3. Affected Scope: Devices=[{dev_str}], Segments=[{seg_str}]. "
            f"4. Evidence: {ev_str}.{contra_str}{alt_str} "
            f"5. Uncertainty & Limitations: {lim_str} "
            f"6. Recommended Next Verification: {next_step_str}."
        )
        return summary[:3000]


def generate_diagnostic_report(
    correlation_input: Union[
        AgentResponse,
        AgentMessage,
        DiagnosticReport,
        Mapping[str, Any],
    ],
    upstream_responses: Optional[
        Sequence[Union[AgentResponse, AgentMessage, Mapping[str, Any]]]
    ] = None,
    *,
    incident_id: Optional[UUID] = None,
    run_id: Optional[UUID] = None,
) -> AgentResponse:
    """Convenience entry point for orchestrator and tests to run the Recommendation & Reporting Agent."""
    return ReportingAgent().analyze(
        correlation_input,
        upstream_responses=upstream_responses,
        incident_id=incident_id,
        run_id=run_id,
    )


run_reporting_analysis = generate_diagnostic_report
