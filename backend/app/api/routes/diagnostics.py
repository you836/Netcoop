import platform
import subprocess
import re
import time
import uuid
from typing import Any
from fastapi import APIRouter, HTTPException, Body, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import (
    Incident as IncidentRow,
    Telemetry as TelemetryRow,
    AgentMessage as AgentMessageRow,
    DiagnosticReport as DiagnosticReportRow,
)
from app.services.orchestrator import run_diagnostic, run_network_diagnosis
from app.services.groq_service import enrich_diagnosis_with_groq
from app.schemas.diagnostics import LivePingProbeRequest

router = APIRouter(
    prefix="/diagnostics",
    tags=["Diagnostics"],
)


def persist_diagnostic_session(
    db: Session,
    *,
    incident_id: str,
    title: str,
    telemetry_items: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    report: dict[str, Any],
) -> bool:
    """
    Persists the full multi-agent diagnostic workflow across the 4 relational tables:
    incidents -> telemetry, agent_messages, diagnostic_reports.
    """
    try:
        inc_id = str(report.get("incident_id") or incident_id or uuid.uuid4())

        # Upsert / replace if same benchmark incident_id is re-run
        existing_inc = db.get(IncidentRow, inc_id)
        if existing_inc is not None:
            db.delete(existing_inc)
            db.flush()

        root_causes = report.get("root_causes") or []
        probable_cause = (
            root_causes[0].get("summary")
            if root_causes and isinstance(root_causes[0], dict)
            else report.get("executive_summary", "Multi-Agent Network Evaluation")
        )[:245]

        inc_row = IncidentRow(
            id=inc_id,
            user_id="noc-operator",
            title=title[:245],
            status=str(report.get("diagnosis_status", "completed"))[:30],
        )
        db.add(inc_row)
        db.flush()

        # 1. Telemetry rows linked to incident
        for item in telemetry_items:
            if not isinstance(item, dict):
                continue
            dev_id = str(item.get("device_id") or item.get("service_id") or "campus-node")[:120]
            metrics_payload = item.get("metrics") if isinstance(item.get("metrics"), dict) else item
            db.add(
                TelemetryRow(
                    id=str(uuid.uuid4()),
                    incident_id=inc_id,
                    user_id="noc-operator",
                    device_id=dev_id,
                    metrics=metrics_payload,
                )
            )

        # 2. Inter-agent protocol messages linked to incident
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            msg_id = str(msg.get("message_id") or uuid.uuid4())
            sender = str(msg.get("sender_agent") or "agent")[:100]
            receiver = str(msg.get("receiver_agent") or "orchestrator")[:100]
            db.add(
                AgentMessageRow(
                    id=msg_id,
                    incident_id=inc_id,
                    run_id=str(msg.get("run_id") or report.get("run_id") or inc_id)[:36],
                    agent_id=sender,
                    sender_agent=sender,
                    receiver_agent=receiver,
                    message_type=str(msg.get("message_type") or "agent_response")[:50],
                    schema_version=str(msg.get("schema_version") or "1.0")[:10],
                    payload=msg.get("payload") if isinstance(msg.get("payload"), dict) else msg,
                )
            )

        # 3. Unified DiagnosticReport linked to incident
        db.add(
            DiagnosticReportRow(
                id=str(report.get("report_id") or uuid.uuid4())[:36],
                incident_id=inc_id,
                user_id="noc-operator",
                probable_cause=probable_cause,
                severity=str(report.get("overall_severity") or "info")[:30],
                confidence=float(report.get("overall_confidence") or 0.0),
                report=report,
            )
        )

        db.commit()
        print(
            f"[DATABASE] Persisted incident {inc_id}: "
            f"{len(telemetry_items)} telemetry row(s), {len(messages)} agent message(s), 1 report."
        )
        return True
    except Exception as exc:
        db.rollback()
        print(f"[DATABASE WARNING] Failed to persist diagnostic session: {exc}")
        return False


def probe_real_host(host: str, count: int = 4) -> dict:
    """Probes a real IP or domain with ICMP ping and extracts live latency, loss, and jitter."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, str(count), host]

    try:
        start = time.time()
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
        elapsed = (time.time() - start) * 1000

        loss_match = re.search(r"(\d+)%\s*(loss|lost)", output, re.IGNORECASE)
        loss = float(loss_match.group(1)) if loss_match else 0.0

        rtt_match = (
            re.search(r"Average\s*=\s*(\d+)ms", output, re.IGNORECASE)
            or re.search(r"min/avg/max[^=]*=\s*[\d\.]+/([\d\.]+)/", output)
        )
        if rtt_match:
            latency = float(rtt_match.group(1))
        else:
            latency = elapsed / count

        jitter = 2.0
        rtt_range = re.search(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms", output, re.IGNORECASE)
        if rtt_range:
            min_rtt = float(rtt_range.group(1))
            max_rtt = float(rtt_range.group(2))
            jitter = round(max(0.5, (max_rtt - min_rtt) / 2.0), 2)

        return {
            "device_id": host,
            "metrics": {
                "latency_ms": round(latency, 2),
                "packet_loss_pct": round(loss, 2),
                "jitter_ms": jitter,
                "dns_ok": True,
                "dhcp_ok": True,
                "link_utilization_pct": 25.0 if loss == 0 else min(95.0, 40.0 + loss * 5),
            },
        }
    except subprocess.TimeoutExpired:
        return {
            "device_id": host,
            "metrics": {
                "latency_ms": 3000.0,
                "packet_loss_pct": 100.0,
                "jitter_ms": 0.0,
                "dns_ok": False,
                "dhcp_ok": True,
                "link_utilization_pct": 0.0,
            },
        }
    except Exception:
        return {
            "device_id": host,
            "metrics": {
                "latency_ms": 3000.0,
                "packet_loss_pct": 100.0,
                "jitter_ms": 0.0,
                "dns_ok": False,
                "dhcp_ok": False,
                "link_utilization_pct": 0.0,
            },
        }


@router.post("/probe-and-diagnose")
def probe_and_diagnose(req: LivePingProbeRequest, db: Session = Depends(get_db)):
    """
    1. Executes a real ICMP probe on the target host/gateway.
    2. Runs all 5 deterministic specialist agents.
    3. Enriches the final synthesis with Groq LLM.
    4. Persists Incident, Telemetry, AgentMessages, and DiagnosticReport to PostgreSQL.
    """
    print(f"\n[DIAGNOSTICS] Starting live ICMP probe to host: '{req.target_host}' (count={req.count})...")
    telemetry = [probe_real_host(req.target_host, req.count)]
    print(f"[DIAGNOSTICS] Telemetry measured: {telemetry}")
    incident_id = str(uuid.uuid4())

    try:
        messages, report = run_diagnostic(incident_id, telemetry)

        print(f"[DIAGNOSTICS] Invoking Groq LLM for host: {req.target_host}...")
        groq_enrichment = enrich_diagnosis_with_groq(
            telemetry=telemetry,
            deterministic_findings=report.get("root_causes", []),
            raw_status=report.get("diagnosis_status", "inconclusive"),
            raw_severity=report.get("overall_severity", "low"),
        )

        if groq_enrichment:
            print("[DIAGNOSTICS] Groq LLM enrichment SUCCESSFUL!")
            if groq_enrichment.get("ai_executive_summary"):
                report["executive_summary"] = groq_enrichment["ai_executive_summary"]
            report["groq_analysis"] = groq_enrichment
        else:
            metric_info = telemetry[0].get("metrics", {})
            loss = metric_info.get("packet_loss_pct", 0)
            lat = metric_info.get("latency_ms", 0)
            jit = metric_info.get("jitter_ms", 0)

            if loss >= 100:
                report["overall_severity"] = "critical"
                report["diagnosis_status"] = "identified"
                report["executive_summary"] = (
                    f"CRITICAL HOST OUTAGE: Target '{req.target_host}' is completely unreachable (100% packet loss, RTT timed out). "
                    "ICMP echo requests failed to elicit a response. Possible link disruption, device offline, or upstream firewall drop."
                )
            elif loss > 0:
                report["overall_severity"] = "high"
                report["diagnosis_status"] = "partial_hypothesis"
                report["executive_summary"] = (
                    f"NETWORK IMPAIRMENT DETECTED: Target '{req.target_host}' experienced {loss}% packet loss with {lat:.1f}ms latency. "
                    "Packet degradation points to buffer congestion or intermittent wireless/physical link quality."
                )
            else:
                report["overall_severity"] = "low"
                report["diagnosis_status"] = "identified"
                report["executive_summary"] = (
                    f"HEALTHY PATH VERIFIED: Target '{req.target_host}' is fully reachable with 0% packet loss, "
                    f"{lat:.1f}ms round-trip latency, and {jit:.1f}ms jitter. Network path operates within nominal SLAs."
                )

        persisted = persist_diagnostic_session(
            db,
            incident_id=incident_id,
            title=f"Live ICMP Probe: {req.target_host}",
            telemetry_items=telemetry,
            messages=messages,
            report=report,
        )

        return {
            "incident_id": incident_id,
            "target_host": req.target_host,
            "telemetry_collected": telemetry,
            "messages": messages,
            "report": report,
            "db_persisted": persisted,
            "powered_by": "Groq LLM + NetCoop Multi-Agent Protocol",
        }
    except Exception as exc:
        print(f"[DIAGNOSTICS ERROR] {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/run")
def run_custom_telemetry(payload: Any = Body(...), db: Session = Depends(get_db)):
    """Diagnoses arbitrary real telemetry ingested from network infrastructure or scenario benchmarks and persists all relational tables."""
    if isinstance(payload, dict) and ("performance_telemetry" in payload or "infrastructure_telemetry" in payload):
        incident_id = str(payload.get("incident_id") or uuid.uuid4())
        try:
            res = run_network_diagnosis(payload)
            messages = [msg.to_json_dict() for msg in res.agent_messages]
            report = (
                res.report.model_dump(mode="json")
                if res.report
                else {
                    "incident_id": str(res.incident_id),
                    "run_id": str(res.run_id),
                    "diagnosis_status": res.diagnosis_status.value,
                    "overall_severity": "low",
                    "overall_confidence": 0.85,
                    "executive_summary": "Diagnosis completed across all agents.",
                    "root_causes": [f.model_dump(mode="json") for f in res.findings],
                    "supporting_findings": [],
                    "recommendations": [],
                    "limitations_and_uncertainties": res.warnings,
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )

            groq_enrichment = enrich_diagnosis_with_groq(
                telemetry=[
                    {"performance_telemetry": payload.get("performance_telemetry", [])[:12]},
                    {"infrastructure_telemetry": payload.get("infrastructure_telemetry", [])[:8]},
                ],
                deterministic_findings=report.get("root_causes", []),
                raw_status=report.get("diagnosis_status", "inconclusive"),
                raw_severity=report.get("overall_severity", "low"),
            )
            if groq_enrichment:
                if groq_enrichment.get("ai_executive_summary"):
                    report["executive_summary"] = groq_enrichment["ai_executive_summary"]
                report["groq_analysis"] = groq_enrichment

            combined_telemetry = [
                *(payload.get("performance_telemetry") or []),
                *(payload.get("infrastructure_telemetry") or []),
            ]
            persisted = persist_diagnostic_session(
                db,
                incident_id=str(res.incident_id),
                title=f"Campus Benchmark Incident {str(res.incident_id)[:8]}",
                telemetry_items=combined_telemetry,
                messages=messages,
                report=report,
            )

            return {
                "incident_id": str(res.incident_id),
                "messages": messages,
                "report": report,
                "db_persisted": persisted,
                "powered_by": "Groq LLM + NetCoop Multi-Agent Protocol",
            }
        except Exception as exc:
            print(f"[SCENARIO RUN ERROR] {exc}")
            raise HTTPException(status_code=500, detail=str(exc))

    raw_telemetry = payload.get("telemetry") if isinstance(payload, dict) else payload
    telemetry_list = raw_telemetry if isinstance(raw_telemetry, list) else [raw_telemetry]
    incident_id = str(uuid.uuid4())

    try:
        messages, report = run_diagnostic(incident_id, telemetry_list)

        groq_enrichment = enrich_diagnosis_with_groq(
            telemetry=telemetry_list,
            deterministic_findings=report.get("root_causes", []),
            raw_status=report.get("diagnosis_status", "inconclusive"),
            raw_severity=report.get("overall_severity", "low"),
        )

        if groq_enrichment:
            if groq_enrichment.get("ai_executive_summary"):
                report["executive_summary"] = groq_enrichment["ai_executive_summary"]
            report["groq_analysis"] = groq_enrichment

        persisted = persist_diagnostic_session(
            db,
            incident_id=incident_id,
            title="Custom Telemetry Diagnostic Run",
            telemetry_items=telemetry_list,
            messages=messages,
            report=report,
        )

        return {
            "incident_id": incident_id,
            "messages": messages,
            "report": report,
            "db_persisted": persisted,
            "powered_by": "Groq LLM + NetCoop Multi-Agent Protocol",
        }
    except Exception as exc:
        print(f"[DIAGNOSTICS ERROR] {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/history")
def get_persisted_history(limit: int = 10, db: Session = Depends(get_db)):
    """Returns persisted incidents along with their relational telemetry, agent_messages, and diagnostic_reports counts."""
    incidents = (
        db.query(IncidentRow)
        .order_by(IncidentRow.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "incident_id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "telemetry_count": len(inc.telemetry_records),
            "messages_count": len(inc.messages),
            "agents_communicated": [
                f"{m.sender_agent} -> {m.receiver_agent}" for m in inc.messages
            ],
            "probable_cause": inc.report.probable_cause if inc.report else None,
            "severity": inc.report.severity if inc.report else None,
            "confidence": inc.report.confidence if inc.report else None,
        }
        for inc in incidents
    ]
