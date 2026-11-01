/**
 * NetCoop AI - TypeScript Models & Types
 * Generated from backend/app/agents/common.py and backend schemas
 */

// =====================================================================
// 1. PROTOCOL CONSTANTS & ENUMS
// =====================================================================

export const CURRENT_SCHEMA_VERSION = "1.0" as const;

export type PrimitiveValue = number | string | boolean;

export type AgentName =
  | "orchestrator"
  | "performance"
  | "infrastructure"
  | "connectivity"
  | "correlation"
  | "reporting";

export type MessageType = "agent_response" | "error_report";

export type ExecutionStatus = "success" | "partial" | "failed";

export type DiagnosisStatus = "identified" | "partial_hypothesis" | "inconclusive";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingType =
  | "performance_degradation"
  | "infrastructure_health"
  | "connectivity_scope"
  | "root_cause_hypothesis";

export type EvidenceType =
  | "metric"
  | "device_status"
  | "interface_counter"
  | "topology_link";

export type ErrorCode =
  | "missing_input"
  | "malformed_telemetry"
  | "invalid_message"
  | "unsupported_schema"
  | "unknown_metric_or_unit"
  | "llm_api_failure"
  | "llm_validation_failure"
  | "missing_topology"
  | "execution_timeout"
  | "internal_agent_error";

// =====================================================================
// 2. CORE DIAGNOSTIC MODELS
// =====================================================================

export interface Evidence {
  evidence_id: string; // UUID
  evidence_type: EvidenceType;
  metric_name: string;
  observed_value: PrimitiveValue;
  unit?: string | null;
  expected_value?: PrimitiveValue | null;
  device_id?: string | null;
  interface_id?: string | null;
  segment_id?: string | null;
  service_id?: string | null;
  source_agent: AgentName;
  telemetry_record_id?: string | null;
  description: string;
  timestamp: string; // ISO-8601 UTC
}

export interface AgentFinding {
  finding_id: string; // UUID
  agent_source: AgentName;
  finding_code: string; // UPPER_SNAKE_CASE (e.g. HIGH_LATENCY)
  finding_type: FindingType;
  severity: Severity;
  summary: string;
  description: string;
  confidence: number; // 0.0 - 1.0
  affected_devices?: string[];
  affected_segments?: string[];
  evidence: Evidence[];
  supporting_finding_ids?: string[];
  contradicting_finding_ids?: string[];
  limitations?: string[];
  timestamp: string; // ISO-8601 UTC
}

export interface Recommendation {
  recommendation_id: string; // UUID
  priority: Severity;
  title: string;
  action: string;
  target_devices?: string[];
  related_finding_ids: string[];
  supporting_evidence_ids: string[];
  requires_verification: boolean;
  verification_steps: string[];
  rationale: string;
}

export interface GroqRemediationAction {
  title: string;
  action: string;
  verification_steps: string[];
  rationale: string;
}

export interface GroqAnalysis {
  ai_executive_summary?: string;
  ai_root_cause_explanation?: string;
  remediation_actions?: GroqRemediationAction[];
  model_used?: string | null;
}

export interface DiagnosticReport {
  report_id: string; // UUID
  incident_id: string; // UUID
  run_id: string; // UUID
  diagnosis_status: DiagnosisStatus;
  overall_severity: Severity;
  overall_confidence: number; // 0.0 - 1.0
  executive_summary: string;
  root_causes: AgentFinding[];
  supporting_findings: AgentFinding[];
  recommendations: Recommendation[];
  limitations_and_uncertainties: string[];
  groq_analysis?: GroqAnalysis;
  generated_at: string; // ISO-8601 UTC
}

// =====================================================================
// 3. ERROR, RESPONSE & MESSAGE ENVELOPE MODELS
// =====================================================================

export interface AgentError {
  error_id: string; // UUID
  error_code: ErrorCode;
  message: string;
  source_agent: AgentName;
  retryable?: boolean;
  details?: Record<string, unknown>;
  timestamp: string; // ISO-8601 UTC
}

export interface AgentResponse {
  agent_name: AgentName;
  status: ExecutionStatus;
  findings?: AgentFinding[];
  report?: DiagnosticReport | null;
  completed_checks?: string[];
  warnings?: string[];
  errors?: AgentError[];
  processing_time_ms?: number | null;
  execution_metadata?: Record<string, unknown>;
  timestamp: string; // ISO-8601 UTC
}

export interface AgentMessage {
  message_id: string; // UUID
  incident_id: string; // UUID
  run_id: string; // UUID
  sender_agent: AgentName;
  receiver_agent: AgentName;
  message_type: MessageType;
  schema_version: string;
  payload: AgentResponse;
  timestamp: string; // ISO-8601 UTC
}

// =====================================================================
// 4. TELEMETRY, INCIDENT & ORCHESTRATOR MODELS
// =====================================================================

export interface PerformanceTelemetry {
  record_id?: string | null;
  metric_name: string;
  value: number;
  unit: string;
  device_id?: string | null;
  interface_id?: string | null;
  segment_id?: string | null;
  service_id?: string | null;
  expected_value?: number | null;
  timestamp?: string;
}

export interface InterfaceTelemetry {
  record_id?: string | null;
  interface_id: string;
  status: string;
  in_errors?: number;
  out_errors?: number;
  in_discards?: number;
  out_discards?: number;
  egress_queue_drops?: number;
  segment_id?: string | null;
  timestamp?: string;
}

export interface InfrastructureTelemetry {
  record_id?: string | null;
  device_id: string;
  status: string;
  cpu_utilization?: number;
  memory_utilization?: number;
  segment_id?: string | null;
  interfaces?: InterfaceTelemetry[];
  timestamp?: string;
}

export interface TopologyDevice {
  device_id: string;
  device_type: string;
  segment_ids?: string[];
  record_id?: string;
  timestamp?: string;
}

export interface TopologyLink {
  link_id: string;
  source_device: string;
  target_device: string;
  source_interface?: string;
  target_interface?: string;
  link_type?: string;
  status?: string;
  evidence_id?: string;
  timestamp?: string;
}

export interface TopologyData {
  devices: TopologyDevice[];
  links: TopologyLink[];
}

export interface DiagnosticIncidentInput {
  incident_id?: string;
  run_id?: string;
  performance_telemetry?: PerformanceTelemetry[];
  infrastructure_telemetry?: InfrastructureTelemetry[];
  topology?: TopologyData;
}

export interface IncidentRecord {
  id: string;
  user_id: string;
  title: string;
  status: "processing" | "completed" | "failed";
  created_at: string;
}

export interface TelemetryMetrics {
  latency_ms?: number;
  jitter_ms?: number;
  packet_loss_pct?: number;
  link_utilization_pct?: number;
  cpu_percent?: number;
  memory_percent?: number;
  signal_dbm?: number;
  throughput_mbps?: number;
  queue_drops?: number;
  interface_errors?: number;
  dns_ok?: boolean;
  dhcp_ok?: boolean;
  [key: string]: unknown;
}

export interface TelemetryRecord {
  id: string;
  user_id: string;
  device_id: string;
  timestamp: string;
  metrics: TelemetryMetrics;
  created_at: string;
}
