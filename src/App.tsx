import { useState, type ReactNode } from "react";
import type {
  AgentFinding,
  AgentMessage,
  DiagnosticReport,
  Severity,
} from "./types/models";
import "./App.css";

// Crisp Lucide-style SVG Icon Set (zero extra bundle dependency)
const IconNetwork = ({ size = 20 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="16" y="16" width="6" height="6" rx="1" />
    <rect x="2" y="16" width="6" height="6" rx="1" />
    <rect x="9" y="2" width="6" height="6" rx="1" />
    <path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" />
    <path d="M12 12V8" />
  </svg>
);

const IconDatabase = ({ size = 15 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <ellipse cx="12" cy="5" rx="9" ry="3" />
    <path d="M3 5V19A9 3 0 0 0 21 19V5" />
    <path d="M3 12A9 3 0 0 0 21 12" />
  </svg>
);

const IconLayers = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="12 2 2 7 12 12 22 7 12 2" />
    <polyline points="2 17 12 22 22 17" />
    <polyline points="2 12 12 17 22 12" />
  </svg>
);

const IconRadio = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="2" />
    <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
  </svg>
);

const IconPlay = ({ size = 15 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="5 3 19 12 5 21 5 3" />
  </svg>
);

const IconZap = ({ size = 15 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </svg>
);

const IconFileText = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="16" y1="13" x2="8" y2="13" />
    <line x1="16" y1="17" x2="8" y2="17" />
  </svg>
);

const IconShieldAlert = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);

const IconActivity = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);

const IconCpu = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
    <rect x="9" y="9" width="6" height="6" />
    <line x1="9" y1="1" x2="9" y2="4" />
    <line x1="15" y1="1" x2="15" y2="4" />
    <line x1="9" y1="20" x2="9" y2="23" />
    <line x1="15" y1="20" x2="15" y2="23" />
    <line x1="20" y1="9" x2="23" y2="9" />
    <line x1="20" y1="14" x2="23" y2="14" />
    <line x1="1" y1="9" x2="4" y2="9" />
    <line x1="1" y1="14" x2="4" y2="14" />
  </svg>
);

const IconTerminal = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="4 17 10 11 4 5" />
    <line x1="12" y1="19" x2="20" y2="19" />
  </svg>
);

const IconSparkles = ({ size = 14 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z" />
  </svg>
);

const IconCheckCircle = ({ size = 18 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
    <polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

const IconCopy = ({ size = 13 }: { size?: number }) => (
  <svg className="lucide-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

// Official Hackathon Scenarios from Problem Statement
const HACKATHON_BENCHMARKS = [
  {
    id: "sc2",
    title: "Scenario 02: Network Link Congestion",
    badge: "Link Congestion",
    desc: "Hostel & Department switches with bufferbloat, 96.5% utilization, and 14,820 queue drops.",
    payload: {
      incident_id: "10000000-0000-4000-8000-000000000002",
      run_id: "20000000-0000-4000-8000-000000000002",
      performance_telemetry: [
        { record_id: "sc2-perf-001", metric_name: "latency_ms", value: 195.0, unit: "ms", device_id: "sw-acc-bldg1-01", segment_id: "vlan-104", timestamp: "2026-10-31T14:00:00Z" },
        { record_id: "sc2-perf-002", metric_name: "packet_loss_rate", value: 3.4, unit: "%", device_id: "sw-acc-bldg1-02", segment_id: "vlan-104", timestamp: "2026-10-31T14:00:05Z" },
        { record_id: "sc2-perf-003", metric_name: "bandwidth_utilization", value: 96.5, unit: "%", device_id: "sw-agg-core-01", interface_id: "TenGig0/1", segment_id: "vlan-104", timestamp: "2026-10-31T14:00:10Z" }
      ],
      infrastructure_telemetry: [
        { record_id: "sc2-infra-001", device_id: "sw-agg-core-01", status: "up", cpu_utilization: 88.0, memory_utilization: 62.0, segment_id: "vlan-104", timestamp: "2026-10-31T14:00:10Z",
          interfaces: [{ record_id: "sc2-infra-if-001", interface_id: "TenGig0/1", status: "up", in_errors: 0, out_errors: 0, out_queue_drops_delta: 14820, elapsed_seconds: 60.0, segment_id: "vlan-104", timestamp: "2026-10-31T14:00:10Z" }] }
      ],
      topology: {
        devices: [
          { device_id: "sw-agg-core-01", device_type: "aggregation_switch", segment_ids: ["vlan-104"] },
          { device_id: "sw-acc-bldg1-01", device_type: "access_switch", segment_ids: ["vlan-104"] }
        ],
        links: [{ link_id: "lnk-agg-acc", source_device: "sw-agg-core-01", target_device: "sw-acc-bldg1-01", status: "up", link_type: "trunk" }]
      }
    }
  },
  {
    id: "sc3",
    title: "Scenario 03: Hardware / CPU Saturation",
    badge: "Hardware Failure",
    desc: "Core campus router reaching 98.4% CPU overload with interface error bursts.",
    payload: {
      incident_id: "10000000-0000-4000-8000-000000000003",
      performance_telemetry: [{ record_id: "sc3-perf-001", metric_name: "latency_ms", value: 420.0, unit: "ms", device_id: "rtr-campus-core-01", segment_id: "vlan-10" }],
      infrastructure_telemetry: [{ record_id: "sc3-infra-001", device_id: "rtr-campus-core-01", status: "degraded", cpu_utilization: 98.4, memory_utilization: 91.2, interfaces: [{ interface_id: "Gi0/0", status: "flapping", in_errors: 1840, egress_queue_drops: 980 }] }],
      topology: { devices: [{ device_id: "rtr-campus-core-01", device_type: "router" }], links: [] }
    }
  },
  {
    id: "sc4",
    title: "Scenario 04: Campus Hostel Weak Wi-Fi",
    badge: "Weak Wi-Fi",
    desc: "Hostel access point with 58ms jitter, high retransmissions, and wireless degradation.",
    payload: {
      incident_id: "10000000-0000-4000-8000-000000000004",
      performance_telemetry: [
        { record_id: "sc4-perf-001", metric_name: "latency_ms", value: 165.0, unit: "ms", device_id: "ap-hostel-floor2-01", segment_id: "wlan-hostel-floor2" },
        { record_id: "sc4-perf-002", metric_name: "jitter_ms", value: 58.0, unit: "ms", device_id: "ap-hostel-floor2-01", segment_id: "wlan-hostel-floor2" },
        { record_id: "sc4-perf-003", metric_name: "packet_loss_rate", value: 4.2, unit: "%", device_id: "ap-hostel-floor2-01", segment_id: "wlan-hostel-floor2" }
      ],
      infrastructure_telemetry: [{ record_id: "sc4-infra-001", device_id: "ap-hostel-floor2-01", status: "up", cpu_utilization: 32.0, memory_utilization: 48.0, segment_id: "wlan-hostel-floor2" }],
      topology: { devices: [{ device_id: "ap-hostel-floor2-01", device_type: "access_point" }], links: [] }
    }
  },
  {
    id: "sc5",
    title: "Scenario 05: DNS / DHCP Failure",
    badge: "Service Failure",
    desc: "Central campus authentication and DNS server connectivity timeout.",
    payload: {
      incident_id: "10000000-0000-4000-8000-000000000005",
      performance_telemetry: [
        { record_id: "sc5-perf-001", metric_name: "latency_ms", value: 240.0, unit: "ms", device_id: "srv-dns-dhcp-core", service_id: "dns-dhcp-core" },
        { record_id: "sc5-perf-002", metric_name: "packet_loss_rate", value: 8.5, unit: "%", device_id: "srv-dns-dhcp-core", service_id: "dns-dhcp-core" }
      ],
      infrastructure_telemetry: [{ record_id: "sc5-infra-001", device_id: "srv-dns-dhcp-core", status: "degraded", cpu_utilization: 34.0, memory_utilization: 51.0 }],
      topology: { devices: [{ device_id: "srv-dns-dhcp-core", device_type: "server" }], links: [] }
    }
  },
  {
    id: "sc1",
    title: "Scenario 01: Normal Healthy Network",
    badge: "Healthy Baseline",
    desc: "Normal campus network operation. All metrics within healthy thresholds.",
    payload: {
      incident_id: "10000000-0000-4000-8000-000000000001",
      performance_telemetry: [
        { record_id: "sc1-perf-001", metric_name: "latency_ms", value: 14.2, unit: "ms", device_id: "rtr-core-01", segment_id: "vlan-10" },
        { record_id: "sc1-perf-002", metric_name: "packet_loss_rate", value: 0.0, unit: "%", device_id: "rtr-core-01", segment_id: "vlan-10" }
      ],
      infrastructure_telemetry: [{ record_id: "sc1-infra-001", device_id: "rtr-core-01", status: "up", cpu_utilization: 24.0, memory_utilization: 38.5 }],
      topology: { devices: [{ device_id: "rtr-core-01", device_type: "router" }], links: [] }
    }
  }
];

// Helper: agent abbreviation for avatar
function agentAbbr(name: string): string {
  const map: Record<string, string> = {
    PerformanceAgent: "PERF",
    InfrastructureAgent: "INFRA",
    ConnectivityAgent: "CONN",
    CorrelationAgent: "CORR",
    ReportingAgent: "RPT",
  };
  return map[name] || name.slice(0, 4).toUpperCase();
}

export default function App() {
  const [activeMode, setActiveMode] = useState<"benchmarks" | "liveProbe">("benchmarks");
  const [selectedBenchmarkId, setSelectedBenchmarkId] = useState<string>("sc2");
  const [telemetryJson, setTelemetryJson] = useState<string>(
    JSON.stringify(HACKATHON_BENCHMARKS[0].payload, null, 2)
  );

  const [targetHost, setTargetHost] = useState<string>("8.8.8.8");
  const [packetCount, setPacketCount] = useState<number>(4);

  const [isDiagnosing, setIsDiagnosing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<"summary" | "rootCauses" | "agents" | "telemetry" | "architecture">("summary");
  const [report, setReport] = useState<DiagnosticReport | null>(null);
  const [agentMessages, setAgentMessages] = useState<AgentMessage[]>([]);
  const [capturedTelemetry, setCapturedTelemetry] = useState<any[]>([]);
  const [apiError, setApiError] = useState<string | null>(null);

  const handleSelectBenchmark = (id: string) => {
    setSelectedBenchmarkId(id);
    const found = HACKATHON_BENCHMARKS.find((b) => b.id === id);
    if (found) setTelemetryJson(JSON.stringify(found.payload, null, 2));
  };

  const handleRunDiagnosis = async () => {
    setIsDiagnosing(true);
    setApiError(null);
    setReport(null);
    try {
      const parsed = JSON.parse(telemetryJson);
      const res = await fetch("/diagnostics/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Server error ${res.status}`);
      }
      const data = await res.json();
      setReport(data.report);
      setAgentMessages(data.messages || []);
      setCapturedTelemetry(parsed.performance_telemetry || parsed.telemetry || []);
      setActiveTab("summary");
    } catch (err: unknown) {
      setApiError(err instanceof Error ? err.message : "Failed to run diagnosis");
    } finally {
      setIsDiagnosing(false);
    }
  };

  const handleLiveProbe = async () => {
    if (!targetHost.trim()) { setApiError("Please provide an IP address or host."); return; }
    setIsDiagnosing(true);
    setApiError(null);
    setReport(null);
    try {
      const res = await fetch("/diagnostics/probe-and-diagnose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_host: targetHost.trim(), count: packetCount }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Server error ${res.status}`);
      }
      const data = await res.json();
      setReport(data.report);
      setAgentMessages(data.messages || []);
      setCapturedTelemetry(data.telemetry_collected || []);
      setActiveTab("summary");
    } catch (err: unknown) {
      setApiError(err instanceof Error ? err.message : "Live probe failed");
    } finally {
      setIsDiagnosing(false);
    }
  };

  const getSevClass = (sev?: Severity | string) => {
    switch (sev) {
      case "critical": return "badge-critical";
      case "high":     return "badge-high";
      case "medium":   return "badge-medium";
      case "low":      return "badge-low";
      default:         return "badge-default";
    }
  };

  const getFindingBorderClass = (sev?: string) => {
    switch (sev) {
      case "critical": return "sev-critical";
      case "high":     return "sev-high";
      case "medium":   return "sev-medium";
      default:         return "sev-low";
    }
  };

  const getMetricValueClass = (sev?: Severity | string) => {
    switch (sev) {
      case "critical": return "red";
      case "high":     return "amber";
      case "medium":   return "amber";
      case "low":      return "green";
      default:         return "sky";
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    e.currentTarget.style.setProperty("--mouse-x", `${e.clientX}px`);
    e.currentTarget.style.setProperty("--mouse-y", `${e.clientY}px`);
  };

  return (
    <div className="noc-shell" onMouseMove={handleMouseMove}>
      {/* ── Apple Liquid Glass Cinematic Ambient Stage ── */}
      <div className="liquid-stage" aria-hidden="true">
        <div className="ambient-orb orb-burnt-orange" />
        <div className="ambient-orb orb-deep-blue" />
        <div className="ambient-orb orb-champagne-gold" />
        <div className="ambient-orb orb-charcoal-glow" />
        <div className="light-rays" />
        <div className="cursor-spotlight" />
        <span className="light-particle" style={{ width: 6, height: 6, top: "18%", left: "24%", animationDelay: "0s" }} />
        <span className="light-particle" style={{ width: 5, height: 5, top: "68%", left: "16%", animationDelay: "-4s" }} />
        <span className="light-particle" style={{ width: 7, height: 7, top: "32%", left: "78%", animationDelay: "-8s" }} />
        <span className="light-particle" style={{ width: 5, height: 5, top: "82%", left: "64%", animationDelay: "-11s" }} />
        <span className="light-particle" style={{ width: 6, height: 6, top: "46%", left: "48%", animationDelay: "-6s" }} />
      </div>

      {/* ── Top Navigation Bar ── */}
      <header className="noc-topbar glass-panel">
        <div className="topbar-left">
          <div className="brand-icon">
            <IconNetwork size={20} />
          </div>
          <div>
            <div className="brand-name">NetCoop AI</div>
            <div className="brand-sub">IIT BBS NOC · Multi-Agent Fault Diagnosis</div>
          </div>
        </div>

        <div className="topbar-right">
          <div className="status-cluster">
            <span className="status-live-badge">
              <span className="pulse-dot" />
              LIVE
            </span>
          </div>
        </div>
      </header>

      {/* ── Body ── */}
      <div className="noc-body">
        {/* ── Left Sidebar ── */}
        <aside className="noc-sidebar glass-panel">
          <div className="sidebar-section-hdr">
            <IconDatabase size={15} />
            <h2>Telemetry Source</h2>
          </div>

          {/* Mode Segmented Control */}
          <div className="seg-tabs">
            <button
              className={`seg-tab${activeMode === "benchmarks" ? " active" : ""}`}
              onClick={() => setActiveMode("benchmarks")}
            >
              <IconLayers size={13} />
              Campus Scenarios
            </button>
            <button
              className={`seg-tab${activeMode === "liveProbe" ? " active" : ""}`}
              onClick={() => setActiveMode("liveProbe")}
            >
              <IconRadio size={13} />
              Live ICMP Probe
            </button>
          </div>

          <div className="sidebar-body">
            {activeMode === "benchmarks" ? (
              <>
                <p className="sidebar-hint" style={{ marginTop: "0.25rem" }}>
                  Select an official IIT Bhubaneswar campus network benchmark scenario:
                </p>

                <div className="scenario-list">
                  {HACKATHON_BENCHMARKS.map((item) => (
                    <div
                      key={item.id}
                      className={`scenario-item glass-card${selectedBenchmarkId === item.id ? " sel" : ""}`}
                      onClick={() => handleSelectBenchmark(item.id)}
                    >
                      <div className="sc-top">
                        <span className="sc-badge">{item.badge}</span>
                        <span className="sc-id">{item.id.toUpperCase()}</span>
                      </div>
                      <div className="sc-title">{item.title}</div>
                      <div className="sc-desc">{item.desc}</div>
                    </div>
                  ))}
                </div>

                <div className="editor-block">
                  <div className="editor-hdr">
                    <IconTerminal size={13} />
                    <span className="editor-hdr-label">Telemetry Protocol · JSON</span>
                  </div>
                  <textarea
                    className="json-editor"
                    value={telemetryJson}
                    onChange={(e) => setTelemetryJson(e.target.value)}
                    rows={7}
                    spellCheck={false}
                  />
                </div>

                {apiError && <div className="err-banner">{apiError}</div>}
              </>
            ) : (
              <>
                <p className="sidebar-hint" style={{ marginTop: "0.25rem" }}>
                  Send active ICMP echo requests to any live IP, switch, or router to test real path metrics:
                </p>

                <div className="field-group">
                  <label className="field-label">Target IP / Hostname</label>
                  <input
                    type="text"
                    className="noc-input"
                    value={targetHost}
                    onChange={(e) => setTargetHost(e.target.value)}
                    placeholder="e.g. 192.168.1.1 or 8.8.8.8"
                  />
                </div>

                <div className="field-group">
                  <label className="field-label">ICMP Packet Count</label>
                  <div className="pkt-selector">
                    {[2, 4, 8, 12].map((cnt) => (
                      <button
                        key={cnt}
                        type="button"
                        className={`pkt-btn${packetCount === cnt ? " active" : ""}`}
                        onClick={() => setPacketCount(cnt)}
                      >
                        {cnt} pkts
                      </button>
                    ))}
                  </div>
                </div>

                <div className="quick-targets">
                  <span className="quick-label">Quick:</span>
                  {["1.1.1.1", "8.8.8.8", "127.0.0.1"].map((ip) => (
                    <button
                      key={ip}
                      type="button"
                      className="ghost-chip"
                      onClick={() => setTargetHost(ip)}
                    >
                      {ip}
                    </button>
                  ))}
                </div>

                {apiError && <div className="err-banner">{apiError}</div>}
              </>
            )}
          </div>

          {/* Sidebar Footer CTA */}
          <div className="sidebar-footer">
            <button
              className="btn-primary"
              disabled={isDiagnosing}
              onClick={activeMode === "benchmarks" ? handleRunDiagnosis : handleLiveProbe}
            >
              {isDiagnosing ? (
                <>
                  <span className="spinner" />
                  {activeMode === "benchmarks" ? "Orchestrating 5 Agents…" : "Probing & Running Agents…"}
                </>
              ) : activeMode === "benchmarks" ? (
                <>
                  <IconPlay size={15} />
                  Run Multi-Agent Diagnosis
                </>
              ) : (
                <>
                  <IconZap size={15} />
                  Execute Live Path Probe
                </>
              )}
            </button>
          </div>
        </aside>

        {/* ── Main Report Panel ── */}
        <main className="noc-main glass-panel">
          {/* Tab Strip */}
          <div className="report-topbar">
            {(["summary", "rootCauses", "agents", "architecture", "telemetry"] as const).map((tab) => {
              const labels: Record<string, string> = {
                summary: "Executive Summary",
                rootCauses: "Root Cause & Evidence",
                agents: "Multi-Agent Protocol",
                architecture: "System Architecture",
                telemetry: "Raw Telemetry",
              };
              const icons: Record<string, ReactNode> = {
                summary: <IconFileText size={14} />,
                rootCauses: <IconShieldAlert size={14} />,
                agents: <IconActivity size={14} />,
                architecture: <IconCpu size={14} />,
                telemetry: <IconTerminal size={14} />,
              };
              const counts: Record<string, number> = {
                summary: 0,
                rootCauses: report?.root_causes?.length ?? 0,
                agents: agentMessages.length,
                architecture: 5,
                telemetry: capturedTelemetry.length,
              };
              return (
                <button
                  key={tab}
                  className={`tab-btn${activeTab === tab ? " active" : ""}`}
                  onClick={() => setActiveTab(tab)}
                >
                  {icons[tab]}
                  {labels[tab]}
                  {counts[tab] > 0 && (
                    <span className="tab-count">{counts[tab]}</span>
                  )}
                </button>
              );
            })}

            {/* Right side status badges */}
            {report && (
              <div className="report-topbar-badges">
                <span className={`badge ${getSevClass(report.overall_severity)}`}>
                  {report.overall_severity?.toUpperCase()}
                </span>
                <span className="badge badge-sky">
                  {report.diagnosis_status?.replace("_", " ").toUpperCase()}
                </span>
                <span className="badge badge-default">
                  {((report.overall_confidence || 0) * 100).toFixed(0)}% CONF
                </span>
              </div>
            )}
          </div>

          {/* Scrollable Report Viewport */}
          <div className="report-viewport">

            {/* ── Empty State ── */}
            {!report && activeTab !== "architecture" && (
              <div className="empty-state">
                <div className="empty-icon-ring">
                  <IconRadio size={30} />
                </div>
                <div className="empty-title">Awaiting Multi-Agent Diagnosis</div>
                <div className="empty-sub">
                  Choose a campus scenario or enter a live probe IP in the sidebar,
                  then click <strong>Run Multi-Agent Diagnosis</strong>.
                </div>
              </div>
            )}

            {/* ── Executive Summary Tab ── */}
            {report && activeTab === "summary" && (
              <div>
                {/* Hero Summary Card */}
                <div className="hero-card glass-card">
                  <div className="hero-card-hdr">
                    <span className="hero-card-tag">
                      <IconFileText size={14} />
                      Executive Assessment
                    </span>
                  </div>
                  <p className="hero-prose">{report.executive_summary}</p>
                </div>

                {/* Groq AI Root Cause Reasoning */}
                {report.groq_analysis?.ai_root_cause_explanation && (
                  <div className="reasoning-card">
                    <span className="reasoning-tag">
                      <IconSparkles size={14} />
                      LLM Root Cause Correlation
                    </span>
                    <p className="reasoning-text">{report.groq_analysis.ai_root_cause_explanation}</p>
                  </div>
                )}

                {/* Metric Scorecards */}
                <div className="metric-strip">
                  <div className="metric-card glass-card">
                    <div className="metric-label">Diagnosis Status</div>
                    <div className="metric-value sky">
                      {report.diagnosis_status?.toUpperCase()}
                    </div>
                  </div>
                  <div className="metric-card glass-card">
                    <div className="metric-label">Overall Severity</div>
                    <div className={`metric-value ${getMetricValueClass(report.overall_severity)}`}>
                      {report.overall_severity?.toUpperCase()}
                    </div>
                  </div>
                  <div className="metric-card glass-card">
                    <div className="metric-label">Agent Confidence</div>
                    <div className="metric-value indigo">
                      {((report.overall_confidence || 0) * 100).toFixed(1)}%
                    </div>
                  </div>
                  <div className="metric-card glass-card">
                    <div className="metric-label">Evaluated At (UTC)</div>
                    <div className="metric-value muted">
                      {new Date(report.generated_at).toLocaleTimeString()}
                    </div>
                  </div>
                </div>

                {/* Uncertainty Block */}
                {report.limitations_and_uncertainties?.length > 0 && (
                  <div className="uncertainty-block">
                    <h5>
                      <IconShieldAlert size={14} />
                      Uncertainty & Data Limitations
                    </h5>
                    <ul>
                      {report.limitations_and_uncertainties.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* ── Root Cause & Evidence Tab ── */}
            {report && activeTab === "rootCauses" && (
              <div>
                <div className="subhead">Identified Root Causes</div>

                {report.root_causes?.length === 0 ? (
                  <div className="healthy-card">
                    <div className="healthy-icon">
                      <IconCheckCircle size={20} />
                    </div>
                    <div className="healthy-text">
                      <strong>Healthy State:</strong> No anomalous performance or infrastructure deviations exceeded SLA thresholds.
                    </div>
                  </div>
                ) : (
                  report.root_causes.map((rc: AgentFinding) => (
                    <div key={rc.finding_id} className={`finding-card glass-card ${getFindingBorderClass(rc.severity)}`}>
                      <div className="finding-hdr">
                        <span className="finding-code">{rc.finding_code}</span>
                        <span className={`badge ${getSevClass(rc.severity)}`}>{rc.severity}</span>
                        <span className="finding-source">Source: {rc.agent_source}</span>
                      </div>
                      <div className="finding-body">
                        <div className="finding-summary">{rc.summary}</div>
                        <div className="finding-desc">{rc.description}</div>

                        {rc.affected_devices && rc.affected_devices.length > 0 && (
                          <div className="devices-row">
                            <span className="devices-label">Affected Hardware:</span>
                            {rc.affected_devices.map((d) => (
                              <span key={d} className="device-chip">{d}</span>
                            ))}
                          </div>
                        )}

                        {rc.evidence && rc.evidence.length > 0 && (
                          <div className="evidence-table">
                            <div className="evidence-table-hdr">
                              <span>Metric</span>
                              <span>Observed</span>
                              <span>Baseline</span>
                              <span>Description</span>
                            </div>
                            {rc.evidence.map((evi) => (
                              <div key={evi.evidence_id} className="evidence-row">
                                <span className="evi-metric">{evi.metric_name}</span>
                                <span className="evi-observed">{evi.observed_value} {evi.unit}</span>
                                <span className="evi-baseline">
                                  {evi.expected_value != null ? `${evi.expected_value} ${evi.unit}` : "—"}
                                </span>
                                <span className="evi-desc">{evi.description}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                )}

                <div className="subhead mt-4">Evidence-Based Operator Actions</div>

                {report.groq_analysis?.remediation_actions && report.groq_analysis.remediation_actions.length > 0 ? (
                  report.groq_analysis.remediation_actions.map((act, i) => (
                    <div key={i} className="action-card glass-card ai-action">
                      <div className="action-hdr">
                        <span className="badge badge-sky">
                          <IconSparkles size={12} />
                          AI
                        </span>
                        <span className="action-title">{act.title}</span>
                      </div>
                      <p className="action-body">{act.action}</p>
                      <div className="rationale-note"><strong>Rationale:</strong> {act.rationale}</div>
                      {act.verification_steps && act.verification_steps.length > 0 && (
                        <div className="cli-block">
                          <div className="cli-block-label">
                            <IconTerminal size={13} />
                            CLI Verification Commands
                          </div>
                          <ul>
                            {act.verification_steps.map((step, sIdx) => (
                              <li key={sIdx}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))
                ) : report.recommendations?.length === 0 ? (
                  <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>No corrective action needed.</p>
                ) : (
                  report.recommendations?.map((rec) => (
                    <div key={rec.recommendation_id} className="action-card glass-card">
                      <div className="action-hdr">
                        <span className={`badge ${getSevClass(rec.priority)}`}>{rec.priority}</span>
                        <span className="action-title">{rec.title}</span>
                      </div>
                      <p className="action-body">{rec.action}</p>
                      <div className="rationale-note"><strong>Rationale:</strong> {rec.rationale}</div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* ── Multi-Agent Protocol Tab ── */}
            {activeTab === "agents" && (
              <div>
                <div className="subhead">Multi-Agent Communication Trace</div>
                <div className="agent-timeline">
                  {agentMessages.length === 0 ? (
                    <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>No messages exchanged yet. Run a diagnosis first.</p>
                  ) : (
                    agentMessages.map((msg: AgentMessage, i) => (
                      <div key={msg.message_id || i} className="agent-node glass-card">
                        <div className="agent-avatar">{agentAbbr(msg.sender_agent)}</div>
                        <div className="agent-info">
                          <div className="agent-name-row">
                            <span className="agent-name">{msg.sender_agent}</span>
                            <span className={`badge ${msg.payload?.status === "success" ? "badge-low" : msg.payload?.status === "partial" ? "badge-medium" : "badge-default"}`}>
                              {msg.payload?.status}
                            </span>
                            {msg.payload?.processing_time_ms != null && (
                              <span className="agent-timing">{msg.payload.processing_time_ms.toFixed(1)} ms</span>
                            )}
                          </div>
                          <div className="agent-checks">
                            {msg.payload?.completed_checks?.join(" · ") || "Standard domain evaluation"}
                          </div>
                          {msg.payload?.findings && msg.payload.findings.length > 0 && (
                            <span className="agent-findings-count">
                              {msg.payload.findings.length} finding{msg.payload.findings.length !== 1 ? "s" : ""} emitted
                            </span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* ── Architecture Diagram Tab ── */}
            {activeTab === "architecture" && (
              <div className="architecture-container">
                <div className="subhead">SYSTEM ARCHITECTURE: MULTI-AGENT NETWORK FAULT DIAGNOSIS</div>

                <div className="architecture-canvas glass-card">
                  {/* Top: Telemetry Source */}
                  <div className="arch-top">
                    <div className="arch-node glass-card arch-telemetry">
                      <span className="arch-node-title">Telemetry Data Source</span>
                      <span className="arch-node-sub">Real ICMP Probes / Benchmarks</span>
                    </div>
                  </div>

                  {/* Flow Arrow Top */}
                  <div className="arch-vertical-flow">
                    <span className="arch-flow-arrow">⇅</span>
                    <span className="arch-flow-label">Bidirectional Ingestion Bus</span>
                  </div>

                  {/* Middle: 3-column Layout */}
                  <div className="arch-grid-middle">
                    {/* Left Column Agents */}
                    <div className="arch-col-left">
                      <div className="arch-agent-card glass-card arch-perf">
                        <div className="arch-agent-tag">Stage A Specialist</div>
                        <div className="arch-agent-name">Performance Agent</div>
                        <div className="arch-agent-desc">Monitors latency, packet loss, jitter & bandwidth utilization</div>
                        <div className="arch-agent-status-badge">Latency & Throughput SLA</div>
                      </div>

                      <div className="arch-agent-card glass-card arch-rpt">
                        <div className="arch-agent-tag">Stage C Synthesizer</div>
                        <div className="arch-agent-name">Reporting Agent</div>
                        <div className="arch-agent-desc">Aggregates findings, limitations & operator verification playbooks</div>
                        <div className="arch-agent-status-badge">Final Synthesis</div>
                      </div>
                    </div>

                    {/* Center Column: Central Orchestrator Hub */}
                    <div className="arch-col-center">
                      <div className="arch-hub-card">
                        <span className="arch-hub-icon">
                          <IconCpu size={24} />
                        </span>
                        <div className="arch-hub-title">Central Orchestrator Hub</div>
                        <div className="arch-hub-sub">State Machine & Protocol Router</div>
                        <div className="arch-hub-features">
                          <span>• Parallel Specialist Fan-Out (Stage A)</span>
                          <span>• Correlation Pipeline (Stage B)</span>
                          <span>• Unified Reporting Engine (Stage C)</span>
                          <span>• Human-in-the-Loop & Groq LLM Bridge</span>
                        </div>
                      </div>
                    </div>

                    {/* Right Column Agents */}
                    <div className="arch-col-right">
                      <div className="arch-agent-card glass-card arch-infra">
                        <div className="arch-agent-tag">Stage A Specialist</div>
                        <div className="arch-agent-name">Infrastructure Agent</div>
                        <div className="arch-agent-desc">Tracks device CPU, memory, interface errors & queue drops</div>
                        <div className="arch-agent-status-badge">Hardware & Interface Telemetry</div>
                      </div>

                      <div className="arch-agent-card glass-card arch-conn">
                        <div className="arch-agent-tag">Stage A Specialist</div>
                        <div className="arch-agent-name">Connectivity Agent</div>
                        <div className="arch-agent-desc">Assesses network link integrity, BFS topology & blast radius</div>
                        <div className="arch-agent-status-badge">Graph Topology Integrity</div>
                      </div>

                      <div className="arch-agent-card glass-card arch-corr">
                        <div className="arch-agent-tag">Stage B Cross-Domain</div>
                        <div className="arch-agent-name">Correlation Agent</div>
                        <div className="arch-agent-desc">Identifies causal relationships, eliminates competing hypotheses</div>
                        <div className="arch-agent-status-badge">Root Cause Hypothesis</div>
                      </div>
                    </div>
                  </div>

                  {/* Flow Arrow Bottom */}
                  <div className="arch-vertical-flow">
                    <span className="arch-flow-arrow">⇅</span>
                    <span className="arch-flow-label">Consensus Protocol Pipeline</span>
                  </div>

                  {/* Bottom: Unified Diagnostic Report Generator */}
                  <div className="arch-bottom">
                    <div className="arch-node glass-card arch-generator">
                      <div className="arch-gen-header">
                        <span className="arch-gen-alert-icon">!</span>
                        <span className="arch-node-title">Unified Diagnostic Report Generator</span>
                      </div>
                      <span className="arch-node-sub">
                        Calibrated Confidence • Supporting Verifiable Evidence • Remediations • Groq LLM Synthesis
                      </span>
                    </div>
                  </div>

                  {/* Legend */}
                  <div className="arch-legend">
                    <div className="legend-item">
                      <span className="legend-arrow legend-data-flow">⟶</span>
                      <span>Data Flow</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-box legend-agent-box" />
                      <span>Specialized Agent</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-arrow legend-orch-flow">⟶</span>
                      <span>Orchestration Pathway</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── Raw Telemetry Tab ── */}
            {activeTab === "telemetry" && (
              <div className="telemetry-view-container">
                <div className="telemetry-view-hdr glass-card">
                  <div className="telemetry-hdr-left">
                    <span className="telemetry-schema-pill">SCHEMA: netcoop-telemetry-v1.json</span>
                    <span className="telemetry-records-count">
                      {capturedTelemetry.length} Ingested Observation{capturedTelemetry.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="telemetry-hdr-actions">
                    <span className="telemetry-status-tag">STRICT SPEC COMPLIANT</span>
                    <button
                      type="button"
                      className="copy-telemetry-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(capturedTelemetry, null, 2));
                      }}
                    >
                      <IconCopy size={13} />
                      Copy JSON
                    </button>
                  </div>
                </div>

                <div className="telemetry-card glass-card">
                  <div className="telemetry-card-bar">
                    <span className="telemetry-dot dot-red" />
                    <span className="telemetry-dot dot-yellow" />
                    <span className="telemetry-dot dot-green" />
                    <span className="telemetry-card-title">netcoop-telemetry-stream</span>
                    <span className="telemetry-format-badge">JSON-SPEC</span>
                  </div>
                  <pre className="telemetry-code-block">
                    {JSON.stringify(capturedTelemetry, null, 2)}
                  </pre>
                </div>
              </div>
            )}

          </div>
        </main>
      </div>
    </div>
  );
}
