# NetCoop AI
### Multi-Agent Network Fault Diagnosis and Interoperability

NetCoop AI is an interoperable multi-agent network fault diagnosis system designed to analyse network telemetry, identify probable network faults, correlate diagnostic evidence, and generate unified diagnostic reports.

The system uses five specialised agents coordinated by a central orchestrator. Each agent performs a specific diagnostic responsibility and communicates through a shared structured message protocol.

---

## 1. Problem Statement

Modern networks can experience several performance and infrastructure issues, including:

- High latency and packet loss
- Network congestion and bandwidth limitations
- High CPU and memory utilisation
- Interface errors and connectivity failures
- Weak wireless connectivity
- DNS and DHCP service failures

Diagnosing these problems becomes challenging when monitoring information comes from different network components and uses inconsistent formats.

NetCoop AI addresses this challenge through coordinated diagnostic agents that analyse telemetry, exchange structured findings, correlate evidence, and produce an explainable diagnosis.

## 2. Project Objectives

- Develop specialised agents for different aspects of network diagnosis.
- Establish structured communication between agents.
- Implement centralised orchestration of agent execution.
- Correlate findings from multiple diagnostic components.
- Generate unified reports with evidence and corrective recommendations.
- Validate the system using multiple synthetic network fault scenarios.

## 3. System Architecture

NetCoop AI follows a modular architecture with five specialised agents and a central orchestrator.

### Architecture Workflow

1. Network telemetry and a selected fault scenario are supplied to the backend.
2. The central orchestrator coordinates the diagnostic workflow.
3. Three primary diagnostic agents execute concurrently.
4. Their findings are collected and passed to the Fault Correlation Agent.
5. The Reporting Agent consolidates the diagnostic results.
6. The unified report is returned to the frontend dashboard.

### Main Components

| Component | Responsibility |
|---|---|
| Frontend | Provides the dashboard and displays diagnostic results. |
| Backend API | Handles requests and coordinates application functionality. |
| Orchestrator | Manages agent execution and result collection. |
| Communication Protocol | Defines structured messages exchanged between agents. |
| Diagnostic Agents | Perform specialised network analysis. |
| Reporting System | Produces the unified diagnostic output. |

## 4. Specialised Agent Responsibilities

### 4.1 Performance Agent

Analyses network performance metrics, including latency, packet loss, jitter, bandwidth, and congestion-related measurements.

Its purpose is to identify performance degradation and abnormal network behaviour.

### 4.2 Infrastructure Agent

Evaluates infrastructure health, including device conditions, CPU and memory utilisation, interface conditions, and infrastructure-related faults.

Its purpose is to identify potential hardware, resource, and interface problems.

### 4.3 Connectivity Agent

Examines network connectivity conditions, link status, reachability, and network service availability.

Its purpose is to identify connectivity-related problems and service disruptions.

### 4.4 Fault Correlation Agent

Receives findings from the primary diagnostic agents and examines their relationships.

It combines available evidence to identify probable root causes rather than treating every detected symptom as an unrelated issue.

### 4.5 Reporting Agent

Consolidates the diagnostic results into a unified report.

The report includes:

- Probable root cause
- Affected devices or network segments
- Supporting evidence
- Confidence estimates
- Alternative explanations or uncertainty, where available
- Recommended corrective actions

## 5. Inter-Agent Communication Protocol

Communication between agents is based on a shared, structured message protocol.

The protocol is implemented using common data models and validation logic in the backend.

### Communication Principles

- **Structured messages:** Information is exchanged using defined message models rather than arbitrary text.
- **Schema versioning:** Messages include schema-version information to support compatibility checks.
- **Sender and receiver identification:** Messages identify the participating agents.
- **Message typing:** Message types identify the purpose of the communication.
- **Payload validation:** Incoming messages are checked before processing.
- **Error reporting:** Invalid or incompatible messages can be reported through structured error handling.

### Communication Workflow

Agent → Structured Message → Protocol Validation → Receiving Agent

The shared protocol supports consistent information exchange and helps prevent incompatible message structures from silently passing between components.

For implementation details, refer to the shared protocol models and parsing logic in `backend/app/agents/common.py`.

## 6. Orchestration Workflow

The central orchestrator manages the execution and coordination of the agents.

The workflow consists of the following stages:

**Stage 1 – Input Processing**

The backend receives the selected scenario and corresponding telemetry.

**Stage 2 – Parallel Diagnosis**

The Performance, Infrastructure, and Connectivity Agents analyse the available information independently and concurrently.

**Stage 3 – Result Collection**

The orchestrator collects the responses generated by the primary diagnostic agents.

**Stage 4 – Fault Correlation**

The Fault Correlation Agent examines the findings and identifies relationships between detected issues.

**Stage 5 – Report Generation**

The Reporting Agent generates the unified diagnostic report.

**Stage 6 – Result Delivery**

The completed diagnostic result is returned to the frontend dashboard.

Agents are coordinated through the central orchestrator rather than directly invoking one another.

## 7. Evidence Correlation

Evidence correlation is an important part of NetCoop AI.

Individual diagnostic agents may identify different symptoms of the same underlying network problem.

For example, network congestion may be associated with increased latency, packet loss, and high link utilisation.

The Fault Correlation Agent examines the findings together to identify possible relationships and determine the most probable explanation.

The final diagnostic output is designed to provide:

- Related diagnostic findings
- Supporting telemetry evidence
- Probable root causes
- Confidence estimates
- Alternative explanations, where applicable
- Suggested corrective actions

This approach makes the diagnosis more explainable than simply presenting isolated alerts.

## 8. Error Handling and Validation

NetCoop AI incorporates validation and error-handling mechanisms to improve reliability.

The shared protocol implementation handles conditions such as:

- Malformed messages
- Missing required fields
- Unsupported schema versions
- Invalid message structures
- Sender and payload inconsistencies
- Unexpected message recipients
- Conflicting telemetry aliases

Incoming messages are validated before being processed. Invalid messages can produce structured error information instead of being silently accepted.

The agents also validate and normalise supported telemetry formats before performing their respective analyses.

## 9. Supported Fault Scenarios

The prototype uses synthetic network telemetry to demonstrate different network conditions.

| Scenario | Description |
|---|---|
| Normal Network | Represents healthy network behaviour. |
| Link Congestion | Simulates network congestion and performance degradation. |
| Weak Wi-Fi | Represents wireless connectivity problems. |
| Ethernet / Interface Fault | Simulates infrastructure and interface-related issues. |
| DNS / DHCP Failure | Represents network service availability problems. |
| Interoperability Failure | Tests invalid or incompatible communication messages. |

These scenarios allow the diagnostic workflow to be evaluated without requiring access to a production campus network.

## 10. Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Styling | Tailwind CSS |
| Data Visualisation | Recharts |
| Backend | Python, FastAPI |
| Data Validation | Pydantic v2 |
| Database Support | PostgreSQL, SQLAlchemy, Alembic |
| Authentication | JWT, Argon2 |
| Testing | Pytest |

## 11. Project Structure

The repository is organised into separate frontend and backend components.

```text
NetCoop-AI/
│
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── common.py
│   │   │   ├── performance.py
│   │   │   ├── infrastructure.py
│   │   │   ├── connectivity.py
│   │   │   ├── correlation.py
│   │   │   └── reporting.py
│   │   │
│   │   └── main.py
│   │
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   └── types/
│   │       └── models.ts
│   │
│   ├── package.json
│   └── index.html
│
└── README.md
```

*Note: This is a simplified representation of the main project components. Additional application modules, configuration files, migrations, and tests are present in the repository.*

## 12. Installation and Setup

### Prerequisites

- Python 3
- Node.js and npm
- Git

### Step 1 – Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

### Step 2 – Set Up the Backend

```bash
cd backend
```

Install the backend dependencies using the dependency file included in the repository.

For example:

```bash
python3 -m pip install -r requirements.txt
```

Start the backend in memory-storage demonstration mode:

```bash
NETCOOP_STORAGE_BACKEND=memory NETCOOP_AUTH_REQUIRED=false python3 -m uvicorn app.main:app --reload
```

### Step 3 – Set Up the Frontend

Open a separate terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open the local development URL displayed by Vite, normally:

```text
http://localhost:5173/
```

The frontend communicates with the backend API.

## 13. Testing

The backend test suite can be executed using:

```bash
cd backend

NETCOOP_STORAGE_BACKEND=memory NETCOOP_AUTH_REQUIRED=false python3 -m pytest -q --ignore=tests/test_postgres_integration.py
```

The test suite covers agent behaviour, protocol validation, telemetry processing, orchestration-related functionality, and error handling.

The PostgreSQL integration test is excluded from this command because it requires a separately configured PostgreSQL environment.

## 14. Expected Diagnostic Output

The system is designed to generate a unified diagnostic report containing:

| Output | Description |
|---|---|
| Diagnosis | Probable network fault |
| Affected Components | Relevant devices or network segments |
| Evidence | Supporting telemetry and agent findings |
| Confidence | Diagnostic confidence estimate |
| Recommendations | Suggested corrective actions |
| Execution Details | Agent execution status and diagnostic information |

## 15. Limitations and Future Scope

### Current Limitations

- The prototype primarily uses synthetic network telemetry.
- Diagnostic behaviour is evaluated using predefined scenarios.
- Real-world network deployment and continuous live monitoring are outside the current demonstration scope.

### Future Enhancements

- Integration with live network monitoring systems.
- Support for additional network vendors and telemetry formats.
- Advanced anomaly detection and diagnostic techniques.
- Human-in-the-loop review of diagnostic recommendations.
- Automated remediation with appropriate access controls.
- Scalable deployment across larger network environments.

## 16. Conclusion

NetCoop AI demonstrates how specialised software agents can collaborate through structured communication and centralised orchestration to perform network fault diagnosis.

By combining parallel diagnostic analysis, interoperability, evidence correlation, and unified reporting, the system provides a modular and explainable approach to identifying probable network faults.

The project establishes a foundation for further development towards intelligent, interoperable, and extensible network diagnosis systems.

---

**Project:** NetCoop AI  
**Category:** Multi-Agent AI / Network Fault Diagnosis  
**Implementation:** Python, FastAPI, React, TypeScript  
**Data Source:** Synthetic Network Telemetry
