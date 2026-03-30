# Attack Flow Agent — Product Story

| Field | Value |
|-------|-------|
| **Product** | Threat intelligence platform integration |
| **Feature** | AI-Powered Attack Flow Generation & Visualization |
| **Date** | 2026-03-26 |
| **Version** | 1.0 |
| **Status** | Draft |
| **Owner** | CTI Platform Engineering |

---

## The Problem

Security analysts at enterprise SOCs receive dozens of threat intelligence reports every day — from ISACs, commercial feeds, government advisories, and internal research. Each report describes a threat campaign: who the actors are, what malware they use, which vulnerabilities they exploit, and how the attack unfolds step by step.

Today, translating a report into an **actionable, ordered attack narrative** is entirely manual. An analyst reads a 15-page report, mentally maps the sequence of techniques, cross-references MITRE ATT&CK, and tries to communicate the attack chain to their team. This takes **30–60 minutes per report** and the result is usually a bullet list in a wiki page or a slide deck that's outdated within a week.

Meanwhile, the structured data the platform already has — indicators, malware objects, attack patterns, threat actors, relationships — sits there as individual objects. There is no way to see **how they connect into a coherent attack story**. The relationships exist, but the sequence, the causality, the "this happens, then that happens, which enables this" — that narrative is locked inside the analyst's head.

The result:
- **Detection engineers** don't know which techniques to prioritize because they can't see the flow.
- **IR teams** responding to an incident can't quickly map what they're seeing to a known campaign's playbook.
- **Leadership** can't assess exposure because there's no visual representation of how attacks actually unfold against their environment.

---

## The Vision

**Every threat intelligence report in the platform automatically generates an interactive, MITRE-compliant attack flow graph that analysts can explore, share, and use to drive defensive action.**

A single click on a report produces a visual map: Initial Access via spear phishing leads to execution via PowerShell, which drops Cobalt Strike for C2, which enables lateral movement via RDP, culminating in data exfiltration over DNS tunneling. Each node is linked to ATT&CK techniques, grounded in evidence from the report, and exportable as STIX 2.1 or MITRE Attack Flow Builder format.

This transforms the platform from a threat intel **aggregation platform** into a threat intel **understanding platform**.

---

## User Personas

### Maya — CTI Analyst

Maya processes 20+ threat reports per week. She manually extracts TTPs, maps them to ATT&CK, and writes summaries for her team. She's frustrated because:
- She spends more time formatting than analyzing.
- Her attack chain diagrams in draw.io go stale immediately.
- When a new report comes in about the same actor, she starts from scratch.

**Maya wants:** "I click a button on a report, and in two minutes I have an interactive attack flow I can share with my team."

### Raj — Detection Engineer

Raj writes Sigma and YARA rules based on Maya's analysis. He's frustrated because:
- Maya's summaries are text-heavy; he has to re-derive the technique sequence himself.
- He doesn't know which nodes in the chain have the highest detection leverage.
- There's no traceable link from a detection rule back to the intelligence that motivated it.

**Raj wants:** "I see the attack flow, click on a technique node, and understand exactly what to write a rule for — with the evidence from the report right there."

### Priya — SOC/IR Lead

Priya runs the incident response team. When a breach is detected, she needs to understand what the attacker might do next based on known campaigns. She's frustrated because:
- Threat intel is scattered across reports, IOC lists, and analyst notes.
- There's no "playbook view" that shows how a specific threat actor operates end-to-end.
- She can't quickly brief her team on what to look for at each stage.

**Priya wants:** "I pull up the attack flow for APT29 and walk my team through the chain step by step during our incident call."

### Arjun — Platform Admin

Arjun manages the platform deployment. He's cautious because:
- LLM-powered features have cost implications (token usage per generation).
- TLP:RED reports must never be sent to external AI services.
- He needs audit trails for everything the system generates.

**Arjun wants:** "I configure which LLM provider to use, set rate limits per tenant, and see exactly how many tokens each generation consumed."

---

## Epics & User Stories

### Epic 1: Attack Flow Generation (Backend Agent)

> *As a CTI analyst, I want the platform to automatically generate a structured attack flow from any threat intelligence report, so that I don't have to manually extract and sequence TTPs.*

#### Story 1.1: Generate Attack Flow from Report (On-Demand)

**As** a the platform user viewing a report detail page,
**I want** to click a "Generate Attack Flow" button,
**So that** the system produces an interactive attack flow graph for that report.

**Acceptance Criteria:**
- [ ] A "Generate Attack Flow" button is visible on the report detail page when no flow exists.
- [ ] Clicking the button triggers an asynchronous job and shows a progress indicator.
- [ ] Progress stages are communicated: "Fetching report data", "Assembling narrative", "Analyzing techniques", "Building graph", "Complete".
- [ ] When generation completes (target: under 3 minutes for typical reports), the attack flow graph renders automatically.
- [ ] If the report has insufficient content for a meaningful flow, the system shows an actionable message explaining why.
- [ ] Generation works for reports with and without a `description` field (narrative assembly handles both cases).

#### Story 1.2: Narrative Assembly from the platform Report Objects

**As** the attack flow agent,
**I need** to assemble a coherent text narrative from a the platform report's structured data (name, description, related SDOs),
**So that** the `ttp_chainer` pipeline receives quality input even when reports lack a prose description.

**Acceptance Criteria:**
- [ ] When `report.description` exists, it is used as the primary narrative body.
- [ ] When `report.description` is missing, the system assembles text from: report name, report type, publication date, and summaries of all referenced SDOs (indicators, malware, tools, attack-patterns, threat-actors, vulnerabilities).
- [ ] Referenced SDOs are sorted deterministically (by type, then name) for reproducible output.
- [ ] ATT&CK technique IDs from existing `attack-pattern` objects are included as extraction hints.
- [ ] Assembled narrative respects a configurable token budget (default: ~25K tokens / 100K chars).
- [ ] If the narrative is too thin to produce a meaningful flow (e.g., report with only 2 indicators and no context), the system returns error code `REPORT_CONTENT_INSUFFICIENT` with guidance.

#### Story 1.3: TLP / Marking Enforcement

**As** a platform admin,
**I want** the attack flow agent to respect TLP markings on reports,
**So that** TLP:RED content is never sent to external LLM providers.

**Acceptance Criteria:**
- [ ] Before calling any LLM, the agent checks the report's `object_marking_refs`.
- [ ] TLP:RED and TLP:AMBER+STRICT reports are blocked from external LLM APIs unless a local/on-premise model is configured.
- [ ] If blocked, the system returns a clear error: "This report's TLP marking prevents external AI processing. Configure a local model to generate attack flows for restricted reports."
- [ ] TLP markings from the source report propagate to all generated artifacts (STIX bundle, AFB, React Flow metadata).

#### Story 1.4: Idempotency and Regeneration

**As** a CTI analyst,
**I want** to regenerate an attack flow when a report is updated,
**So that** the flow always reflects the latest intelligence.

**Acceptance Criteria:**
- [ ] Each generation is keyed by `(report_id, report.modified)`.
- [ ] If a flow already exists for the current report revision, the system returns the cached result instantly (no LLM call).
- [ ] A "Regenerate" button forces a new generation, superseding the previous flow.
- [ ] The previous flow version is archived (not deleted) for audit purposes.
- [ ] The UI shows when the flow was last generated and whether the report has been updated since.

#### Story 1.5: Job Observability

**As** a platform admin,
**I want** to see metadata for every attack flow generation job,
**So that** I can monitor costs, performance, and troubleshoot failures.

**Acceptance Criteria:**
- [ ] Every job records: job ID, report ID, tenant ID, requesting user, start/end timestamps, status, LLM model used, total tokens consumed, number of nodes/edges produced, and any errors.
- [ ] Job metadata is queryable via API (`GET /jobs/{job_id}`).
- [ ] Failed jobs include structured error codes and human-readable messages.
- [ ] Token usage is aggregated per tenant for cost tracking.

---

### Epic 2: Attack Flow Visualization (Frontend)

> *As a CTI analyst, I want to see the attack flow as an interactive graph inside the platform UI, so that I can explore the attack chain visually without leaving the platform.*

#### Story 2.1: Attack Flow Tab on Report Detail Page

**As** a the platform user,
**I want** an "Attack Flow" tab on the report detail page,
**So that** I can view the generated flow alongside the report's other data (IOCs, related objects, history).

**Acceptance Criteria:**
- [ ] A new "Attack Flow" tab appears on all report detail pages.
- [ ] If no flow exists, the tab shows an empty state with a "Generate" call-to-action.
- [ ] If a flow exists, the tab renders the interactive graph.
- [ ] The tab lazy-loads (React Flow and Dagre are code-split, not bundled into the main app chunk).
- [ ] Tab state persists during navigation (switching to IOCs tab and back doesn't re-fetch).

#### Story 2.2: Interactive Graph Visualization

**As** a CTI analyst,
**I want** to pan, zoom, and explore the attack flow graph,
**So that** I can understand the full attack chain and drill into specific techniques.

**Acceptance Criteria:**
- [ ] The graph renders using React Flow with automatic Dagre hierarchical layout.
- [ ] Nodes are visually typed and color-coded: Action (ATT&CK technique), Malware, Tool, Asset, Infrastructure, Vulnerability, Condition (AND/OR operators).
- [ ] Edges show relationship labels (e.g., "leads-to", "uses", "exploits").
- [ ] Panning and zooming are smooth; a "Fit View" button resets to show the full graph.
- [ ] Minimap is available for large flows.
- [ ] The graph supports both light and dark themes (matching the platform's theme setting).

#### Story 2.3: Node Detail Panel

**As** a CTI analyst,
**I want** to click on any node in the attack flow to see its details,
**So that** I can understand the evidence, technique, and context without switching views.

**Acceptance Criteria:**
- [ ] Clicking a node opens a slide-in detail panel on the right side.
- [ ] The panel shows: node name, type, description, confidence level, and source evidence (the excerpt from the report that supports this node).
- [ ] For ATT&CK technique nodes: MITRE technique ID, tactic name, and a link to the ATT&CK page.
- [ ] For malware/tool nodes: associated indicators or hashes if available in the report.
- [ ] A "Copy" button copies the node's details as formatted text.
- [ ] The panel closes on clicking outside or pressing Escape.

#### Story 2.4: Export Attack Flow

**As** a CTI analyst,
**I want** to export the attack flow in multiple formats,
**So that** I can share it with external teams or use it in other tools.

**Acceptance Criteria:**
- [ ] An "Export" dropdown offers: PNG (image), STIX 2.1 Bundle (JSON), MITRE AFB (.afb), and FlowViz JSON.
- [ ] PNG export captures the full graph at high resolution, regardless of current zoom level.
- [ ] STIX export produces a valid STIX 2.1 bundle with attack-pattern, relationship, and extension objects.
- [ ] AFB export produces a file loadable in MITRE's Attack Flow Builder tool.
- [ ] All exports include metadata: source report name, generation timestamp, and tenant information.

---

### Epic 3: the platform Platform Integration

> *As the platform, I need the attack flow agent to integrate seamlessly with existing infrastructure — authentication, storage, event bus, and multi-tenancy.*

#### Story 3.1: the platform Backend Proxy Layer

**As** the platform,
**I need** a thin proxy in the platform backend that routes attack flow requests to the agent service,
**So that** the agent is never exposed directly to the internet and all requests go through the platform auth.

**Acceptance Criteria:**
- [ ] the platform backend exposes: `POST /api/attack-flow/generate`, `GET /api/attack-flow/jobs/{id}`, `GET /api/attack-flow/report/{id}`, `GET /api/attack-flow/{id}/export/{format}`.
- [ ] All endpoints validate the user's HMAC signature (same auth as existing the platform APIs).
- [ ] Requests are forwarded to the agent service over the internal network (no external exposure).
- [ ] RBAC: only users with read permission on the report can trigger generation or view its flow.
- [ ] Rate limiting: configurable per-tenant limit (default: 20 generations/hour).

#### Story 3.2: Agent ↔ the platform Data Exchange

**As** the attack flow agent,
**I need** to fetch report data from the platform and store results back,
**So that** attack flows are first-class objects in the platform data model.

**Acceptance Criteria:**
- [ ] Agent fetches report details via `GET /ingestion/threat-data/report/{id}/basic/`.
- [ ] Agent fetches related SDOs via `GET /ingestion/threat-data/report/{id}/relations/`.
- [ ] Agent stores generated STIX objects via `POST /ingestion/ingestion-api/ingest_bundle/` with a dedicated source and collection.
- [ ] Agent notifies the platform of completion via callback URL, passing `react_flow_data` for frontend rendering.
- [ ] The generated attack flow is linked to the source report via a STIX `relationship` (type: `derived-from`).

#### Story 3.3: Event-Driven Generation

**As** a the platform admin,
**I want** to optionally auto-generate attack flows when reports are published or updated,
**So that** flows stay current without manual intervention.

**Acceptance Criteria:**
- [ ] A tenant-level setting controls whether event-driven generation is enabled (default: off).
- [ ] When enabled, a `report.published` or `report.updated` event triggers generation for reports that meet a minimum SDO threshold (configurable, default: 5 related objects).
- [ ] Duplicate suppression: if a flow already exists for the current report revision, the event is silently skipped.
- [ ] Event-driven jobs have lower priority than on-demand (user-triggered) jobs in the queue.

#### Story 3.4: Multi-Tenant Isolation

**As** a platform admin managing multiple tenants,
**I want** complete data isolation between tenants,
**So that** one tenant's reports, flows, and LLM calls never leak to another.

**Acceptance Criteria:**
- [ ] Every agent request includes `tenant_id`; all the platform API calls are scoped to that tenant.
- [ ] LLM prompts include no cross-tenant context (no shared memory or cache between tenants).
- [ ] Stored artifacts (STIX bundles, AFB files, React Flow JSON) are partitioned by tenant.
- [ ] Rate limits and token budgets are enforced per tenant independently.
- [ ] Audit logs include tenant context for every operation.

---

### Epic 4: Production Readiness

> *As the engineering team, we need the attack flow agent to be reliable, observable, and maintainable in production.*

#### Story 4.1: Error Handling and Graceful Degradation

**As** a user,
**I want** clear, actionable error messages when attack flow generation fails,
**So that** I know what went wrong and what to do about it.

**Acceptance Criteria:**
- [ ] Structured error codes for all failure modes: `REPORT_NOT_FOUND`, `REPORT_CONTENT_INSUFFICIENT`, `TLP_RESTRICTED`, `LLM_TIMEOUT`, `LLM_RATE_LIMITED`, `PIPELINE_VALIDATION_FAILED`, `INTERNAL_ERROR`.
- [ ] Each error includes a human-readable message and, where applicable, a suggested action.
- [ ] Partial failures (e.g., graph built but export failed) are handled: the flow is saved and the error is surfaced alongside it.
- [ ] LLM timeouts trigger up to 2 retries with exponential backoff before failing.

#### Story 4.2: Configurable LLM Provider

**As** a platform admin,
**I want** to choose which LLM provider the agent uses,
**So that** I can balance cost, speed, and data residency requirements.

**Acceptance Criteria:**
- [ ] Supported providers: OpenAI, Anthropic, Azure OpenAI, and Ollama (local).
- [ ] Provider and model are configured via environment variables (not hardcoded).
- [ ] LiteLLM abstraction allows switching providers without code changes.
- [ ] For TLP:RED reports, the system automatically falls back to a local model if the primary provider is external.
- [ ] Per-tenant model override is supported (e.g., Tenant A uses GPT-4o, Tenant B uses Claude).

#### Story 4.3: Observability and Monitoring

**As** an SRE,
**I want** structured logs, metrics, and health checks for the attack flow agent,
**So that** I can monitor its health and troubleshoot issues.

**Acceptance Criteria:**
- [ ] All log entries include: trace ID, job ID, tenant ID, timestamp, and severity.
- [ ] Key metrics are exposed (Prometheus-compatible or structured logs): generation latency (p50/p95/p99), success/failure rate, token usage per job, queue depth, active jobs.
- [ ] Health endpoint (`GET /health`) returns service status, current job count, and dependency connectivity (the platform API reachable, LLM provider reachable).
- [ ] Alerts can be configured for: generation failure rate > 10%, p95 latency > 5 minutes, queue depth > 50.

---

### Epic 5: Advanced Features (Future)

> *These stories are planned for subsequent phases and are included for roadmap visibility.*

#### Story 5.1: Story Mode (Step-Through Playback)

**As** a SOC/IR lead,
**I want** to walk through the attack flow step by step,
**So that** I can brief my team on the attack chain during an incident call.

**Acceptance Criteria:**
- [ ] A "Story Mode" button activates a guided walkthrough.
- [ ] Each step highlights one node (or group), dims the rest, and shows a narrative description.
- [ ] Forward/backward navigation with keyboard arrows.
- [ ] Auto-play option with configurable speed.
- [ ] Story Mode works in full-screen for presentation use.

#### Story 5.2: Attack Flow → Detection Rules (Agent 2)

**As** a detection engineer,
**I want** to generate Sigma, YARA, and Suricata rules directly from attack flow nodes,
**So that** I can quickly create detection coverage for the techniques in a campaign.

**Acceptance Criteria:**
- [ ] Clicking a node shows a "Generate Detection Rule" option.
- [ ] Rules are generated per-node with traceability back to the attack flow.
- [ ] Supported formats: Sigma (SIEM), YARA (malware), Suricata (network).
- [ ] Bulk generation: "Generate rules for all nodes" produces a downloadable rule pack.

#### Story 5.3: IOB Repository (Threat Actor Playbooks)

**As** a CTI analyst,
**I want** to see all attack flows clustered by threat actor,
**So that** I can build a behavioral profile (IOBs) for each adversary over time.

**Acceptance Criteria:**
- [ ] Attack flows are tagged with associated threat actors from the source report.
- [ ] A "Threat Actor Playbooks" view shows all flows grouped by actor.
- [ ] Common sub-patterns across flows are highlighted (e.g., "APT29 always starts with spear phishing → OAuth token theft").
- [ ] Flows can be compared side-by-side.

#### Story 5.4: AFB Import (Pre-Built Flows)

**As** a CTI analyst,
**I want** to import MITRE's pre-built attack flow files (.afb) into the platform,
**So that** I can use the community's existing attack flow library alongside AI-generated ones.

**Acceptance Criteria:**
- [ ] Upload `.afb` file via the UI.
- [ ] File is parsed, converted to React Flow format, and rendered in the standard viewer.
- [ ] Imported flows are linked to relevant reports or threat actors in the platform.
- [ ] MITRE's 34+ published attack flows can be batch-imported.

---

## Technical Context

### What Already Exists

| Component | Location | Role |
|-----------|----------|------|
| `ttp_chainer` | `/Downloads/ttp_chainer/` | AI pipeline: text → STIX + AFB (DSPy + LiteLLM, 6 parallel extractors, graph judge validation) |
| FlowViz | `/flowviz/` | Open-source React + Express attack flow visualizer (React Flow, Dagre layout, node components) |
| `cftr_copilot_agent` | `/Downloads/cftr_copilot_agent/` | Reference LangGraph + FastAPI agent architecture already used in the platform |
| Platform API connector (reference) | `/Downloads/platform_api_connector/` | HMAC auth, report endpoints, STIX ingestion patterns |

### What Gets Built

| Component | Technology | Description |
|-----------|-----------|-------------|
| Attack Flow Agent Service | Python, FastAPI, LangGraph | Standalone microservice wrapping `ttp_chainer` with the platform integration |
| the platform Backend Proxy | Django (the platform backend) | Thin proxy layer adding auth, rate limiting, audit |
| Attack Flow UI Module | React, TypeScript, React Flow, Dagre | New `features/attack-flow/` module in the platform frontend |
| the platform API Client | Python, httpx | HMAC-authenticated client for fetching reports and storing results |

### Architecture (Simplified)

```
┌────────────────┐     ┌──────────────┐     ┌───────────────────┐     ┌─────────┐
│  the platform Frontend  │────►│ the platform Backend  │────►│ Attack Flow Agent │────►│   LLM   │
│  (React)        │◄────│ (Django)      │◄────│ (FastAPI)         │◄────│ (GPT-4o)│
│                 │     │              │     │                   │     └─────────┘
│ Attack Flow Tab │     │ /api/    │     │ /api/v1/          │
│ React Flow      │     │ attack-flow/ │     │ attack-flow/      │
│ Node Components │     │              │     │                   │
└────────────────┘     └──────┬───────┘     └─────────┬─────────┘
                              │                       │
                       ┌──────▼───────┐        ┌──────▼──────┐
                       │ the platform Database │        │ ttp_chainer │
                       │ (Reports,     │        │ Pipeline    │
                       │  Flows, SDOs) │        │ (DSPy)      │
                       └──────────────┘        └─────────────┘
```

---

## Delivery Phases

### Phase 1: Core Pipeline (Weeks 1–3)

**Goal:** A working agent that takes a report ID and produces an attack flow.

| Story | Description | Estimate |
|-------|-------------|----------|
| 1.1 | Generate Attack Flow from Report (On-Demand) | 5 days |
| 1.2 | Narrative Assembly from the platform Report Objects | 3 days |
| 1.3 | TLP / Marking Enforcement | 2 days |
| 1.5 | Job Observability | 2 days |
| 3.2 | Agent ↔ the platform Data Exchange | 3 days |

**Deliverable:** FastAPI service deployed alongside the platform, callable via internal API. Returns STIX bundle + AFB + React Flow JSON.

### Phase 2: UI Integration (Weeks 4–6)

**Goal:** Attack flows are visible and interactive inside the platform.

| Story | Description | Estimate |
|-------|-------------|----------|
| 2.1 | Attack Flow Tab on Report Detail Page | 3 days |
| 2.2 | Interactive Graph Visualization | 5 days |
| 2.3 | Node Detail Panel | 3 days |
| 2.4 | Export Attack Flow | 2 days |
| 3.1 | the platform Backend Proxy Layer | 2 days |

**Deliverable:** Users can generate and explore attack flows entirely within the platform UI.

### Phase 3: Production Hardening (Weeks 7–8)

**Goal:** The feature is reliable, secure, and observable in production.

| Story | Description | Estimate |
|-------|-------------|----------|
| 1.4 | Idempotency and Regeneration | 2 days |
| 3.3 | Event-Driven Generation | 3 days |
| 3.4 | Multi-Tenant Isolation | 2 days |
| 4.1 | Error Handling and Graceful Degradation | 2 days |
| 4.2 | Configurable LLM Provider | 1 day |
| 4.3 | Observability and Monitoring | 2 days |

**Deliverable:** Feature is production-ready with monitoring, rate limiting, and TLP enforcement.

### Phase 4: Advanced Features (Weeks 9+)

**Goal:** Differentiated capabilities that extend the platform's value.

| Story | Description | Estimate |
|-------|-------------|----------|
| 5.1 | Story Mode (Step-Through Playback) | 5 days |
| 5.2 | Attack Flow → Detection Rules (Agent 2) | 10 days |
| 5.3 | IOB Repository (Threat Actor Playbooks) | 8 days |
| 5.4 | AFB Import (Pre-Built Flows) | 3 days |

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Generation latency** (p95) | < 3 minutes | Agent job metadata |
| **Generation success rate** | > 90% for reports with 5+ SDOs | Job status tracking |
| **Analyst time saved** | 30+ minutes per report | User survey / before-after comparison |
| **Feature adoption** | 60% of active analysts use within first month | Tab click tracking |
| **Graph accuracy** (manual review) | > 80% of nodes correctly mapped to ATT&CK | Quarterly quality audit |
| **Export usage** | 40% of generated flows are exported at least once | Export button tracking |
| **Cost per generation** | < $0.50 average (GPT-4o pricing) | Token usage × rate |
| **Uptime** | 99.5% | Health check monitoring |

---

## Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Reports without `description` produce low-quality flows | Medium | High | Narrative assembly (Story 1.2) synthesizes context from SDOs; quality gate rejects thin reports |
| TLP:RED content sent to external LLM | Critical | Low | Mandatory TLP check (Story 1.3) with local model fallback |
| LLM hallucinates techniques not in the report | Medium | Medium | Graph judge validation loop (up to 10 iterations); evidence grounding; confidence scores |
| Long processing time frustrates users | Medium | Medium | Async job pattern with progress updates; WebSocket push on completion |
| Large STIX bundles exceed LLM token limits | Medium | Medium | Deterministic SDO sorting + truncation with token budget |
| React Flow bundle size impacts the platform load time | Low | Low | Code-split the attack flow tab; lazy-load on first visit |
| Multi-tenant data leakage via LLM context | Critical | Low | Tenant-scoped prompts; no shared LLM memory; per-tenant API credentials |
| the platform API rate limits block agent data fetching | Medium | Low | Internal service token with elevated rate limits; pagination for large relation sets |

---

## Dependencies

| Dependency | Owner | Status |
|------------|-------|--------|
| the platform backend proxy endpoints (Django) | the platform Backend Team | Needs implementation |
| the platform WebSocket infrastructure (for real-time updates) | the platform Frontend Team | Exists for other features; needs new event type |
| the platform report detail page tab system | the platform Frontend Team | Exists; adding one tab |
| `ttp_chainer` pipeline | CTI Platform / AI Team | Exists; needs packaging as importable module |
| LLM API access (OpenAI / Anthropic / Ollama) | Platform Infra | Exists for other agents |
| S3 or equivalent blob storage | Platform Infra | Exists |
| the platform v3 API (report + threat data endpoints) | the platform Backend Team | Exists |

---

## Open Questions

| # | Question | Decision Needed By |
|---|----------|-------------------|
| 1 | Should event-driven generation be opt-in or opt-out per tenant? | Phase 3 start |
| 2 | What is the maximum number of SDOs to include in narrative assembly before truncation? | Phase 1 start |
| 3 | Should attack flows be a new STIX custom object (`x-attack-flow`) or stored as a a platform-internal entity? | Phase 1 start |
| 4 | Do we need to support editing attack flows in the UI (drag nodes, add/remove), or is it view-only + regenerate? | Phase 2 start |
| 5 | What is the per-tenant LLM token budget? Flat or tiered by plan? | Phase 3 start |
| 6 | Should exported STIX bundles include the generated attack flow objects, or just the source report's objects? | Phase 2 start |
| 7 | Is there a need for a "Compare Flows" feature (diff two versions of the same report's flow)? | Phase 4 planning |
