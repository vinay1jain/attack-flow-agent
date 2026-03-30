# The Bigger Picture: Universal Cybersecurity Flow Platform

| Field | Value |
|-------|-------|
| **Type** | Vision & Brainstorm Document |
| **Date** | 2026-03-26 |
| **Status** | Exploratory |
| **Relation to current plan** | Add-on / parallel track. The CTIX Attack Flow Agent (PRODUCT_STORY.md) remains unchanged and ships first. This document explores where it can grow. |

---

## The Core Insight

The current plan generates attack flows from **threat intelligence reports** inside CTIX. But the underlying problem — "I have cybersecurity data and I need to understand the story, see the flow, and take action" — is **not limited to reports**.

Every cybersecurity artifact tells a partial story:

- An **incident** is a story of what happened in your environment.
- A **report** is a story of what happened somewhere else.
- A **cluster of IOCs** is a fragment of a story — the breadcrumbs.
- A **vulnerability advisory** is a story of what *could* happen.
- A **set of alerts** from a SIEM is a story trying to assemble itself.
- A **malware sandbox result** is a story of what something *does*.

Today, the human analyst is the one stitching these fragments into a coherent narrative, deciding what matters, figuring out mitigations, and then manually jumping between 6 different tools to take action.

**What if one platform could take any of these inputs, generate the flow, and let you act on it — all from the same canvas?**

---

## The Vision: Flow → Understand → Act

```
                          ┌─────────────────────────────────────┐
                          │                                     │
      ANY INPUT ─────────►│     FLOW GENERATION ENGINE          │
                          │     (AI-powered, multi-model)       │
                          │                                     │
                          └──────────────┬──────────────────────┘
                                         │
                                         ▼
                          ┌─────────────────────────────────────┐
                          │                                     │
                          │     INTERACTIVE FLOW CANVAS          │
                          │     (Visualize, Explore, Annotate)  │
                          │                                     │
                          └──────────────┬──────────────────────┘
                                         │
                                         ▼
                          ┌─────────────────────────────────────┐
                          │                                     │
                          │     ACTION LAYER                     │
                          │     (Mitigate, Detect, Respond,     │
                          │      Deploy, Communicate)           │
                          │                                     │
                          └─────────────────────────────────────┘
```

Three layers, one platform:

1. **Flow Generation** — Takes any cybersecurity input and produces a structured, ordered flow graph.
2. **Flow Canvas** — A universal, interactive visualization where you can explore the attack/incident chain.
3. **Action Layer** — From any node in the flow, take direct action: see mitigations, generate detection rules, push blocks to your firewall, create tickets, isolate hosts.

---

## Layer 1: Universal Input → Flow Generation

### What can be fed in?

| Input Type | Example | What the flow shows |
|------------|---------|-------------------|
| **Threat Intel Report** | APT29 campaign analysis PDF | Attack chain: Initial Access → Execution → C2 → Exfil |
| **Incident Summary** | "At 3am, user John's account was compromised via phishing..." | Timeline: Phishing → Credential Theft → Lateral Movement → Data Access |
| **IOC Collection** | 15 IPs, 3 domains, 2 hashes from a campaign | Inferred relationships: C2 servers → malware → targets → techniques |
| **SIEM Alert Cluster** | 47 correlated alerts from Splunk over 6 hours | Alert chain: What happened, in what order, across which assets |
| **Vulnerability Advisory** | CVE-2026-XXXX with CVSS 9.8 | Exploitation chain: How this vuln is exploited → what it enables → impact |
| **Malware Sandbox Report** | Cuckoo/Any.run analysis of ransomware.exe | Behavior flow: Drop → Execute → Privilege Escalation → Encrypt → Ransom Note |
| **PCAP / Network Log Summary** | DNS tunneling + lateral movement evidence | Network flow: Internal → DNS queries → External C2 → Data exfiltration |
| **Threat Actor Profile** | APT28 known behaviors | Composite playbook: All known TTPs, tools, and targets assembled into a master flow |
| **Email / Phishing Analysis** | Suspicious email with attachment | Kill chain: Email received → Attachment opened → Macro executed → Payload downloaded |
| **Cloud Security Event** | AWS CloudTrail anomaly cluster | Cloud attack flow: Compromised key → S3 enumeration → Data download → Trail deletion |
| **Paste / Free Text** | Analyst's raw notes from investigation | Best-effort flow extraction from unstructured notes |
| **STIX Bundle** | Any STIX 2.1 bundle | Object relationship graph + inferred attack flow |

### Key idea: The AI doesn't just extract — it **infers**

For a report, the attack chain is usually described explicitly. But for an IOC cluster or alert group, the AI has to **infer** the likely chain:
- "These 3 IPs are known C2 for Cobalt Strike" + "These 2 hashes are Cobalt Strike beacons" + "This domain was used in a spear phishing campaign" → The AI infers the probable attack chain: Phishing → Beacon Drop → C2 Communication.

This is where the LLM's world knowledge of ATT&CK, threat actor behaviors, and malware families becomes the reasoning engine — not just an extractor, but an **inference engine** that connects dots.

### Input Methods

| Method | Description |
|--------|-------------|
| **Paste** | Paste text, JSON, or CSV directly into the platform |
| **Upload** | Upload PDF, DOCX, TXT, STIX JSON, AFB, PCAP summary, sandbox JSON |
| **URL** | Provide a URL to a threat report, advisory, or blog post |
| **API Push** | Other tools (SIEM, SOAR, EDR) push data to the platform via API |
| **Pull from CTIX** | Select a report, incident, or object collection from CTIX |
| **Pull from CFTR** | Import an incident with its evidence from CFTR |
| **Pull from SIEM** | Connect to Splunk/QRadar/Sentinel, pull alert clusters |
| **Email Forward** | Forward a phishing email or advisory to a dedicated inbox |

---

## Layer 2: The Flow Canvas

### Beyond attack flows — a universal flow vocabulary

The current plan focuses on **attack flows** (MITRE Attack Flow specification). The bigger platform supports multiple flow types:

| Flow Type | Description | Node Types |
|-----------|-------------|------------|
| **Attack Flow** | How an adversary executes a campaign (offensive) | Actions, Assets, Conditions, Tools, Malware, Infrastructure |
| **Incident Timeline** | What happened during a specific incident (forensic) | Events, Assets, Users, Systems, Timestamps, Evidence |
| **Kill Chain Map** | Maps evidence to Lockheed Martin or MITRE kill chain phases | Phase nodes, Evidence nodes, Gap indicators |
| **Vulnerability Exploitation Chain** | How a CVE can be/was exploited in context | Vuln, Pre-conditions, Exploit steps, Impact, Affected systems |
| **Detection Coverage Map** | Overlays detection rules on attack flow — where do you have coverage? | Technique nodes + Detection rule nodes (green=covered, red=gap) |
| **Response Playbook** | Recommended response actions mapped to attack flow nodes | Attack nodes → Response action nodes → Tool nodes |
| **Threat Actor Composite** | Aggregated behaviors of an actor across multiple campaigns | Composite technique nodes with frequency, recency, confidence |

### Canvas capabilities

| Capability | Description |
|------------|-------------|
| **Auto-layout** | Dagre hierarchical layout (same as current plan), plus timeline view, radial view |
| **Manual editing** | Drag nodes, add/remove connections, annotate with notes (optional, Phase 4+) |
| **Overlays** | Toggle layers: Show/hide mitigations, detection coverage, response actions |
| **Comparison** | Side-by-side: Compare two flows (e.g., what changed in APT29's playbook) |
| **Time scrubbing** | For incident timelines: scrub through time to see the attack unfold |
| **Collaboration** | Multiple analysts view/annotate the same flow in real time |
| **Bookmarks** | Save specific views/zoom levels for presentation or sharing |
| **Theming** | Match org branding; dark/light mode; print-friendly mode |

---

## Layer 3: Action from Every Node

This is where the platform becomes **operational**, not just analytical. Every node in a flow is an action surface.

### Node Context Menu: "What can I do here?"

```
┌─────────────────────────────────────────────────────────┐
│  Node: Spear Phishing (T1566.001)                       │
│  Tactic: Initial Access                                  │
│  Confidence: High                                        │
│  Evidence: "Threat actor sent targeted emails with..."   │
│  ─────────────────────────────────────────────────────── │
│                                                          │
│  UNDERSTAND                                              │
│  ├── View MITRE ATT&CK page                             │
│  ├── See related threat actors who use this technique    │
│  ├── View historical incidents with this technique       │
│  └── Read source evidence from report                    │
│                                                          │
│  DETECT                                                  │
│  ├── Generate Sigma rule for this technique              │
│  ├── Generate YARA rule (if file-based)                  │
│  ├── Generate Suricata/Snort rule (if network-based)     │
│  ├── Check existing detection coverage                   │
│  └── Deploy rule to → [Splunk] [QRadar] [Sentinel]      │
│                                                          │
│  MITIGATE                                                │
│  ├── MITRE ATT&CK mitigations (M1049: Antivirus, ...)   │
│  ├── Recommended configurations                          │
│  ├── NIST CSF mappings                                   │
│  └── CIS Benchmark recommendations                       │
│                                                          │
│  RESPOND                                                 │
│  ├── Block sender domain → [Proofpoint] [Mimecast]      │
│  ├── Block attachment hash → [CrowdStrike] [Defender]    │
│  ├── Send awareness alert → [Slack] [Teams] [Email]     │
│  ├── Create investigation ticket → [ServiceNow] [Jira]  │
│  └── Run containment playbook → [CSOL] [XSOAR]          │
│                                                          │
│  HUNT                                                    │
│  ├── Search for this technique in logs → [Splunk query]  │
│  ├── Search for these IOCs → [CTIX lookup]               │
│  ├── Scan endpoints → [CrowdStrike RTR] [Defender Live]  │
│  └── Query email gateway → [O365] [Google Workspace]     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Action Categories

| Category | What it does | Integrations |
|----------|-------------|-------------|
| **Understand** | Enrich context for the node: ATT&CK details, threat intel, past incidents | MITRE ATT&CK, CTIX, VirusTotal, Shodan, CTI feeds |
| **Detect** | Generate or deploy detection rules targeting this technique | Sigma → Splunk/QRadar/Sentinel; YARA → EDR; Suricata → NDR |
| **Mitigate** | Show recommended mitigations, configurations, and controls | MITRE mitigations, NIST CSF, CIS Benchmarks, vendor hardening guides |
| **Respond** | Take direct containment/remediation actions | SOAR (CSOL, XSOAR), EDR (CrowdStrike, Defender), Email (Proofpoint), IAM (Okta, AD) |
| **Hunt** | Proactively search for evidence of this technique in your environment | SIEM queries, EDR live response, network traffic analysis |
| **Communicate** | Generate reports, briefings, or notifications from the flow | Email, Slack, Teams, PDF export, executive summary generation |

### The integration model: Connectors

Each "action" button maps to a **connector** — the same concept CTIX and CSOL already use:

```
┌──────────────────────────────────────────────────────────────────┐
│                    CONNECTOR FRAMEWORK                            │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  SIEM        │  │  EDR         │  │  Email       │             │
│  │  ─────────── │  │  ─────────── │  │  ─────────── │             │
│  │  Splunk      │  │  CrowdStrike │  │  Proofpoint  │             │
│  │  QRadar      │  │  SentinelOne │  │  Mimecast    │             │
│  │  Sentinel    │  │  Defender    │  │  O365        │             │
│  │  Elastic     │  │  Carbon Black│  │  Google WS   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Firewall    │  │  SOAR        │  │  Ticketing   │             │
│  │  ─────────── │  │  ─────────── │  │  ─────────── │             │
│  │  Palo Alto   │  │  CSOL        │  │  ServiceNow  │             │
│  │  Fortinet    │  │  XSOAR       │  │  Jira        │             │
│  │  Check Point │  │  Swimlane    │  │  PagerDuty   │             │
│  │  Cisco       │  │  Tines       │  │  Opsgenie    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Cloud       │  │  IAM         │  │  Vuln Mgmt   │             │
│  │  ─────────── │  │  ─────────── │  │  ─────────── │             │
│  │  AWS         │  │  Okta        │  │  Tenable     │             │
│  │  Azure       │  │  Azure AD    │  │  Qualys      │             │
│  │  GCP         │  │  CyberArk    │  │  Rapid7      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└──────────────────────────────────────────────────────────────────┘
```

This is not greenfield — CTIX and CSOL already have 200+ connectors. The platform reuses them, just surfaces them **in the context of a flow node** rather than a standalone action.

---

## What's Different From What Exists in the Market?

### Current landscape

| Tool | What it does | Gap |
|------|-------------|-----|
| **MITRE Attack Flow Builder** | Manual drag-and-drop flow creation | No AI, no automation, no actions, no integrations |
| **FlowViz** | AI-generated flows from URLs/text | Single prompt, no actions, no integrations, browser-only storage |
| **SIEM (Splunk, etc.)** | Alert correlation, dashboards | No attack flow visualization, no technique-level view |
| **SOAR (XSOAR, CSOL)** | Playbook automation | Playbooks are pre-built, not generated from intel; no visual flow |
| **TIP (CTIX, MISP, ThreatConnect)** | Intel aggregation and sharing | Has objects and relationships, but no sequential flow view |
| **Mandiant Advantage** | Threat intel with ATT&CK mapping | Static technique heatmaps, not interactive ordered flows |
| **AttackIQ / SafeBreach** | Breach and attack simulation | Tests known techniques, doesn't analyze your specific incidents |

### What's missing everywhere

Nobody does **Input → Flow → Action** as a single, unified experience:
- Intel platforms stop at aggregation.
- Visualization tools stop at pretty pictures.
- SOAR tools start from pre-built playbooks, not from intelligence.
- SIEM tools show alerts, not attack narratives.

**The gap is the connective tissue between understanding and action.**

---

## Scenarios: How People Would Use This

### Scenario 1: "A new APT report just dropped"

```
Maya (CTI Analyst):
1. Pastes the report URL into the platform
2. In 2 minutes, sees the full attack flow: Spear Phishing → Macro Exec → 
   Cobalt Strike → LSASS Dump → Lateral Movement → DC Compromise → Exfil
3. Clicks on "LSASS Dump (T1003.001)" node → sees MITRE mitigations
4. Clicks "Check Detection Coverage" → sees her Splunk has no rule for this
5. Clicks "Generate Sigma Rule" → rule appears → clicks "Deploy to Splunk"
6. Clicks "Send Briefing" → auto-generated summary goes to #threat-intel Slack
7. Total time: 8 minutes. Previously: 2 hours across 4 tools.
```

### Scenario 2: "We have an active incident"

```
Priya (IR Lead):
1. Pulls the incident from CFTR (incident ID: INC-2026-0847)
2. Platform ingests: 23 alerts, 5 compromised hosts, 12 IOCs
3. Generates an incident timeline flow showing the attack chain as it unfolded
4. Team sees: Phishing email (9:03am) → User clicked (9:07am) → PowerShell 
   execution (9:08am) → Cobalt Strike beacon (9:12am) → Lateral movement to 
   file server (9:45am) → Data staging (10:30am) → [CURRENT: Exfil attempt]
5. Clicks on "Lateral Movement" node → "Hunt: Search for RDP sessions in 
   last 24h" → launches Splunk query → finds 2 more compromised hosts
6. Clicks on "Exfil attempt" node → "Respond: Block destination IP" → 
   pushes block rule to Palo Alto firewall
7. Clicks on root cause "Phishing email" node → "Respond: Block sender 
   domain" → pushes to Proofpoint
8. Entire response orchestrated from a single visual canvas.
```

### Scenario 3: "What's our exposure to this CVE?"

```
Raj (Detection Engineer):
1. Pastes CVE-2026-XXXX advisory into the platform
2. Platform generates exploitation chain: Vulnerable service exposed → 
   Exploit sent → RCE achieved → Web shell dropped → Persistence via 
   scheduled task → Lateral movement
3. For each node, sees: "You have detection" (green) or "No detection" (red)
4. Clicks on all red nodes → "Bulk Generate Detection Rules" → gets a 
   Sigma rule pack
5. Reviews, tunes, deploys to Sentinel with one click
6. Shares the flow with the vuln management team: "Patch this — here's 
   exactly what happens if you don't."
```

### Scenario 4: "What does APT28 look like across all our intel?"

```
Maya (CTI Analyst):
1. Selects all reports tagged "APT28" from CTIX (12 reports over 2 years)
2. Platform generates a composite threat actor playbook — a master flow 
   combining all observed behaviors
3. Nodes are weighted by frequency: "Spear Phishing" appears in 11/12 
   reports → high confidence. "Watering Hole" in 2/12 → emerging behavior.
4. Maya can see the evolution: "They started using OAuth token theft in 
   Q3 2025 — that's new."
5. Exports as a PDF briefing for the quarterly threat review.
```

### Scenario 5: "Here's a bunch of IOCs, what's the story?"

```
Raj (Detection Engineer):
1. Pastes 30 IOCs from an ISAC sharing (IPs, domains, hashes)
2. Platform enriches each IOC (via CTIX, VirusTotal, Shodan)
3. AI infers relationships: "These 5 IPs are Cobalt Strike C2 servers. 
   These 3 hashes are Cobalt Strike beacons. This domain was used for 
   phishing delivery. Connected threat actor: FIN7."
4. Generates a probable attack flow: Phishing via domain → Beacon delivery 
   via hashes → C2 communication via IPs → likely followed by [inferred 
   based on FIN7 TTPs]: POS malware deployment
5. Raj now has context he didn't have from just a flat IOC list.
```

---

## Architecture: How This Extends the Current Plan

```
                    CURRENT PLAN                          EXPANDED PLATFORM
                    ────────────                          ─────────────────
                    
                    CTIX Report                           ANY INPUT
                         │                                     │
                         ▼                                     ▼
                    ┌─────────────┐                    ┌──────────────────┐
                    │ Narrative    │                    │ Universal Input   │
                    │ Assembler    │                    │ Parser & Router   │
                    └──────┬──────┘                    └────────┬─────────┘
                           │                                    │
                           ▼                                    ▼
                    ┌─────────────┐                    ┌──────────────────┐
                    │ ttp_chainer  │                    │ Multi-Model Flow  │
                    │ Pipeline     │                    │ Generation Engine │
                    └──────┬──────┘                    │  ├── ttp_chainer  │
                           │                            │  ├── Incident     │
                           │                            │  │   Flow Engine  │
                           │                            │  ├── IOC Inference│
                           │                            │  │   Engine       │
                           │                            │  └── Vuln Chain   │
                           │                            │      Engine       │
                           │                            └────────┬─────────┘
                           ▼                                     ▼
                    ┌─────────────┐                    ┌──────────────────┐
                    │ React Flow   │                    │ Universal Flow    │
                    │ Viewer       │                    │ Canvas            │
                    │ (view only)  │                    │ (view + annotate  │
                    └─────────────┘                    │  + overlay        │
                                                       │  + collaborate)   │
                                                       └────────┬─────────┘
                                                                │
                                                                ▼
                                         NOT IN CURRENT    ┌──────────────────┐
                                         PLAN              │ Action Layer      │
                                         ◄─────────────────│ (Detect, Mitigate,│
                                                           │  Respond, Hunt,   │
                                                           │  Communicate)     │
                                                           └──────────────────┘
```

**The current plan is the foundation.** It builds:
- The flow generation engine (ttp_chainer + LangGraph agent)
- The visualization canvas (React Flow in CTIX)
- The CTIX integration layer (API, storage, auth)

**The expanded platform adds:**
- More input types (incidents, IOCs, alerts, vulns, free text)
- More flow models (incident timeline, kill chain map, detection coverage)
- The action layer (tool integrations from every node)
- Collaboration and overlay features
- Standalone deployment option (not just inside CTIX)

---

## What We Might Be Missing — Brainstorm Gaps

### Gap 1: Feedback Loop / Learning

Flows are generated, but do they get better over time?

- **Analyst corrections**: If an analyst drags a node to a different position or removes a hallucinated technique, that correction should feed back into the model.
- **Incident validation**: When an incident is resolved, map the actual attack chain against the AI-generated flow. What did it get right/wrong?
- **Organizational context**: Over time, the system should learn that "in our environment, T1566 usually leads to T1059.001 (PowerShell), not T1059.003 (Windows Script Host)" — because that's our attack surface.

**Idea:** A "Confirm / Correct" workflow on each node. Corrections are stored and used to fine-tune or RAG-retrieve in future generations.

### Gap 2: Coverage Score / Defensive Posture

The flow shows the attack. But what about the defense?

- **Detection coverage overlay**: For each technique node, query the SIEM/EDR: "Do I have a rule that would catch this?" Green = covered, red = gap.
- **Mitigation completeness**: For each technique, check: "Is the recommended mitigation implemented in my environment?"
- **Risk score**: Aggregate: "This attack flow has 12 nodes. You detect 7 of them. Your coverage is 58%. The 5 gaps are in these techniques."

This transforms the platform from "here's what the attack looks like" to **"here's your exposure and here's exactly what to do about it."**

### Gap 3: Cross-Flow Intelligence

Individual flows are valuable. But the real power comes from analyzing across flows:

- **Technique frequency**: "T1059.001 (PowerShell) appears in 73% of our flows. It's the most common post-exploitation technique we face."
- **Common sub-chains**: "Spear Phishing → Macro → PowerShell appears in 40% of flows. That's our most common initial chain."
- **Threat actor evolution**: "APT29 shifted from using Cobalt Strike to Sliver in Q4 2025."
- **Industry benchmarking**: "Compared to other financial sector organizations, you have 20% less coverage on lateral movement techniques."

### Gap 4: What About Prevention, Not Just Detection?

Most platforms focus on detection (after the attack starts). What about **prevention**?

- **Configuration recommendations**: "For T1566 (Phishing), Microsoft recommends: Enable Safe Links, configure attachment sandboxing, deploy DMARC."
- **Policy enforcement**: "Check if your email gateway is configured with these protections" → query the actual gateway API.
- **Hardening scripts**: Generate PowerShell/bash scripts that implement recommended mitigations.
- **Compliance mapping**: "These 3 mitigations also satisfy PCI-DSS Requirement 5.2 and NIST CSF PR.PT-1."

### Gap 5: Real-Time / Streaming Mode

The current design is batch: submit input → wait → get flow. But for active incidents:

- **Streaming flow**: As new alerts come in during an incident, the flow updates in real time.
- **Predictive next step**: "Based on the chain so far (Phishing → Execution → C2), the AI predicts the next likely step is Lateral Movement via T1021 (Remote Services). Here are the proactive hunts to run NOW."
- **Live collaboration**: Multiple analysts on the same canvas during incident response, seeing updates as they happen.

### Gap 6: Executive / Non-Technical View

Not everyone reads ATT&CK technique IDs. The platform needs views for:

- **Executive summary**: Auto-generated 1-page PDF: "Attack chain overview, risk score, top 3 gaps, recommended actions."
- **Board-level view**: "In Q1 2026, we analyzed 47 threats. Average coverage score improved from 62% to 78%. Top remaining gaps: ..."
- **Compliance officer view**: "These attack flows map to these compliance controls. Here's where we're compliant and where we're not."

### Gap 7: Integration with Threat Simulation

Generated attack flows can be used as **input for breach simulation**:

- Export flow as an attack scenario for **AttackIQ, SafeBreach, or Atomic Red Team**.
- Run the simulation against your environment.
- Compare simulated results with expected detections.
- Update the flow's coverage overlay with actual test results.

**This closes the loop**: Intel → Flow → Detection → Simulation → Validation → Improvement.

### Gap 8: Community / Sharing

Attack flows are intelligence. They should be shareable:

- **Share within ISAC**: Export flows in STIX 2.1 for sharing via TAXII.
- **Community library**: Publish anonymized flows to a community repository.
- **Import community flows**: Load shared flows and overlay your detection coverage.
- **Collaborative analysis**: External analysts (MSSP, consulting) can view and annotate flows you share with them.

---

## Product Positioning

### If this were a standalone product (not just a CTIX feature)

**Name ideas** (brainstorm, not final):
- **FlowOps** — Cybersecurity flows, operationalized
- **AttackCanvas** — Visualize, understand, act
- **ThreatFlow** — From intelligence to action
- **ChainView** — See the full attack chain, take action
- **CyberGraph** — Your attack surface, visualized

### Tagline
> "Paste anything. See the attack. Take action."

### Value proposition (30-second pitch)
> "FlowOps turns any cybersecurity input — a threat report, an incident summary, a pile of IOCs — into an interactive attack flow in under 3 minutes. From every node in the flow, you can see mitigations, generate detection rules, and push protections to your security stack. It's the missing link between understanding a threat and defending against it."

---

## Relationship to Current Plan

| Aspect | Current Plan (PRODUCT_STORY.md) | Expanded Platform (this doc) |
|--------|--------------------------------|------------------------------|
| **Scope** | CTIX feature: Attack Flow tab on report pages | Standalone platform + CTIX integration |
| **Input** | CTIX report objects only | Any cybersecurity input |
| **Output** | Attack flow visualization + export | Flows + actions + integrations + analytics |
| **AI Engine** | ttp_chainer (report → attack flow) | Multiple engines: reports, incidents, IOCs, vulns |
| **Action** | View and export only | Detect, mitigate, respond, hunt from every node |
| **Deployment** | Microservice inside CTIX | Standalone SaaS + CTIX embedded + on-prem |
| **Timeline** | Phase 1–3 (8 weeks) | Current plan ships first; expanded features layer on over 6–12 months |

**The current plan is Phase 1 of the bigger platform.** Nothing changes about what we're building now. The expanded vision is a roadmap for where it goes after the CTIX integration proves the core value.

### Phased evolution

```
Phase 1 (Current Plan - Weeks 1-8):
  ✅ Attack flows from CTIX reports
  ✅ React Flow visualization in CTIX
  ✅ Export (STIX, AFB, PNG)

Phase 2 (Weeks 9-14):
  → Incident flow generation (from CFTR incidents)
  → Free text / URL input (paste anything)
  → Mitigation overlay (MITRE mitigations per node)
  → Detection coverage overlay

Phase 3 (Weeks 15-22):
  → IOC cluster inference engine
  → Action layer v1 (Sigma rule generation + deployment to 1 SIEM)
  → Story Mode for presentations
  → Vulnerability exploitation chain flows

Phase 4 (Weeks 23-30):
  → Full connector framework (SIEM, EDR, SOAR, firewall, email)
  → Real-time / streaming mode for active incidents
  → Cross-flow analytics (technique frequency, actor evolution)
  → Executive reporting view

Phase 5 (Weeks 31+):
  → Standalone deployment option
  → Community sharing (STIX/TAXII)
  → Threat simulation integration (AttackIQ/SafeBreach)
  → Feedback loop / model improvement from analyst corrections
  → Composite threat actor playbooks
```

---

## Open Questions for the Bigger Picture

| # | Question | Impact |
|---|----------|--------|
| 1 | Should this be a CTIX feature, a standalone Cyware product, or both? | Product strategy, pricing, engineering investment |
| 2 | How do we handle the inference gap — IOC → flow requires much more AI reasoning than report → flow? | Model capability, accuracy, cost |
| 3 | For the action layer, do we build our own connectors or reuse CSOL/CTIX connectors? | Engineering effort, time to market |
| 4 | Is real-time streaming mode technically feasible with current LLM latency? | Architecture, user expectations |
| 5 | How do we price the LLM usage — per-flow, per-tenant flat, or metered? | Business model |
| 6 | Should the detection coverage overlay query security tools live, or use cached state? | Performance, integration complexity |
| 7 | How do we handle multi-format input parsing without a brittle parser for each type? | Engineering, maintainability |
| 8 | Is there a market for a standalone "FlowOps" product outside of Cyware customers? | Go-to-market, competition |
| 9 | How do we measure and communicate flow accuracy to build user trust? | Adoption, credibility |
| 10 | Should we open-source the flow canvas (like FlowViz) to drive community adoption? | Strategy, community, talent |

---

## Summary: What This Adds to the Current Plan

The current plan (PRODUCT_STORY.md) is a **strong, shippable first step**: attack flows from CTIX reports, visualized with React Flow, exportable as STIX/AFB.

This document adds the **long-term vision** of where that foundation grows into:

1. **Universal input** — not just reports, but incidents, IOCs, alerts, vulns, free text
2. **Actionable nodes** — every node is a launchpad for mitigations, detection rules, response actions, and threat hunting
3. **Tool integration** — connected to the entire security stack via connectors
4. **Intelligence analytics** — cross-flow insights, coverage scoring, actor profiling
5. **Multiple deployment modes** — CTIX feature, standalone product, or embedded in any Cyware product

The vision is: **one canvas where you go from "what happened?" to "what do I do about it?" in minutes, not hours**.
