# AllBlue × Splunk — Architecture

> **Hackathon:** Splunk Agentic Ops Hackathon · Security Track · June 2026

## Architecture Diagram

![AllBlue Architecture](./architecture.png)

---

## Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          SPLUNK ENTERPRISE                                │
│                                                                           │
│  ┌─────────────────┐   ┌──────────────────────┐   ┌──────────────────┐  │
│  │  Splunk Alerts  │   │  Splunk MCP Server   │   │  Splunk HEC      │  │
│  │  (Webhook)      │   │  Port 3000           │   │  Port 8088       │  │
│  │  Search → Alert │   │  search/enrich_ip/   │   │  index=main      │  │
│  │  → POST :8718   │   │  enrich_process      │   │  allblue:*   │  │
│  └────────┬────────┘   └──────────┬───────────┘   └────────▲─────────┘  │
│           │                       │                          │            │
└───────────┼───────────────────────┼──────────────────────────┼────────────┘
            │                       │                          │
            ▼                       │                          │
┌──────────────────────────────────────────────────────────────────────────┐
│                           ALLBLUE SYSTEM                                  │
│                                                                           │
│  ┌──────────────────────┐                                                 │
│  │  Alert Webhook       │  ← internal/splunk/alert_handler.go            │
│  │  Port :8718          │    POST /splunk-alert → 202 Accepted           │
│  │  POST /splunk-alert  │    spawns triage goroutine                     │
│  └──────────┬───────────┘                                                 │
│             │                                                              │
│             ▼                                                              │
│  ┌──────────────────────┐    ┌──────────────────────────────────────────┐ │
│  │  Orchestrator        │───▶│  Splunk MCP Client                       │ │
│  │  orchestrator.go     │    │  internal/splunk/mcp_client.go           │ │
│  │  Claude Sonnet 4.6   │◀───│  EnrichIP / EnrichProcess / SearchAlerts │ │
│  │  Gemini 2.5 Flash    │    │  Adds Splunk context to findings         │ │
│  │  10-iteration loop   │    └──────────────────────────────────────────┘ │
│  └──────────┬───────────┘                                    │            │
│             │                                                 ▲            │
│             ▼                                                 │            │
│  ╔══════════════════════════════════════════════════════════════════════╗  │
│  ║         SECURITY BOUNDARY — Go MCP Server (cmd/sift-mcp/main.go)   ║  │
│  ║         LLM cannot execute shell commands — typed Go functions only  ║  │
│  ║                                                                      ║  │
│  ║  ┌────────────────┐  ┌────────────────┐  ┌─────────────────────┐   ║  │
│  ║  │  Memory Agent  │  │   Disk Agent   │  │  Splunk Tools (NEW) │   ║  │
│  ║  │  memory.go     │  │   disk.go      │  │  push_findings      │   ║  │
│  ║  │  pslist        │  │  log2timeline  │  │  query_splunk_alerts│   ║  │
│  ║  │  netscan       │  │  fls/mactime   │  │  get_splunk_context │   ║  │
│  ║  │  malfind       │  │  registry      │  └─────────────────────┘   ║  │
│  ║  │  hunt_malware  │  │  verify_hashes │                             ║  │
│  ║  └────────────────┘  └────────────────┘                             ║  │
│  ║                                                                      ║  │
│  ║  internal/wrappers/    — 7 typed tool wrappers (SafeExec only)      ║  │
│  ║  internal/validator/   — CONFIRMED / INFERRED / UNVERIFIED tags     ║  │
│  ║  internal/correlator/  — disk vs memory cross-reference             ║  │
│  ║  internal/registry/    — 30+ tool allowlist (binary + fixed args)   ║  │
│  ║  internal/splunk/      — HEC push + MCP client + webhook  (NEW)     ║  │
│  ╚══════════════════════════════════════════════════════════════════════╝  │
│             │                                                              │
│             ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │  Splunk HEC Push — internal/splunk/hec.go                           │ │
│  │  PushFindings() · PushRawLog() → Splunk index=main                  │──┼─▶ (to Splunk HEC)
│  │  sourcetype: allblue:ioc  ·  allblue:summary                │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      SIFT WORKSTATION TOOLS (read-only)                   │
│                   exec.Command(binary, args...)  — never bash -c          │
│                                                                           │
│  Volatility 3   log2timeline   TSK (fls)   RegRipper   YARA   hashdeep  │
│  bulk_extractor   foremost                                                │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Component Table

| Component | File | Technology | Purpose |
|---|---|---|---|
| Alert Webhook | `internal/splunk/alert_handler.go` | Go `net/http` | Receives Splunk alerts on `:8718`, spawns triage |
| Orchestrator | `agents/orchestrator/orchestrator.go` | Claude Sonnet 4.6 / Gemini 2.5 Flash | Multi-agent DFIR reasoning loop |
| Memory Agent | `agents/memory_agent/memory.go` | Volatility 3 | 9-step memory triage with self-correction |
| Disk Agent | `agents/disk_agent/disk.go` | log2timeline / TSK | Disk + registry forensics |
| Splunk MCP Client | `internal/splunk/mcp_client.go` | JSON-RPC 2.0 | Queries Splunk MCP Server for enrichment |
| Splunk HEC Push | `internal/splunk/hec.go` | HTTP POST | Sends structured findings to Splunk |
| Splunk Tools | `cmd/sift-mcp/main.go` | Go MCP | 3 new MCP tools registered for Splunk |
| Validator | `internal/validator/validator.go` | Go | Tags findings CONFIRMED / INFERRED / UNVERIFIED |
| Correlator | `internal/correlator/correlator.go` | Go | Cross-references disk vs memory findings |
| Dashboard | `splunk/dashboard.xml` | Splunk XML | Live IOC dashboard in Splunk Web |

---

## Security Properties

| Property | How Enforced |
|---|---|
| LLM cannot run shell commands | MCP server only exposes typed Go functions |
| No destructive evidence operations | Tool registry allowlist — no write/delete entries |
| No `bash -c` injection | `SafeExec` wrapper uses `exec.Command(binary, args...)` only |
| Evidence integrity | SHA-256 + MD5 computed before and after triage — must match |
| Splunk credentials never in code | Loaded from `.env` via `godotenv` at runtime |
| HEC token scoped minimally | `index=main` only, `allblue:*` sourcetypes |

---

## Splunk Integration Points

```
AllBlue → Splunk (outbound):
  1. Findings pushed via HEC POST to :8088/services/collector/event
     sourcetype=allblue:ioc     (one event per IOC)
     sourcetype=allblue:summary (one event per session)
     sourcetype=allblue:log     (real-time agent logs)

Splunk → AllBlue (inbound):
  2. Splunk Alert fires webhook → POST :8718/splunk-alert
     AllBlue receives, launches autonomous triage

AllBlue ↔ Splunk MCP Server (bidirectional enrichment):
  3. AllBlue queries Splunk MCP Server at :3000
     - search: historical event context
     - enrich_ip: IP reputation from Splunk data
     - enrich_process: process execution history
```

---

## New Files Added for Splunk

```
internal/splunk/
├── hec.go            — HEC push (PushFindings, PushRawLog)
├── mcp_client.go     — Splunk MCP Server queries
└── alert_handler.go  — Webhook receiver + triage launcher

splunk/
├── dashboard.xml     — Import into Splunk UI
└── saved_search.conf — Alert configs
```

---

*AllBlue — github.com/amareshhebbar/allblue · MIT License*