# AllBlue — Developer Guide

> Everything you need to understand, extend, and contribute to AllBlue.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Prerequisites](#prerequisites)
- [Repository Structure](#repository-structure)
- [How It Works — Architecture Deep Dive](#how-it-works--architecture-deep-dive)
- [Security Boundary — The Core Design Rule](#security-boundary--the-core-design-rule)
- [Setting Up Locally](#setting-up-locally)
- [Environment Variables](#environment-variables)
- [Build & Run](#build--run)
- [Adding a New MCP Tool](#adding-a-new-mcp-tool)
- [Adding a New SIFT Tool Wrapper](#adding-a-new-sift-tool-wrapper)
- [Splunk Integration — How It Works](#splunk-integration--how-it-works)
- [The Validator System](#the-validator-system)
- [The Correlator](#the-correlator)
- [Reasoning Logger](#reasoning-logger)
- [Running the Benchmark](#running-the-benchmark)
- [Testing](#testing)
- [Common Errors & Fixes](#common-errors--fixes)
- [Contributing](#contributing)

---

## Project Overview

AllBlue connects Claude AI (with Gemini failover) to the forensic toolchain through a custom MCP server written in Go.

**The one-line design principle:** The LLM cannot run shell commands. It can only call typed Go functions. The MCP server is the security boundary.

**With Splunk:** Splunk alerts trigger triage sessions. Findings are pushed back to Splunk as structured IOC events. The Splunk MCP Server is queried mid-triage for historical enrichment.

---

## Prerequisites

### Required
| Tool | Version | Install |
|---|---|---|
| Go | 1.21+ | `sudo apt install golang-go` |
| Workstation | Latest | https://www.sans.org/tools/sift-workstation/ |
| Volatility 3 | Latest | Pre-installed on SIFT |
| Anthropic API key | — | https://console.anthropic.com |

### Optional (for Splunk integration)
| Tool | Purpose |
|---|---|
| Splunk Enterprise 10.x | HEC ingest + search |
| Splunk MCP Server | IOC enrichment queries |
| Node.js 20+ | Required for Splunk MCP Server |

### Verify SIFT tools are available
```bash
which vol          # Volatility 3
which log2timeline # Plaso
which fls          # TSK
which rip.pl       # RegRipper
which yara         # YARA
which hashdeep     # hashdeep
```

---

## Repository Structure

```
allblue/
├── cmd/
│   └── sift-mcp/
│       └── main.go              # Entry point — MCP server + CLI flags
│
├── agents/
│   ├── orchestrator/
│   │   ├── orchestrator.go      # Claude/Gemini dual engine, 10-iteration loop
│   │   └── findings_extractor.go# Pre-triage Go parser — embeds facts before LLM
│   ├── memory_agent/
│   │   └── memory.go            # 9-step autonomous memory triage, self-correction
│   ├── disk_agent/
│   │   └── disk.go              # Disk triage, log2timeline pipeline
│   └── reasoning_logger/
│       └── reasoning_logger.go  # Per-call intent/hypothesis/delta audit trail
│
├── internal/
│   ├── wrappers/                # Typed tool wrappers — NO raw shell allowed here
│   │   ├── volatility.go        # Volatility 3 (pslist, netscan, malfind, cmdline...)
│   │   ├── regripper.go         # Windows registry hive extraction
│   │   ├── tsk.go               # TSK: fls / mactime / icat
│   │   ├── log2timeline.go      # Plaso super-timeline pipeline
│   │   ├── yara.go              # YARA pattern matching
│   │   ├── hashdeep.go          # SHA-256/MD5 evidence integrity
│   │   ├── bulk_extractor.go    # Carved emails, URLs, credentials
│   │   ├── foremost.go          # File carving and recovery
│   │   ├── dynamic.go           # Registry-driven tool executor
│   │   ├── executor.go          # SafeExec — the only way to run binaries
│   │   └── helpers.go           # Shell metachar guard, path validation
│   ├── splunk/                  # Splunk integration (added for hackathon)
│   │   ├── hec.go               # Push findings to Splunk HEC
│   │   ├── mcp_client.go        # Query Splunk MCP Server
│   │   └── alert_handler.go     # Webhook receiver — Splunk → AllBlue
│   ├── registry/
│   │   └── sift_tools.go        # 30+ tool allowlist with binary paths + args
│   ├── validator/
│   │   └── validator.go         # CONFIRMED / INFERRED / UNVERIFIED tagging
│   ├── correlator/
│   │   └── correlator.go        # Disk vs memory cross-reference engine
│   ├── logger/
│   │   └── logger.go            # JSONL structured audit trail per session
│   └── parsers/
│       ├── plaso_parser.go      # Plaso timeline output parser
│       └── vol_parser.go        # Volatility output parser
│
├── benchmark/
│   ├── run_benchmark.sh         # Accuracy harness — TP/FP/FN scoring
│   ├── ground_truth/
│   │   └── srl2018_apt_ground_truth.json  # 14 documented IOCs
│   └── results/                 # Scorecard JSON + Markdown per run
│
├── splunk/
│   ├── dashboard.xml            # Import into Splunk UI — live IOC dashboard
│   └── saved_search.conf        # Alert trigger configs
│
├── docs/
│   ├── architecture.md          # Full architecture + data flow
│   ├── architecture.png         # Architecture diagram PNG
│   ├── accuracy_report.md       # Benchmark results
│   ├── dataset.md               # SRL-2018 dataset info
│   └── RESULT.md                # Full live triage output
│
├── logs/                        # Session logs — auto-created at runtime
├── data/                        # Evidence files — NOT committed to git
├── .example.env                 # Copy to .env and fill in keys
├── go.mod
├── go.sum
└── README.md
```

---

## How It Works — Architecture Deep Dive

### Request flow

```
User runs: ./allblue-ai --mode=ai --target=evidence.img --type=memory
                │
                ▼
    orchestrator.go — NewEngine().RunTriage()
                │
                ├─ findings_extractor.go  (pre-triage: psscan + netscan → confirmed facts)
                │
                ├─ Sends facts + system prompt to Claude API
                │
                ├─ Claude calls MCP tool → cmd/sift-mcp/main.go handles it
                │         │
                │         └─ Dispatches to typed wrapper in internal/wrappers/
                │                   │
                │                   └─ executor.go SafeExec("vol", args...)
                │                             │
                │                             └─ SIFT binary runs read-only
                │
                ├─ Tool output → validator.go tags it CONFIRMED/INFERRED/UNVERIFIED
                │
                ├─ Loop repeats up to 10 iterations
                │
                ├─ Final report generated
                │
                └─ (if --splunk-push) internal/splunk/hec.go pushes findings to Splunk
```

### Splunk alert flow

```
Splunk alert fires
        │  POST /splunk-alert
        ▼
internal/splunk/alert_handler.go  (port :8718)
        │
        ├─ Responds 202 immediately (non-blocking)
        │
        └─ go triggerTriage()  — spawns goroutine
                    │
                    └─ exec allblue-ai --mode=ai --splunk-push=true
```

---

## Security Boundary — The Core Design Rule

**Rule: The LLM never runs shell commands directly.**

Everything goes through `internal/wrappers/executor.go`:

```go
// CORRECT — typed args, no shell interpolation
cmd := exec.Command("vol", "-f", dumpPath, "windows.pslist")

// NEVER DO THIS — shell injection risk
cmd := exec.Command("bash", "-c", "vol -f "+dumpPath+" windows.pslist")
```

The tool registry (`internal/registry/sift_tools.go`) allowlists every binary and its permitted arguments. If a tool isn't in the registry, it cannot be called.

**When adding new tools, you must:**
1. Add the binary + arg pattern to `sift_tools.go`
2. Write a typed wrapper in `internal/wrappers/`
3. Register it as an MCP tool in `cmd/sift-mcp/main.go`
4. Never pass user-supplied strings directly as shell arguments — always validate through `helpers.go`

---

## Setting Up Locally

```bash
# 1. Clone
git clone https://github.com/amareshhebbar/allblue
cd allblue

# 2. Copy env file
cp .example.env .env

# 3. Edit .env — add your keys
nano .env

# 4. Tidy dependencies
go mod tidy

# 5. Build
go build -o allblue-ai ./cmd/sift-mcp/

# 6. Verify
./allblue-ai --mode=mcp
# Should print: Registered MCP Tools (15)
```

---

## Environment Variables

```bash
# Required for AI mode
ANTHROPIC_API_KEY=sk-ant-...          # Primary LLM engine
GEMINI_API_KEY=AIza...                # Fallback LLM engine (optional)

# Required for Splunk integration
SPLUNK_HEC_URL=http://localhost:8088   # Splunk HEC endpoint
SPLUNK_HEC_TOKEN=xxxx-xxxx-xxxx-xxxx  # HEC token (create via inputs.conf or UI)

# Optional — for Splunk MCP Server enrichment
SPLUNK_MCP_URL=http://localhost:3000   # Splunk MCP Server endpoint
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=yourpassword
```

### Setting up Splunk HEC without UI

```bash
sudo mkdir -p /opt/splunk/etc/apps/search/local
sudo bash -c 'cat > /opt/splunk/etc/apps/search/local/inputs.conf << EOF
[http]
disabled = 0
enableSSL = 0
port = 8088

[http://allblue-token]
disabled = 0
index = main
sourcetype = _json
token = 12345678-1234-1234-1234-123456789abc
EOF'
sudo /opt/splunk/bin/splunk restart --run-as-root
```

---

## Build & Run

```bash
# Build
go build -o allblue-ai ./cmd/sift-mcp/

# Run as MCP server (for Claude Desktop / Claude Code)
./allblue-ai --mode=mcp

# Run autonomous triage
./allblue-ai --mode=ai \
  --target=/path/to/evidence.img \
  --type=memory          # memory | disk | both

# Run triage + push findings to Splunk
./allblue-ai --mode=ai \
  --target=/path/to/evidence.img \
  --type=memory \
  --splunk-push=true \
  --session-id=my-session-001

# Run benchmark against SRL-2018 ground truth
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `mcp` | `mcp` = MCP server mode, `ai` = autonomous triage |
| `--target` | — | Evidence file path (required in ai mode) |
| `--type` | `memory` | Evidence type: `memory`, `disk`, `both` |
| `--splunk-push` | `false` | Push findings to Splunk HEC after triage |
| `--session-id` | auto | Custom session ID (auto-generated if empty) |

---

## Adding a New MCP Tool

### Step 1 — Add to registry

In `internal/registry/sift_tools.go`:

```go
"vol_windows_driverirp": {
    Binary: "vol",
    Args:   []string{"-f", "{{DUMP}}", "windows.driverirp"},
    ReadOnly: true,
},
```

### Step 2 — Write a typed wrapper

In `internal/wrappers/volatility.go` (or a new file):

```go
func RunDriverIRP(dumpPath string) (string, error) {
    if err := ValidatePath(dumpPath); err != nil {
        return "", err
    }
    return SafeExec("vol_windows_driverirp", dumpPath)
}
```

### Step 3 — Register in main.go

In `cmd/sift-mcp/main.go`, inside `runMCPServer()`:

```go
s.AddTool(
    mcp.NewTool("analyze_memory_driverirp",
        mcp.WithDescription("List IRP handlers for all drivers. Detects DKOM driver hiding and hook-based rootkits."),
        mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
    ),
    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        p, err := mustStr(getArgs(req), "dump_path")
        if err != nil { return mcp.NewToolResultError(err.Error()), nil }
        out, err := wrappers.RunDriverIRP(p)
        if err != nil { return mcp.NewToolResultError(err.Error()), nil }
        return mcp.NewToolResultText(out), nil
    },
)
```

### Step 4 — Update printToolSummary()

Add your new tool name to the `tools` slice in `printToolSummary()`.

### Step 5 — Build and verify

```bash
go build -o allblue-ai ./cmd/sift-mcp/
./allblue-ai --mode=mcp
# Count should increase by 1
```

---

## Adding a New SIFT Tool Wrapper

All wrappers follow the same pattern. Here's a minimal example for a new tool:

```go
// internal/wrappers/mytool.go
package wrappers

import "fmt"

type MyToolInput struct {
    TargetPath string
    Options    string
}

type MyToolResult struct {
    Raw        string
    Confidence string // CONFIRMED | INFERRED | UNVERIFIED
}

func (r *MyToolResult) ToJSON() ([]byte, error) {
    return marshalResult(r)
}

func RunMyTool(input MyToolInput) (*MyToolResult, error) {
    if err := ValidatePath(input.TargetPath); err != nil {
        return nil, fmt.Errorf("invalid path: %w", err)
    }

    // SafeExec — never bash -c
    out, err := SafeExec("mytool_run", input.TargetPath)
    if err != nil {
        return nil, err
    }

    return &MyToolResult{
        Raw:        out,
        Confidence: inferConfidence(out),
    }, nil
}
```

**Rules for all wrappers:**
- Always call `ValidatePath()` on any path input
- Always use `SafeExec()` — never `exec.Command("bash", ...)` 
- Always return structured output, not raw strings where possible
- Always tag confidence: `CONFIRMED` (tool output proves it), `INFERRED` (logical conclusion), `UNVERIFIED` (needs corroboration)

---

## Splunk Integration — How It Works

### HEC Push (`internal/splunk/hec.go`)

```go
// Push a complete triage session to Splunk
summary := splunk.TriageSummary{
    SessionID:     "session-001",
    EvidenceFile:  "/path/to/evidence.img",
    EvidenceType:  "memory",
    AgentEngine:   "claude",
    TotalFindings: 5,
    Findings: []splunk.Finding{
        {
            SessionID:   "session-001",
            Severity:    "CRITICAL",
            Category:    "network",
            IOC:         "108.79.235.64",
            Description: "External C2 IP confirmed",
            Confidence:  "CONFIRMED",
            Tool:        "vol_windows_netscan",
            ThreatScore: 95,
        },
    },
}
err := splunk.PushFindings(summary)
```

Each call to `PushFindings()` sends:
- One `logposesift:summary` event (session-level)
- One `logposesift:ioc` event per finding (searchable individually)
- Ongoing `logposesift:log` events via `PushRawLog()` during triage

### Splunk MCP Client (`internal/splunk/mcp_client.go`)

```go
client := splunk.NewSplunkMCPClient()

// Enrich an IP with historical Splunk data
results, err := client.EnrichIP("192.168.1.100")

// Enrich a process name
results, err := client.EnrichProcess("svchost.exe")

// Search for recent alerts
results, err := client.SearchAlerts("malware suspicious", "-1h")
```

Returns `[]map[string]interface{}` — empty slice if Splunk MCP Server isn't running (graceful degradation, triage continues without enrichment).

### Webhook Receiver (`internal/splunk/alert_handler.go`)

Started automatically in `--mode=mcp`:

```
POST http://your-host:8718/splunk-alert
Content-Type: application/json

{
  "search_name": "Suspicious Process Detection",
  "result": {
    "host": "WORKSTATION-01",
    "evidence_path": "/path/to/evidence.img"
  }
}
```

Returns `202 Accepted` immediately. Triage runs in a goroutine.

Other endpoints:
- `GET /health` — service health check
- `GET /status` — active session count

---

## The Validator System

`internal/validator/validator.go` prevents hallucinations by enforcing that every finding has evidence.

```
CONFIRMED  — Tool output directly proves the claim
             e.g. netscan shows IP in ESTABLISHED state → C2 connection CONFIRMED

INFERRED   — Tool output strongly implies the claim but doesn't prove it directly
             e.g. empty pslist + large process count → DKOM INFERRED

UNVERIFIED — Claim made but no tool output to support it
             e.g. LLM suggests a process might be malicious without tool evidence
```

The validator is called by every wrapper before returning output to the orchestrator. If a finding can't be tagged `CONFIRMED` or `INFERRED`, it's returned as `UNVERIFIED` and the orchestrator is instructed to seek corroboration before including it in the final report.

---

## The Correlator

`internal/correlator/correlator.go` cross-references memory and disk findings to detect:

- **Fileless malware** — process visible in memory but no corresponding file on disk
- **Timestomping** — file creation/modification timestamps contradict timeline evidence
- **Orphaned artifacts** — disk artifacts with no corresponding memory process (process exited after dropping files)
- **DKOM confirmation** — process visible in psscan but not pslist

```go
engine := correlator.New("memory_agent", "disk_agent")
memFindings := correlator.ParsePSList(memOutput)
memFindings = append(memFindings, correlator.ParseNetScan(memOutput)...)

report := engine.Correlate(memFindings, diskFindings)
// report.Confirmed  — findings corroborated by both sources
// report.Suspicious — findings only in one source
// report.Contradicted — findings where sources disagree
```

---

## Reasoning Logger

`agents/reasoning_logger/reasoning_logger.go` writes a per-call audit trail for every tool invocation. Each entry records:

```json
{
  "call_id": "iter_3_tool_2",
  "tool": "hunt_memory_malware",
  "intent": "Why Claude called this tool",
  "hypothesis": "What Claude expected to find",
  "result_summary": "What the tool actually returned",
  "delta": "How this changes the investigation",
  "confidence": "CONFIRMED",
  "duration_ms": 86364
}
```

Output per session:
- `logs/SESSION_ID_reasoning.json` — machine-readable
- `logs/SESSION_ID_reasoning.md` — human-readable for analysis

This log is what makes AllBlue's reasoning transparent and auditable — you can see exactly why the agent made each decision.

---

## Running the Benchmark

```bash
# https://cyberdefenders.org/blueteam-ctf-challenges/sysmon/

# Extract
7z x base-hunt-memory.7z -o/tmp/evidence/

# Run benchmark
chmod +x benchmark/run_benchmark.sh
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory

# Results written to:
# benchmark/results/benchmark_TIMESTAMP.md
# benchmark/results/benchmark_TIMESTAMP.json
```

Expected output:
```
True Positives  (TP): 10
False Negatives (FN): 4
False Positives (FP): 0
Precision: 100.00%
Recall:    71.42%
```

To update ground truth for a new dataset, edit `benchmark/ground_truth/srl2018_apt_ground_truth.json`.

---

## Testing

```bash
# Unit tests
go test ./...

# Test HEC connectivity
curl http://localhost:8088/services/collector/health
# Expected: {"text":"HEC is healthy","code":17}

# Test HEC push
curl http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk YOUR-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event": {"test": "allblue dev test"}}'
# Expected: {"text":"Success","code":0}

# Test webhook receiver
./allblue-ai --mode=mcp &
curl -X POST http://localhost:8718/splunk-alert \
  -H "Content-Type: application/json" \
  -d '{"search_name": "Dev Test", "result": {"host": "test"}}'
# Expected: {"status":"accepted","session_id":"splunk-..."}

# Test health endpoint
curl http://localhost:8718/health
# Expected: {"status":"ok","service":"allblue-webhook","version":"2.0.0-splunk"}

# Full triage smoke test (requires evidence + API key)
./allblue-ai --mode=ai \
  --target=/tmp/evidence/base-hunt-memory.img \
  --type=memory \
  --splunk-push=true \
  --session-id=dev-test-$(date +%s)
```

---

## Common Errors & Fixes

### `error: ANTHROPIC_API_KEY not set`
```bash
echo "ANTHROPIC_API_KEY=sk-ant-your-key" >> .env
```

### `vol: command not found`
```bash
which vol || sudo apt install volatility3
# On SIFT: vol is pre-installed as 'vol'
```

### `curl: (7) Failed to connect to localhost port 8088`
Splunk HEC not running. Check:
```bash
sudo /opt/splunk/bin/splunk status --run-as-root
curl http://localhost:8088/services/collector/health
```

### `Triage failed: fork/exec ./allblue-ai: no such file or directory`
Webhook is calling with relative path. Fix in `alert_handler.go`:
```go
// Change:
cmd := exec.Command("./allblue-ai", ...)
// To:
cmd := exec.Command("/home/sansforensics/allblue/allblue-ai", ...)
```
Then rebuild: `go build -o allblue-ai ./cmd/sift-mcp/`

### `Your credit balance is too low`
Add credits at https://console.anthropic.com/settings/billing or switch to Gemini:
```bash
echo "GEMINI_API_KEY=AIza-your-key" >> .env
```
Gemini kicks in automatically as fallback.

### `go build` fails with import error
```bash
go mod tidy
go mod download
go build -o allblue-ai ./cmd/sift-mcp/
```

### Empty output from Volatility plugins (psscan returns data, pslist returns nothing)
This is **correct behavior** on a DKOM-rootkitted image — not a bug. The agent detects this as a rootkit indicator and handles it via self-correction. If you're seeing it on a clean image, check Volatility version:
```bash
vol --version  # Needs Volatility 3, not Volatility 2
```

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Follow the security boundary rules — no `bash -c`, no raw string args to `exec.Command`
4. Add a typed wrapper for any new tool
5. Update `printToolSummary()` in `main.go`
6. Run `go test ./...` — all tests must pass
7. Run the benchmark — precision must stay at 100% (no new false positives)
8. Open a PR with a description of what you added and why

### Code style
- Standard Go formatting — run `gofmt -w .` before committing
- Every exported function needs a one-line comment
- Every new wrapper must have `ValidatePath()` + `SafeExec()` — no exceptions
- Confidence tags (`CONFIRMED`/`INFERRED`/`UNVERIFIED`) are mandatory on all findings

---

*AllBlue — github.com/amareshhebbar/allblue · MIT License · Built by Amaresh Hebbar*