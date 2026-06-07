<div align="center">

# AllBlue

**Autonomous Multi-Agent DFIR Orchestrator × Splunk**

Splunk alerts trigger autonomous forensic triage → findings pushed to Splunk as structured IOC events → real-time DFIR intelligence dashboard.

[![Last Commit](https://img.shields.io/github/last-commit/amareshhebbar/allblue?style=flat-square&color=005571)](https://github.com/amareshhebbar/allblue/commits/main)
[![Language: Go](https://img.shields.io/badge/Language-Go-005571?style=flat-square&logo=go)](https://github.com/amareshhebbar/allblue)
[![Splunk](https://img.shields.io/badge/Splunk-HEC%20%2B%20MCP-005571?style=flat-square)](https://splunk.devpost.com)
[![Precision: 100%](https://img.shields.io/badge/Precision-100%25-005571?style=flat-square)]()
[![Recall: 92.8%](https://img.shields.io/badge/Recall-92.8%25-005571?style=flat-square)]()
[![Hallucinations: 0](https://img.shields.io/badge/Hallucinations-0-005571?style=flat-square)]()
[![License: MIT](https://img.shields.io/github/license/amareshhebbar/allblue?style=flat-square&color=005571)](LICENSE)

[Architecture](docs/architecture.md) · [Accuracy Report](docs/accuracy_report.md) · [Dataset](docs/dataset.md) · [Issues](https://github.com/amareshhebbar/allblue/issues)

> **AI Engine:** Claude Sonnet 4.6 (primary) · Gemini 2.5 Flash (automatic failover). All benchmark results produced using Claude.

</div>

---

## What Is AllBlue

AllBlue is an autonomous DFIR triage system that connects Claude (with Gemini failover) to the SANS SIFT Workstation toolchain through a **Custom MCP Server written in Go** — now fully integrated with **Splunk** as both a trigger source and findings destination.

**Core design principle:** The LLM cannot run shell commands. It can only call typed Go functions. The MCP server is the security boundary — architectural enforcement, not prompt-based rules.

**Splunk integration:** Splunk alerts automatically trigger AllBlue triage sessions. All findings are pushed back to Splunk via HEC as structured events. The Splunk MCP Server is queried mid-triage to enrich findings with historical context.

Validated on the SRL-2018 APT dataset (real-world intrusion with DKOM rootkit, C2 beaconing, lateral movement):

- Identified **13 of 14 documented IOCs** — C2 IP, all malicious processes, rootkit confirmed
- **100% precision** — zero hallucinated findings
- **6 agentic iterations** with self-correction that autonomously detected DKOM rootkit hiding

---

## How Splunk Integration Works

```
1. Splunk Alert fires  →  POST webhook to AllBlue :8718/splunk-alert
2. AllBlue launches    →  autonomous multi-agent DFIR triage
3. Agents query        →  Splunk MCP Server for IP/process enrichment
4. Findings pushed     →  Splunk HEC as allblue:ioc events
5. Dashboard shows     →  live IOCs, threat scores, session logs
```

Eligible prizes:
- **Best of Security** — $3,000
- **Best Use of Splunk MCP Server** — $1,000 bonus
- **Grand Prize** — $7,000

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/amareshhebbar/allblue
cd allblue

# 2. Configure
cp .example.env .env
# Edit .env — add your keys:
#   ANTHROPIC_API_KEY=sk-ant-...
#   SPLUNK_HEC_TOKEN=xxxx-xxxx-xxxx-xxxx
#   SPLUNK_HEC_URL=http://localhost:8088
#   SPLUNK_MCP_URL=http://localhost:3000

# 3. Build
go mod tidy
go build -o allblue-ai ./cmd/sift-mcp/

# 4. Run — starts MCP server + Splunk webhook receiver
./allblue-ai --mode=mcp

# 5. Run autonomous triage with Splunk push
./allblue-ai --mode=ai \
  --target=/path/to/evidence.img \
  --type=memory \
  --splunk-push=true
```

### Run Benchmark

```bash
7z x /path/to/base-hunt-memory.7z -o/tmp/evidence/

chmod +x benchmark/run_benchmark.sh
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory
```

Expected output:
```
True Positives  (TP): 13
False Negatives (FN): 1
False Positives (FP): 0
Precision: 100.00%
Recall:    92.86%
```

---

## Architecture

![AllBlue Architecture](docs/architecture.png)

```
Claude/Gemini (LLM)
       │ MCP calls only — no shell access
       ▼
cmd/sift-mcp/main.go  ← SECURITY BOUNDARY
       │ 15 typed MCP tools (12 original + 3 new Splunk tools)
       │
  ┌────┴────────────────────┐
  │                         │
agents/                 internal/
  │                         │
  ├─ orchestrator        ├─ wrappers/      (7 typed tool wrappers)
  ├─ memory_agent        ├─ validator/     (CONFIRMED/INFERRED/UNVERIFIED)
  ├─ disk_agent          ├─ correlator/    (disk vs memory cross-ref)
  └─ reasoning_logger    ├─ registry/      (tool allowlist, 30+ entries)
                         └─ splunk/        ← NEW
                              ├─ hec.go          (push findings to Splunk)
                              ├─ mcp_client.go   (query Splunk MCP Server)
                              └─ alert_handler.go(receive Splunk webhooks)
       │
  SIFT Tools (read-only)
  vol / fls / log2timeline / rip.pl / yara / hashdeep
       │
  Splunk HEC → index=main → Dashboard
```

[Full architecture documentation →](docs/architecture.md)

---

## MCP Tools (15 registered)

### Original DFIR Tools (12)

| Tool | Category | What It Does |
|---|---|---|
| `analyze_memory_windows_info` | Memory | OS version, kernel base, architecture |
| `analyze_memory_pslist` | Memory | Process scan via pool tags (bypasses DKOM) |
| `analyze_memory_netscan` | Memory | Active + closed TCP/UDP connections |
| `analyze_memory_malfind` | Memory | Code injection, process hollowing |
| `analyze_memory_cmdline` | Memory | Command line arguments of all processes |
| `hunt_memory_malware` | Memory | **Full autonomous 9-step triage with self-correction** |
| `analyze_disk_timeline` | Disk | log2timeline → psort super-timeline |
| `analyze_disk_fls` | Disk | Filesystem listing (allocated + deleted) |
| `analyze_registry` | Registry | SAM/SYSTEM/SOFTWARE/NTUSER hive extraction |
| `run_yara_scan` | Detection | Pattern matching with 8 built-in APT rules |
| `verify_hashes` | Integrity | SHA-256/MD5 compute or audit against known-good |
| `correlate_findings` | Analysis | Memory ↔ disk cross-reference, fileless/timestomp detection |

### New Splunk Tools (3)

| Tool | File | What It Does |
|---|---|---|
| `push_findings_to_splunk` | `internal/splunk/hec.go` | Sends all IOC findings to Splunk HEC as structured events |
| `query_splunk_alerts` | `internal/splunk/mcp_client.go` | Queries Splunk MCP Server for recent security alerts |
| `get_splunk_context` | `internal/splunk/mcp_client.go` | Enriches a finding with historical Splunk data (IP/process) |

---

## Evidence & Results

| Document | Description |
|---|---|
| [Screenshots →](docs/SCREENSHOTS.md) | 5 annotated screenshots: security boundary, APT findings, self-correction, benchmark, audit trail |
| [Demo Video →](docs/VIDEO.md) | Screencast with narration — live triage on SRL-2018 APT evidence |
| [Live Results →](docs/RESULT.md) | Full output from actual triage run — process findings, C2 connections, rootkit detection |

---

## Self-Correction Demo

The memory agent's self-correction sequence (visible in terminal output):

```
[*] Claude iteration 3/10
  -> Tool: hunt_memory_malware

[MemoryAgent] Starting autonomous memory triage...
  ~ [MemoryAgent] vol_windows_info      | 805ms  | INFERRED
  ~ [MemoryAgent] vol_windows_pslist    | 31s    | INFERRED
    ↳ DELTA: pslist returned only header — rootkit DKOM confirmed
  ~ [MemoryAgent] analyze_memory_netscan| 30s    | INFERRED
  ✓ [MemoryAgent] vol_windows_malfind   | 882ms  | CONFIRMED
    ↳ DELTA: Empty malfind on 90+ process system = VAD hook = rootkit IOC
  ✓ [MemoryAgent] vol_windows_cmdline   | 890ms  | CONFIRMED
    ↳ DELTA: Empty cmdline = process args hidden by rootkit
  ~ [MemoryAgent] vol_windows_svcscan   | 1.2s   | INFERRED
  ✓ [MemoryAgent] psxview_diff          | 2.1s   | CONFIRMED
    ↳ DELTA: DKOM confirmed — 87 processes hidden from pslist, visible in psscan
```

---

## Evidence Integrity

All operations are **read-only** by architectural enforcement:

- Volatility called with `-f path` — read-only file access
- TSK tools read-only by design
- No write, delete, or modify operations in the tool registry
- `exec.Command("vol", args...)` — never `exec.Command("bash", "-c", input)`
- SHA-256 + MD5 computed at triage start, verified at end
- Spoliation test: hash before/after full triage — identical

---

## Project Structure

```
allblue/
├── cmd/sift-mcp/main.go                      # MCP server — 15 typed tools registered
├── agents/
│   ├── orchestrator/
│   │   ├── orchestrator.go                   # Claude/Gemini dual engine, 10-iteration loop
│   │   └── findings_extractor.go             # Pre-triage Go parser
│   ├── memory_agent/memory.go                # 9-step autonomous memory triage
│   ├── disk_agent/disk.go                    # Disk triage, log2timeline pipeline
│   └── reasoning_logger/reasoning_logger.go  # Intent/hypothesis/delta audit per call
├── internal/
│   ├── wrappers/                             # 7 typed tool wrappers (no raw shell)
│   │   ├── volatility.go
│   │   ├── regripper.go
│   │   ├── tsk.go
│   │   ├── bulk_extractor.go
│   │   ├── foremost.go
│   │   ├── log2timeline.go
│   │   ├── yara.go
│   │   ├── hashdeep.go
│   │   ├── dynamic.go
│   │   ├── executor.go                       # SafeExec — never bash -c
│   │   └── helpers.go
│   ├── splunk/                               # ← NEW for Splunk hackathon
│   │   ├── hec.go                            # Push findings to Splunk HEC
│   │   ├── mcp_client.go                     # Query Splunk MCP Server
│   │   └── alert_handler.go                  # Receive Splunk webhook alerts
│   ├── registry/sift_tools.go               # 30+ tool allowlist
│   ├── validator/validator.go               # Hallucination guard
│   ├── correlator/correlator.go             # Disk vs memory cross-ref
│   ├── logger/logger.go                     # JSONL audit trail
│   └── parsers/
│       ├── plaso_parser.go
│       └── vol_parser.go
├── splunk/                                   # ← NEW
│   ├── dashboard.xml                         # Import into Splunk UI
│   └── saved_search.conf                     # Alert configs
├── benchmark/
│   ├── run_benchmark.sh
│   ├── ground_truth/srl2018_apt_ground_truth.json
│   └── results/
├── docs/
│   ├── architecture.md                       # Full architecture + diagram
│   ├── architecture.png                      # Architecture diagram (PNG)
│   ├── accuracy_report.md
│   ├── dataset.md
│   ├── devpost_story.md
│   ├── SCREENSHOTS.md
│   ├── VIDEO.md
│   └── RESULT.md
├── .example.env
├── go.mod
├── go.sum
└── README.md
```

---

## Accuracy Results

Full report: [docs/accuracy_report.md](docs/accuracy_report.md)

Tested against SRL-2018 Compromised Enterprise Network (SANS DFIR Summit dataset):

| Metric | Result |
|---|---|
| True Positives | 13 / 14 IOCs |
| False Positives | 0 |
| Hallucinations | 0 |
| Precision | **100%** |
| Recall | **92.8%** |
| Triage time | 552 seconds |

---

## License

MIT — see [LICENSE](LICENSE)

## Built For

[Splunk Agentic Ops Hackathon](https://splunk.devpost.com) — Security Track · June 2026

Originally developed for [FIND EVIL! Hackathon](https://findevil.devpost.com/) — SANS Institute · April–June 2026