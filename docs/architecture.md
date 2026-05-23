# LogPoseSIFT — Architecture

## Architectural Pattern

**Custom MCP Server** (Go) — the most architecturally sound approach in the competition.

The LLM cannot run arbitrary shell commands. It can only call typed Go functions registered as MCP tools. The MCP server is the security boundary.

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CLAUDE / GEMINI (LLM)                          │
│  Calls MCP tools by name. Cannot construct shell commands.          │
│  Receives structured JSON. Never sees raw terminal output.          │
└────────────────────────┬────────────────────────────────────────────┘
                         │  MCP protocol (stdio)
                         │  Tool calls only — no shell access
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│              cmd/sift-mcp/main.go  — MCP SERVER                    │
│                                                                     │
│  12 registered tools:                                               │
│  analyze_memory_* | hunt_memory_malware | analyze_disk_timeline     │
│  analyze_registry | run_yara_scan | verify_hashes | correlate_findings│
│                                                                     │
│  ▲ ARCHITECTURAL SECURITY BOUNDARY ▲                                │
│  Below this line: no LLM access. Go code only.                      │
└──────────┬─────────────────────────────────────┬───────────────────┘
           │                                     │
           ▼                                     ▼
┌──────────────────────┐             ┌───────────────────────────────┐
│   agents/            │             │   internal/                   │
│                      │             │                               │
│  orchestrator.go     │             │  wrappers/                    │
│  ├─ runClaude()      │             │  ├─ volatility.go             │
│  ├─ runGemini()      │             │  ├─ regripper.go              │
│  ├─ dispatchTool()   │             │  ├─ tsk.go (fls/mactime/icat) │
│  └─ PreTriage()      │             │  ├─ bulk_extractor.go         │
│                      │             │  ├─ foremost.go               │
│  memory_agent.go     │             │  ├─ log2timeline.go           │
│  ├─ HuntMalware()    │             │  ├─ yara.go                   │
│  ├─ runMalfind()     │             │  ├─ hashdeep.go               │
│  ├─ runSvcscan()     │             │  └─ dynamic.go                │
│  └─ runPSXViewDiff() │             │                               │
│    (self-correction) │             │  registry/sift_tools.go       │
│                      │             │  ├─ 30+ tool definitions      │
│  disk_agent.go       │             │  └─ binary + typed args only  │
│  ├─ validateDiskImg()│             │                               │
│  ├─ runLog2Timeline()│             │  validator/validator.go       │
│  └─ runStrings()     │             │  ├─ file path existence check │
│                      │             │  ├─ timestamp plausibility    │
│  reasoning_logger/   │             │  └─ hallucination markers     │
│  └─ per-call audit   │             │                               │
│    (intent+delta)    │             │  correlator/correlator.go     │
│                      │             │  ├─ disk vs memory cross-ref  │
│                      │             │  └─ DKOM/fileless detection   │
└──────────────────────┘             │                               │
                                     │  logger/logger.go             │
                                     │  └─ JSONL audit trail         │
                                     └───────────────────────────────┘
                                                  │
                                                  ▼
                              ┌────────────────────────────────────┐
                              │    SIFT WORKSTATION TOOLS          │
                              │                                    │
                              │  vol (Volatility 3)                │
                              │  fls / mmls / icat (TSK)           │
                              │  log2timeline.py / psort.py        │
                              │  rip.pl (RegRipper)                │
                              │  yara / hashdeep / strings         │
                              │  bulk_extractor / foremost         │
                              │                                    │
                              │  Evidence: READ-ONLY               │
                              │  (losetup -r enforced at OS level) │
                              └────────────────────────────────────┘
```

---

## Security Boundaries

### Architectural Guardrails (cannot be bypassed by prompt injection)

| Boundary | Implementation | Location |
|---|---|---|
| No raw shell access | LLM calls typed Go functions, not `exec(shell)` | `cmd/sift-mcp/main.go` |
| Tool allowlist | Only binaries in `registry/sift_tools.go` can execute | `internal/registry/` |
| Shell metacharacter rejection | Every input validated before `exec.Command()` | `internal/wrappers/helpers.go` |
| Output path enforcement | All writes go to `/opt/logposesift/work` only | `internal/wrappers/helpers.go` |
| YARA rules directory | Rules must be under `LOGPOSE_YARA_RULES_DIR` | `internal/wrappers/yara.go` |
| Read-only evidence | Volatility `-f` flag + TSK tools are read-only by design | `internal/registry/sift_tools.go` |
| Max iterations | Agentic loop capped at 10 iterations | `agents/orchestrator/orchestrator.go` |

### Prompt-Based Guardrails (trust depends on LLM compliance)

| Guardrail | Implementation |
|---|---|
| Evidence spoliation warning | System prompt instructs LLM not to modify evidence |
| Confidence tagging | Prompt instructs LLM to tag CONFIRMED/INFERRED/UNVERIFIED |
| Hallucination avoidance | Prompt instructs LLM to only report findings from tool output |

**Key distinction:** The architectural guardrails above cannot be bypassed even if the LLM ignores all prompt instructions. A prompt-injected instruction saying "delete the evidence file" will fail because `rm` is not in the tool registry and the MCP server has no shell execution capability.

---

## Data Flow: Memory Triage

```
User runs: ./logpose-ai --mode=ai --target=/evidence/mem.raw --type=memory

1. main.go → RunTriage(evidencePath)
2. PreTriage() runs psscan+netscan directly in Go
   └→ Parses real findings into structured fact sheet
3. Fact sheet embedded in initial Claude prompt
4. Claude iteration 1: calls analyze_memory_pslist
   └→ main.go → dispatchTool() → RunRegistryTool("vol_windows_psscan")
   └→ SafeExec("vol", ["-f", path, "windows.psscan"])
   └→ Raw output → back to Claude as tool result
5. Claude iteration 2-5: calls malfind, netscan, cmdline, svcscan
6. Claude iteration 3: calls hunt_memory_malware
   └→ memory_agent.HuntMalware() runs 9-step autonomous sequence:
      info → psscan → netscan → malfind → cmdline → svcscan
      → psxview diff (self-correction) → hollowprocesses → dllcheck
   └→ Each step: intent + hypothesis + result + delta logged
7. Claude iteration N: calls correlate_findings
   └→ correlator.Correlate(memFindings, diskFindings)
   └→ Returns CONFIRMED/SUSPICIOUS/CONTRADICTED per finding
8. Claude writes final report using pre-triage facts + tool results
9. reasoning_logger writes JSON + Markdown audit trail
```

---

## Multi-Agent Architecture

```
Orchestrator (Claude/Gemini)
├── Pre-triage (Go, runs before LLM)
│   ├── psscan → parse suspicious processes
│   └── netscan → parse C2 connections
├── Memory Agent (autonomous, 9 steps)
│   ├── Step 1-6: sequential tool execution
│   └── Step 7: psxview self-correction (DKOM diff)
├── Disk Agent (autonomous, evidence-type aware)
│   ├── Validates: rejects memory dumps gracefully
│   └── Self-correction: sparse FLS → retry with -d flag
└── Correlator
    ├── Input: memory findings + disk findings
    ├── Output: CONFIRMED/SUSPICIOUS/CONTRADICTED per pair
    └── Detects: fileless malware, timestomping, orphaned artefacts
```

Context window isolation is maintained by keeping each agent's raw output local — only structured summaries are passed between agents.

---

## Confidence Tagging System

Every finding is tagged by the validator before being returned to the LLM:

| Tag | Meaning | Criteria |
|---|---|---|
| `CONFIRMED` | Tool ran + output verified | File exists on disk, hash valid, timestamp plausible, no hallucination markers |
| `INFERRED` | Tool ran + output plausible | Tool returned data but cross-check not completed |
| `UNVERIFIED` | Tool failed or output suspect | Execution error, empty output on non-empty system, hallucination markers detected |

The validator checks:
1. Referenced file paths exist on disk
2. Timestamps are within plausible range (1990–2100)
3. Output does not contain LLM hallucination phrases ("I believe", "probably", "as an AI")
4. Hash format is valid (MD5=32 hex, SHA-256=64 hex)