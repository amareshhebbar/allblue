# AllBlue — Developer Notes

## Environment

- **SIFT Workstation:** Ubuntu 22.04 (VirtualBox VM)
- **Host:** Fedora (SSHFS bridge to VM)
- **Language:** Go 1.22
- **API Keys:** Store in `.env` file in project root (gitignored)

---

## Daily Startup (Fedora Host → SIFT VM)

```bash
# 1. Start SIFT VM in VirtualBox
# 2. Get VM IP in SIFT terminal:
ip a | grep "inet " | grep -v 127

# 3. Mount VM filesystem on Fedora host:
sshfs sansforensics@<VM_IP>:/home/sansforensics/allblue ~/hackathon/allblue

# 4. Verify bridge works:
touch ~/hackathon/allblue/test.txt
# Check it appears in SIFT VM:
ls ~/allblue/test.txt && rm test.txt
```

---

## Common Commands (run inside SIFT VM)

```bash
cd ~/allblue

# Build the binary
go build -o logpose-ai ./cmd/sift-mcp/

# Test MCP server starts (Ctrl+C to exit)
./logpose-ai --mode=mcp

# Run autonomous triage on memory dump
./logpose-ai --mode=ai \
  --target=/tmp/evidence/base-hunt-memory.img \
  --type=memory

# Run autonomous triage on disk image
./logpose-ai --mode=ai \
  --target=/tmp/evidence/base-file-snapshot5.img \
  --type=disk

# Run benchmark (scores TP/FP/FN against ground truth)
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory

# Check audit logs from last run
ls -lt logs/ | head -5
cat logs/triage_*_tools.jsonl | python3 -m json.tool | head -60

# Check reasoning chain from last run
cat logs/triage_*_reasoning.md | head -100
```

---

## Evidence Setup

```bash
# Extract the SRL-2018 memory image (do this once)
mkdir -p /tmp/evidence
cd ~/allblue/data/Compromised_APT_Attack_Scenarios/\
SRL_2018_Compromised_Enterprose_Network/SRL_2018/\
HACKATHON-2026/Compromised\ APT\ Attack\ Scenarios/\
SRL-2018-Compromised\ Enterprise\ Network/SRL-2018/

7z x base-hunt-memory.7z -o/tmp/evidence/
ls -lh /tmp/evidence/
# Expected: base-hunt-memory.img (5.37 GB) + base-hunt-memory.md5
```

---

## Volatility Commands (direct, for debugging)

```bash
# OS info
vol -f /tmp/evidence/base-hunt-memory.img windows.info

# Process scan (bypasses rootkit DKOM)
vol -f /tmp/evidence/base-hunt-memory.img windows.psscan | head -30

# Network connections
vol -f /tmp/evidence/base-hunt-memory.img windows.netscan | head -20

# Compare pslist vs psscan (DKOM diff)
vol -f /tmp/evidence/base-hunt-memory.img windows.pslist > /tmp/pslist.txt
vol -f /tmp/evidence/base-hunt-memory.img windows.psscan > /tmp/psscan.txt
diff /tmp/pslist.txt /tmp/psscan.txt | head -30

# Service scan
vol -f /tmp/evidence/base-hunt-memory.img windows.svcscan | head -20

# PSXView (4-method comparison)
vol -f /tmp/evidence/base-hunt-memory.img windows.psxview | head -20
```

---

## Project Structure Quick Reference

```
cmd/sift-mcp/main.go         ← START HERE: MCP server + AI entry point
agents/orchestrator/         ← Claude/Gemini agentic loop
agents/memory_agent/         ← Autonomous memory triage (9 steps)
agents/disk_agent/           ← Autonomous disk triage
agents/reasoning_logger/     ← Analyst training loop (intent+delta)
internal/wrappers/           ← Typed tool wrappers (the security boundary)
internal/registry/           ← Tool allowlist (what can run)
internal/validator/          ← Hallucination guard (CONFIRMED/INFERRED)
internal/correlator/         ← Disk vs memory cross-reference
internal/logger/             ← JSONL audit trail
benchmark/                   ← Accuracy harness + ground truth
docs/                        ← All submission documents
```

---

## Adding a New Tool Wrapper

1. Add entry to `internal/registry/sift_tools.go`:
```go
"tool_key": {
    Binary:      "binary-name",
    Description: "What it does",
    FixedArgs:   []string{"--flag", "{TARGET}"},
    TargetParam: "input_param_name",
},
```

2. Register as MCP tool in `cmd/sift-mcp/main.go`:
```go
s.AddTool(
    mcp.NewTool("tool_name",
        mcp.WithDescription("Description for Claude"),
        mcp.WithString("param", mcp.Required(), mcp.Description("...")),
    ),
    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        p, err := mustStr(getArgs(req), "param")
        if err != nil { return mcp.NewToolResultError(err.Error()), nil }
        out, err := wrappers.RunRegistryTool("tool_key", p)
        if err != nil { return mcp.NewToolResultError(err.Error()), nil }
        return mcp.NewToolResultText(out), nil
    },
)
```

3. Add to `allToolDefs()` in `agents/orchestrator/orchestrator.go` if Claude should use it autonomously.

4. `go build -o logpose-ai ./cmd/sift-mcp/` to verify.

---

## API Key Setup

```bash
# .env file (gitignored)
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AI...

# The orchestrator loads this automatically via godotenv
# Verify it's loaded:
./logpose-ai --mode=ai --target=/tmp/evidence/base-hunt-memory.img --type=memory
# Should show: [*] Primary Engine: Claude
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `model not found` | Check model string in `orchestrator.go`: use `claude-sonnet-4-6` |
| `credit balance too low` | Add credits at console.anthropic.com |
| `vol: error: argument PLUGIN: invalid choice /path` | Remove `--symbols-path` from Volatility args — symbols are cached |
| `rules_path must be under /opt/allblue/yara-rules` | Set `LOGPOSE_YARA_RULES_DIR=~/yara-rules` or create the dir |
| `log2timeline: unrecognized arguments` | Use `--storage-file` not positional args |
| `BrokenPipeError` from Volatility | Normal when piping to `head` — not an error |
| `builds clean` but empty final report | Check `MaxTokens` in `runClaude()` — must be 8192 |

---

## Git Workflow

```bash
# Save progress
git add . && git commit -m "description of change"
git push origin <branch-name>

# Check what changed
git log --oneline -10
git diff HEAD~1 --stat
```