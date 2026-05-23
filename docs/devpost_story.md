# LogPoseSIFT — Devpost Project Story

## What It Does

LogPoseSIFT is an autonomous DFIR triage agent that closes the speed gap between AI-powered attackers and human defenders. It connects Claude (with Gemini failover) to the full SANS SIFT Workstation toolchain through a purpose-built Custom MCP Server written in Go.

Given a memory dump or disk image, LogPoseSIFT autonomously:

1. **Pre-triages** the evidence in Go before the LLM even starts — running psscan and netscan directly and parsing real findings into a structured fact sheet embedded in the initial prompt
2. **Calls 12 forensic tools** across 6 categories (memory, disk, registry, YARA, hashing, correlation) in an agentic loop of up to 10 iterations
3. **Self-corrects** — when pslist returns empty (rootkit hiding processes), the memory agent detects this, escalates to psscan, then runs psxview to produce a DKOM diff proving which processes are hidden
4. **Correlates** memory findings against disk findings to detect fileless malware (process in memory with no disk trace) and timestomping (timestamp contradictions)
5. **Tags every finding** CONFIRMED / INFERRED / UNVERIFIED before returning it to the LLM — a hallucination guard that runs in Go before any finding touches the context window
6. **Writes an audit trail** — structured JSONL logs and a human-readable Markdown reasoning chain documenting intent, hypothesis, result, and delta for every tool call

On the SRL-2018 APT dataset (a documented real-world intrusion), LogPoseSIFT achieved **100% precision and 92.8% recall** with **zero hallucinated findings**.

---

## How We Built It

### Architecture Decision

We chose the Custom MCP Server pattern — the hardest of the four supported approaches and the one the competition documentation calls "the most sound architecture." Most competitors used Direct Agent Extension (easiest path, prompt-based guardrails). We built architectural enforcement: the LLM literally cannot run a destructive command because the MCP server does not expose shell access.

### The Security Boundary

The core insight is that `exec.Command("vol", args...)` is fundamentally different from `exec.Command("bash", "-c", userInput)`. Every SIFT tool is wrapped as a typed Go function. The args are constructed by Go code from validated typed inputs — not by the LLM. Shell metacharacter injection is rejected at the input layer before execution.

### The Hallucination Problem

The biggest technical challenge was Claude ignoring real tool output in its final report and writing hallucinated findings instead. We solved this with **pre-triage fact injection**: Go code runs psscan and netscan before the LLM loop starts, parses the real process names and IP addresses, and embeds them as confirmed facts in the initial prompt. Claude cannot claim "tools returned nothing" when its own prompt contains the actual process list.

### The Rootkit Problem

The SRL-2018 image has a DKOM rootkit that hides all processes from `windows.pslist`. Our initial implementation failed silently — pslist returned only a header row. The fix required understanding that empty pslist on a live system **is itself a CONFIRMED finding**. The memory agent now explicitly reports empty malfind/cmdline as rootkit IOCs, not as failures.

### Multi-Agent Architecture

Three agents with distinct responsibilities:
- **Memory Agent:** 9-step autonomous sequence (info → psscan → netscan → malfind → cmdline → svcscan → psxview self-correction → hollowprocesses → dllcheck)
- **Disk Agent:** Evidence type detection (rejects memory dumps gracefully), log2timeline with fixed plaso paths, self-correction on sparse FLS
- **Orchestrator:** Claude + Gemini dual-engine with automatic failover, pre-triage injection, tool dispatch

---

## Challenges

**The context window problem.** Volatility's netscan returns 12,000+ characters. Passing raw terminal output to Claude fills the context window with noise and degrades report quality. Solution: Go parsers that extract only the semantically relevant rows (ESTABLISHED connections, suspicious ports) before returning to the LLM.

**The self-correction trigger.** Early versions only triggered self-correction if malfind explicitly contained "Process:" — which never fires on a rootkit-compromised image. We rewrote the trigger logic: empty malfind on a system where psscan finds 90+ processes is definitionally suspicious and triggers the psxview diff path.

**The plaso path mismatch.** The disk agent was calling log2timeline with a hardcoded `/tmp/timeline.plaso` in the registry but checking for the file at `outputCSV + ".plaso"` — a path that never existed. Fixed by calling SafeExec directly with explicit `--storage-file` arg.

**Gemini type system.** Go's type system rejects assigning `genai.FunctionResponse` to a variable declared as `genai.Text`. Required declaring the current message as `genai.Part` (the interface both implement) to allow the agentic loop to work with Gemini.

---

## What We Learned

**Architectural enforcement beats prompt engineering.** Every hour spent making Go wrappers type-safe saved ten hours of fighting hallucinations. The LLM does not need to be told not to modify evidence if the tool registry literally has no write operations.

**Empty output is a finding.** A rootkit that hides processes produces empty pslist. Treating empty tool output as "no findings" is forensically wrong — it should be treated as active anti-forensics. This realization changed the entire memory agent design.

**Pre-inject facts, don't hope the LLM remembers.** Claude can receive 8,000 characters of real process data in iteration 1 and still write "tools returned nothing" in iteration 6. The solution is not better prompting — it is running the key tools in Go before the loop starts and embedding the parsed results as confirmed facts.

---

## What's Next

- **Disk triage against the SRL-2018 file server snapshot** — the `base-file-snapshot5.7z` disk image has MFT artefacts and registry hives to parse
- **YARA against memory** — scan the raw memory image with Cobalt Strike and Mimikatz signatures for pattern-based confirmation
- **Live endpoint integration** — connect the MCP server to a SIEM or remote endpoint for real-time triage
- **Cross-image correlation** — run memory agents on all 7 SRL-2018 hosts simultaneously and correlate findings across the enterprise
- **Persistent learning loop** — write failures to `progress.json` so the agent learns from previous runs on the same case

---

## Built With

- **Go 1.22** — MCP server, all wrappers, agents, validators, correlator
- **Anthropic Claude Sonnet 4.6** — primary AI engine
- **Google Gemini 2.5 Flash Lite** — failover engine
- **SANS SIFT Workstation** — forensic toolchain (Volatility 3, TSK, Plaso, RegRipper, YARA, hashdeep)
- **github.com/mark3labs/mcp-go** — MCP server framework
- **github.com/liushuangls/go-anthropic** — Anthropic Go client
- **github.com/google/generative-ai-go** — Gemini Go client