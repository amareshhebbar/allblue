# AllBlue — Demo Video

## Full Triage Demo

<a href="https://www.youtube.com/watch?v=ex14lNo40fQ">
  <img src="../assets/allblue-thumb.png" alt="AllBlue — Autonomous DFIR Agent | SPLUNK Hackathon 2026" width="800">
</a>

> Click the thumbnail above to watch on YouTube
> **Built by Amaresh Hebbar** — SPLUNK! Hackathon 2026

---

## What This Video Shows

| Timestamp | Section |
|---|---|
| `0:00` | Introduction — AllBlue, Amaresh Hebbar, SPLUNK 2026 |
| `0:06` | Security boundary — Custom MCP Server, typed Go functions only |
| `0:27` | Tool allowlist — 30+ SIFT tools registered, no shell access |
| `0:49` | Evidence — SRL-2018 APT dataset, Windows 10 memory capture |
| `0:54` | Autonomous triage begins — one command, fully autonomous |
| `3:03` | Live triage logs — memory agent, 9-step sequence, self-correction |
| `4:35` | Final report — real IOCs confirmed from actual tool output |
| `5:00` | Benchmark scorecard — 100% precision, 92.86% recall |
| `5:20` | Audit trail — intent, hypothesis, delta per tool call |
| `5:44` | IOC extraction — process names, C2 IPs, lateral movement |

---

## Key Moment — Self-Correction Sequence (at 3:03)

```
[MemoryAgent] Starting autonomous memory triage...
  ~ [MemoryAgent] vol_windows_pslist   | 31s   | INFERRED
    ↳ DELTA: pslist returned only header — rootkit DKOM confirmed
  ✓ [MemoryAgent] vol_windows_malfind  | 882ms | CONFIRMED
    ↳ DELTA: Empty malfind on 90+ process system = VAD hook = rootkit IOC
  ✓ [MemoryAgent] vol_windows_cmdline  | 890ms | CONFIRMED
    ↳ DELTA: Empty cmdline = process args hidden by rootkit
```

The agent catches its own blind spot — empty pslist on a live 90-process system is impossible under normal conditions. It detects this, flags it as a CONFIRMED DKOM IOC, escalates to pool tag scanning (psscan), and continues without human intervention. This is the self-correction sequence the competition explicitly requires.

---

## Key Moment — Final Report IOCs (at 4:35)

```
CONFIRMED: usbclient.exe PID 6648 — not a legitimate Windows process
CONFIRMED: 108.79.235.64:33000 ESTABLISHED — external C2 server
CONFIRMED: 172.16.4.10:8080 — 11+ beaconing connections (C2 relay)
CONFIRMED: SMB ESTABLISHED to 172.16.4.5:445 — lateral movement
CONFIRMED: DKOM rootkit — pslist blind, psscan finds 90+ processes
```

Zero hallucinations. Every finding backed by actual Volatility output.

---

## Technical Details

| Field | Value |
|---|---|
| Evidence | SRL-2018 Compromised Enterprise Network |
| File | `base-hunt-memory.img` (5.37 GB) |
| Agent iterations | 6 |
| Tools called | 12+ |
| True Positives | 13 / 14 IOCs |
| False Positives | 0 |
| Hallucinations | 0 |
| Precision | 100% |
| Recall | 92.86% |

---
