# AllBlue — Screenshots

## Screenshot 1 — Security Boundary

> The LLM calls typed Go functions only. No raw shell. No injection possible.

<img src="../assets/Screenshot from 2026-05-25 07-31-26.png" alt="MCP tool registration showing typed Go functions" width="900"/>

**Caption:** Custom Go MCP Server: LLM calls typed functions only. No raw shell. No injection. Architectural enforcement, not prompt rules.

---

## Screenshot 2 — Real APT Findings

> Confirmed IOCs from the SRL-2018 dataset. Real process names, real IPs, real C2 beaconing pattern.

<img src="../assets/Screenshot from 2026-05-25 08-11-39.png" alt="Final report showing usbclient.exe, C2 IP 108.79.235.64, beaconing to 172.16.4.10:8080" width="900"/>

**Caption:** CONFIRMED: usbclient.exe PID 6648, C2 to 108.79.235.64:33000, 11+ beacons to 172.16.4.10:8080. Real SRL-2018 APT dataset.

---

## Screenshot 3 — Self-Correction Live

> The memory agent detects empty pslist, identifies it as a rootkit IOC, and escalates automatically.

<img src="../assets/Screenshot from 2026-05-25 08-08-17.png" alt="Memory agent showing DELTA lines: pslist empty = DKOM, malfind empty = VAD hook" width="900"/>

**Caption:** Self-correction live: pslist empty → DKOM IOC flagged → malfind empty → VAD hook confirmed. Agent catches its own blind spots.

---

## Screenshot 4 — Benchmark Scorecard

> Scored against documented ground truth from SANS DFIR training dataset.

<img src="../assets/Screenshot from 2026-05-25 07-57-02.png" alt="Benchmark results: 100% precision, 92.86% recall, 0 false positives" width="900"/>

**Caption:** SRL-2018 APT benchmark: 100% precision, 92.86% recall, 0 false positives, 0 hallucinations. Scored against documented ground truth.

---

## Screenshot 5 — Audit Trail

> Every tool call logged with intent, hypothesis, result, and delta. Full traceability.

<img src="../assets/Screenshot from 2026-05-25 07-58-29.png" alt="JSONL audit trail showing intent, hypothesis, confidence, duration_ms fields" width="900"/>

**Caption:** Every tool call logged: intent, hypothesis, result, delta. Any finding traced back to exact execution. JSONL + Markdown output.