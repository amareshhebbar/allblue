# LogPoseSIFT — Dataset Documentation

## Primary Dataset: SRL-2018 Compromised Enterprise Network

### Source
SANS Digital Forensics and Incident Response (DFIR) Summit training dataset, distributed as part of the FIND EVIL! hackathon at `HACKATHON-2026.zip`.

### Evidence Files

| File | Format | Size | Type |
|---|---|---|---|
| `base-hunt-memory.img` | Raw memory dump | 5.37 GB | Windows 10 x64 memory capture |
| `base-hunt-memory.md5` | MD5 hash file | <1 KB | Chain of custody |
| `base-admin-memory.7z` | Compressed raw dump | ~1 GB | Domain controller memory |
| `base-dc-memory.7z` | Compressed raw dump | ~1 GB | DC memory |
| `base-av-memory.7z` | Compressed raw dump | ~1 GB | AV server memory |
| `base-elf-memory.7z` | Compressed raw dump | ~1 GB | ELF host memory |
| `base-file-memory.7z` | Compressed raw dump | ~1 GB | File server memory |
| `base-file-snapshot5.7z` | Disk snapshot | ~5 GB | File server disk image |
| `base-mail-memory.7z` | Compressed raw dump | ~1 GB | Mail server memory |

### System Profile (base-hunt-memory.img)

| Field | Value |
|---|---|
| OS | Windows 10 x64 |
| Build | NtMajorVersion 10, NtMinorVersion 0 |
| Kernel Base | `0xf80211a05000` |
| System Time | `2018-09-07 01:03:57 UTC` |
| Architecture | 64-bit (Is64Bit: True, IsPAE: False) |
| System Root | `C:\Windows` |
| Product Type | NtProductWinNt (Workstation) |

### Scenario Description

The SRL-2018 scenario simulates a multi-stage APT intrusion against an enterprise network. The attacker:

1. Gained initial access and installed persistence services (`license_ctrl.exe`, `subject_ctrl.exe`, `connector_ctrl.exe`)
2. Deployed a primary implant (`usbclient.exe`) spawned from `explorer.exe`
3. Established C2 to an external IP (`108.79.235.64:33000`) and an internal relay (`172.16.4.10:8080`)
4. Installed a rootkit to hide all malicious processes from standard EPROCESS enumeration (DKOM)
5. Conducted lateral movement via SMB to at least two internal hosts (`172.16.4.5`, `172.16.5.50`)
6. Deployed credential harvesting tooling against LSASS

### Ground Truth

Documented in `benchmark/ground_truth/srl2018_apt_ground_truth.json`.

Derived from:
- Manual Volatility analysis of the memory image
- SANS DFIR training documentation
- Correlation with network connection artefacts

---

## How LogPoseSIFT Was Tested

```bash
# Extract evidence
7z x base-hunt-memory.7z -o/tmp/evidence/

# Run full benchmark
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory

# Results written to:
# benchmark/results/benchmark_TIMESTAMP.json
# benchmark/results/benchmark_TIMESTAMP.md
```

### Benchmark Results (2026-05-23)

- **True Positives:** 13/14 documented IOCs correctly identified
- **False Positives:** 0 (zero hallucinated findings)
- **Precision:** 100%
- **Recall:** 92.8%
- **Triage Duration:** 552 seconds (~9 minutes)

---

## Reproducibility

To reproduce this benchmark on the SANS SIFT Workstation:

```bash
# 1. Clone and build
git clone https://github.com/amareshhebbar/LogPoseSIFT
cd LogPoseSIFT
go build -o logpose-ai ./cmd/sift-mcp/

# 2. Set API key
echo "ANTHROPIC_API_KEY=your_key_here" > .env

# 3. Extract evidence (requires the hackathon dataset)
7z x /path/to/base-hunt-memory.7z -o/tmp/evidence/

# 4. Run benchmark
./benchmark/run_benchmark.sh /tmp/evidence/base-hunt-memory.img memory
```

Expected output: scorecard with 10+ true positives, 0 false positives.

---

## Dataset Integrity

All evidence files include an `.md5` file for chain-of-custody verification. LogPoseSIFT computes SHA-256 hashes of evidence at triage start and records them in the session log. No evidence files are modified during analysis — all tool operations are read-only.