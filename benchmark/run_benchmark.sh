#!/usr/bin/env bash
# LogPoseSIFT Accuracy Benchmark
# Runs the agent against the SRL-2018 APT dataset and scores findings
# against documented ground truth.
#
# Usage:
#   ./benchmark/run_benchmark.sh [evidence_path]
#
# Output:
#   benchmark/results/benchmark_TIMESTAMP.json   — machine-readable scorecard
#   benchmark/results/benchmark_TIMESTAMP.md     — human-readable report

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$REPO_DIR/logpose-ai"
RESULTS_DIR="$SCRIPT_DIR/results"
GROUND_TRUTH="$SCRIPT_DIR/ground_truth/srl2018_apt_ground_truth.json"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_JSON="$RESULTS_DIR/benchmark_${TIMESTAMP}.json"
OUTPUT_MD="$RESULTS_DIR/benchmark_${TIMESTAMP}.md"

# Evidence path (default: SRL-2018 memory image)
EVIDENCE_PATH="${1:-/tmp/evidence/base-hunt-memory.img}"
EVIDENCE_TYPE="${2:-memory}"

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo -e "${BOLD}   LogPoseSIFT Accuracy Benchmark Harness${NC}"
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────
check_prereqs() {
    local failed=0
    for tool in vol fls mmls python3 jq; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${YELLOW}[WARN] $tool not found — some checks will skip${NC}"
        fi
    done
    if [[ ! -f "$BINARY" ]]; then
        echo -e "${BLUE}[*] Building logpose-ai...${NC}"
        cd "$REPO_DIR" && go build -o logpose-ai ./cmd/sift-mcp/ || {
            echo -e "${RED}[!] Build failed${NC}"; exit 1
        }
    fi
    if [[ ! -f "$EVIDENCE_PATH" ]]; then
        echo -e "${RED}[!] Evidence not found: $EVIDENCE_PATH${NC}"
        echo "    Extract with: 7z x base-hunt-memory.7z -o/tmp/evidence/"
        exit 1
    fi
    mkdir -p "$RESULTS_DIR"
}

# ── Ground truth loader ───────────────────────────────────────
# The SRL-2018 APT case has known IOCs documented in the ground truth file.
# If the file doesn't exist, we generate a baseline from known findings.
setup_ground_truth() {
    mkdir -p "$(dirname "$GROUND_TRUTH")"
    if [[ ! -f "$GROUND_TRUTH" ]]; then
        echo -e "${BLUE}[*] Generating ground truth from SRL-2018 APT documentation...${NC}"
        cat > "$GROUND_TRUTH" << 'TRUTH'
{
  "dataset": "SRL-2018 Compromised Enterprise Network",
  "source": "SANS DFIR Summit / HACKATHON-2026",
  "evidence_file": "base-hunt-memory.img",
  "documented_iocs": {
    "malicious_processes": [
      {"name": "usbclient.exe", "pid": 6648, "ppid": 4508, "note": "Primary implant, spawned from explorer.exe"},
      {"name": "license_ctrl.exe", "pid": 1716, "ppid": 660, "note": "Persistence service, listener on 5682"},
      {"name": "subject_ctrl", "pid": 7076, "ppid": 660, "note": "Malware controller"},
      {"name": "connector_ctrl", "pid": 6868, "ppid": 660, "note": "Malware connector"},
      {"name": "imager_ctrl.exe", "pid": 3324, "ppid": 660, "note": "Malware imager component"},
      {"name": "main_console", "pid": 6960, "ppid": 4508, "note": "Attacker console interface"},
      {"name": "ftusbsrvc.exe", "pid": 4916, "ppid": 660, "note": "USB service with C2 listener on 33001"}
    ],
    "c2_connections": [
      {"remote_ip": "108.79.235.64", "remote_port": 33000, "state": "ESTABLISHED", "note": "Primary external C2"},
      {"remote_ip": "172.16.4.10", "remote_port": 8080, "state": "CLOSED", "note": "Internal C2 relay (11+ beaconing connections)"}
    ],
    "lateral_movement": [
      {"remote_ip": "172.16.4.5", "remote_port": 445, "protocol": "SMB", "note": "SMB lateral movement"},
      {"remote_ip": "172.16.5.50", "remote_port": 445, "protocol": "SMB", "note": "SMB lateral movement"}
    ],
    "rootkit_indicators": [
      {"type": "DKOM", "note": "pslist returns empty header; all processes hidden from ActiveProcessLinks"},
      {"type": "VAD_hook", "note": "malfind returns empty; VAD walk blocked by rootkit"},
      {"type": "cmdline_suppression", "note": "cmdline returns empty; process args hidden"}
    ],
    "expected_psxview": {
      "all_processes_hidden_from_pslist": true,
      "psscan_finds_processes": true,
      "hidden_count_min": 30
    }
  }
}
TRUTH
        echo -e "${GREEN}[✓] Ground truth created${NC}"
    fi
}

# ── Run the agent ─────────────────────────────────────────────
run_agent() {
    echo -e "${BLUE}[*] Running LogPoseSIFT against evidence...${NC}"
    echo -e "    Evidence: $EVIDENCE_PATH"
    echo -e "    Type: $EVIDENCE_TYPE"
    echo ""

    TRIAGE_START=$(date +%s)
    AGENT_OUTPUT=$("$BINARY" --mode=ai --target="$EVIDENCE_PATH" --type="$EVIDENCE_TYPE" 2>&1 || true)
    TRIAGE_END=$(date +%s)
    TRIAGE_DURATION=$((TRIAGE_END - TRIAGE_START))

    echo -e "${GREEN}[✓] Agent completed in ${TRIAGE_DURATION}s${NC}"
    echo "$AGENT_OUTPUT" > "$RESULTS_DIR/agent_output_${TIMESTAMP}.txt"
}

# ── Score findings ─────────────────────────────────────────────
score_findings() {
    echo ""
    echo -e "${BLUE}[*] Scoring findings against ground truth...${NC}"

    local output_file="$RESULTS_DIR/agent_output_${TIMESTAMP}.txt"
    local agent_output
    agent_output=$(cat "$output_file" 2>/dev/null || echo "")
    local agent_lower
    agent_lower=$(echo "$agent_output" | tr '[:upper:]' '[:lower:]')

    # ── TRUE POSITIVES: known IOCs that the agent correctly identified ──

    local tp=0
    local fp=0
    local fn=0
    local tp_list=()
    local fn_list=()

    # Check malicious processes
    declare -A mal_processes=(
        ["usbclient.exe"]="primary implant"
        ["license_ctrl.exe"]="persistence service"
        ["subject_ctrl"]="malware controller"
        ["connector_ctrl"]="malware connector"
        ["main_console"]="attacker console"
        ["ftusbsrvc.exe"]="C2 listener service"
    )
    for proc in "${!mal_processes[@]}"; do
        proc_lower=$(echo "$proc" | tr '[:upper:]' '[:lower:]')
        if echo "$agent_lower" | grep -q "$proc_lower"; then
            tp=$((tp + 1))
            tp_list+=("PROCESS: $proc (${mal_processes[$proc]})")
        else
            fn=$((fn + 1))
            fn_list+=("PROCESS: $proc (${mal_processes[$proc]})")
        fi
    done

    # Check C2 connections
    declare -A c2_iocs=(
        ["108.79.235.64"]="external C2 IP"
        ["172.16.4.10"]="internal C2 relay"
        [":8080"]="C2 port 8080"
        [":33000"]="C2 port 33000"
    )
    for ioc in "${!c2_iocs[@]}"; do
        if echo "$agent_output" | grep -q "$ioc"; then
            tp=$((tp + 1))
            tp_list+=("NETWORK: $ioc (${c2_iocs[$ioc]})")
        else
            fn=$((fn + 1))
            fn_list+=("NETWORK: $ioc (${c2_iocs[$ioc]})")
        fi
    done

    # Check rootkit detection
    declare -A rootkit_iocs=(
        ["dkom"]="DKOM rootkit technique"
        ["rootkit"]="rootkit identified"
        ["pslist.*false.*psscan.*true"]="psxview DKOM detection"
    )
    for ioc in "${!rootkit_iocs[@]}"; do
        if echo "$agent_lower" | grep -qE "$ioc"; then
            tp=$((tp + 1))
            tp_list+=("ROOTKIT: ${rootkit_iocs[$ioc]}")
        else
            fn=$((fn + 1))
            fn_list+=("ROOTKIT: ${rootkit_iocs[$ioc]}")
        fi
    done

    # Check lateral movement
    if echo "$agent_output" | grep -q "172.16.4.5" || echo "$agent_output" | grep -q ":445"; then
        tp=$((tp + 1))
        tp_list+=("LATERAL: SMB lateral movement to internal hosts")
    else
        fn=$((fn + 1))
        fn_list+=("LATERAL: SMB lateral movement to 172.16.4.5/172.16.5.50:445")
    fi

    # ── FALSE POSITIVES: claims agent made that are NOT in ground truth ──
    # Check for hallucinated specifics
    hallucination_checks=(
        "cobalt strike"
        "mimikatz"
        "metasploit"
        "ransomware"
        "wannacry"
    )
    local hallucinations=()
    for claim in "${hallucination_checks[@]}"; do
        if echo "$agent_lower" | grep -q "$claim"; then
            # These MIGHT be real but are not documented in ground truth
            hallucinations+=("UNVERIFIED CLAIM: '$claim' — not in ground truth documentation")
            fp=$((fp + 1))
        fi
    done

    # ── Compute scores ──────────────────────────────────────────
    local total_iocs=$((tp + fn))
    local precision=0
    local recall=0
    local f1=0

    if [[ $((tp + fp)) -gt 0 ]]; then
        precision=$(echo "scale=2; $tp * 100 / ($tp + $fp)" | bc)
    fi
    if [[ $total_iocs -gt 0 ]]; then
        recall=$(echo "scale=2; $tp * 100 / $total_iocs" | bc)
    fi

    # ── Print results ───────────────────────────────────────────
    echo ""
    echo -e "${BOLD}══════════════ BENCHMARK RESULTS ══════════════${NC}"
    echo ""
    echo -e "  True Positives  (TP): ${GREEN}${BOLD}$tp${NC}"
    echo -e "  False Negatives (FN): ${YELLOW}$fn${NC}"
    echo -e "  False Positives (FP): ${RED}$fp${NC} (unverified claims)"
    echo -e "  Precision: ${BOLD}${precision}%${NC}"
    echo -e "  Recall:    ${BOLD}${recall}%${NC}"
    echo ""

    if [[ ${#tp_list[@]} -gt 0 ]]; then
        echo -e "${GREEN}  ✓ CORRECTLY IDENTIFIED:${NC}"
        for item in "${tp_list[@]}"; do
            echo -e "    ✓ $item"
        done
        echo ""
    fi

    if [[ ${#fn_list[@]} -gt 0 ]]; then
        echo -e "${YELLOW}  ~ MISSED FINDINGS:${NC}"
        for item in "${fn_list[@]}"; do
            echo -e "    ✗ $item"
        done
        echo ""
    fi

    if [[ ${#hallucinations[@]} -gt 0 ]]; then
        echo -e "${RED}  ! UNVERIFIED CLAIMS (check for hallucination):${NC}"
        for item in "${hallucinations[@]}"; do
            echo -e "    ! $item"
        done
        echo ""
    fi

    # ── Write JSON scorecard ─────────────────────────────────────
    python3 - << PYEOF
import json, datetime

scorecard = {
    "session": {
        "timestamp": "$TIMESTAMP",
        "evidence": "$EVIDENCE_PATH",
        "evidence_type": "$EVIDENCE_TYPE",
        "triage_duration_seconds": $TRIAGE_DURATION
    },
    "scores": {
        "true_positives": $tp,
        "false_negatives": $fn,
        "false_positives": $fp,
        "total_known_iocs": $total_iocs,
        "precision_pct": $precision,
        "recall_pct": $recall
    },
    "true_positives": [$(printf '"%s",' "${tp_list[@]}" | sed 's/,$//;s/,/","/g')],
    "false_negatives": [$(printf '"%s",' "${fn_list[@]}" | sed 's/,$//;s/,/","/g')],
    "unverified_claims": [$(printf '"%s",' "${hallucinations[@]}" | sed 's/,$//;s/,/","/g')]
}

with open("$OUTPUT_JSON", "w") as f:
    json.dump(scorecard, f, indent=2)

print(f"  Scorecard written: $OUTPUT_JSON")
PYEOF

    # ── Write Markdown report ────────────────────────────────────
    cat > "$OUTPUT_MD" << MDEOF
# LogPoseSIFT Accuracy Report

**Dataset:** SRL-2018 Compromised Enterprise Network  
**Evidence:** \`$EVIDENCE_PATH\`  
**Timestamp:** $TIMESTAMP  
**Triage Duration:** ${TRIAGE_DURATION}s  

## Scores

| Metric | Value |
|---|---|
| True Positives | **$tp** |
| False Negatives | $fn |
| False Positives (unverified) | $fp |
| Total Known IOCs | $total_iocs |
| Precision | **${precision}%** |
| Recall | **${recall}%** |

## Correctly Identified IOCs
$(for item in "${tp_list[@]}"; do echo "- ✓ $item"; done)

## Missed Findings
$(for item in "${fn_list[@]}"; do echo "- ✗ $item"; done)

## Unverified Claims (potential hallucinations)
$(for item in "${hallucinations[@]}"; do echo "- ⚠ $item"; done)

## Evidence Integrity

The agent computes SHA-256 and MD5 hashes of all evidence files at triage time.
No evidence files are modified — all Volatility and TSK operations are read-only.
MDEOF

    echo -e "${GREEN}  Markdown report: $OUTPUT_MD${NC}"
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
}

# ── Main ──────────────────────────────────────────────────────
main() {
    check_prereqs
    setup_ground_truth
    run_agent
    score_findings
    echo ""
    echo -e "${GREEN}${BOLD}Benchmark complete.${NC}"
    echo -e "Results in: $RESULTS_DIR/"
}

main "$@"