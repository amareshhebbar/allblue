package memory_agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/gvamaresh/logposesift/internal/logger"
	"github.com/gvamaresh/logposesift/internal/validator"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

const agentName = "MemoryAgent"

func HuntMalware(dumpPath string) (string, error) {
	fmt.Printf("\n[MemoryAgent] Starting autonomous memory triage on: %s\n", dumpPath)
	log := logger.Get()

	var allFindings []string
	var confirmed, inferred, unverified int

	osInfo, err := runWithReasoning(log, dumpPath, "analyze_memory_windows_info",
		"Determine OS version and kernel to orient all subsequent analysis",
		"Expect Windows OS version, build, and kernel base address")
	if err == nil {
		conf := validator.QuickValidate("vol_windows_info", osInfo, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[OS INFO | %s]\n%s", conf, truncate(osInfo, 800)))
	}

	psOutput, err := runWithReasoning(log, dumpPath, "analyze_memory_pslist",
		"List all running processes to identify suspicious names, parent anomalies, and orphaned PIDs",
		"Expect standard Windows processes; flag unknown executables, cmd.exe children, svchost anomalies")
	if err == nil {
		conf := validator.QuickValidate("vol_windows_pslist", psOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[PROCESS LIST | %s]\n%s", conf, truncate(psOutput, 1200)))
	}

	netOutput, err := runWithReasoning(log, dumpPath, "analyze_memory_netscan",
		"Identify active and recently closed network connections to find C2 infrastructure",
		"Expect local connections; flag foreign IPs on non-standard ports, especially from non-browser processes")
	if err == nil {
		conf := validator.QuickValidate("vol_windows_netscan", netOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[NETWORK SCAN | %s]\n%s", conf, truncate(netOutput, 1200)))
	}

	malfindOutput, err := runMalfind(log, dumpPath)
	if err == nil && malfindOutput != "" {
		conf := validator.QuickValidate("vol_windows_malfind", malfindOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[MALFIND | %s]\n%s", conf, truncate(malfindOutput, 1000)))
	}

	cmdOutput, err := runCmdline(log, dumpPath)
	if err == nil && cmdOutput != "" {
		conf := validator.QuickValidate("vol_windows_cmdline", cmdOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[CMDLINE | %s]\n%s", conf, truncate(cmdOutput, 1000)))
	}

	if malfindOutput != "" && strings.Contains(malfindOutput, "Process:") {
		dllOutput, dllErr := runDLLCheck(log, dumpPath, extractSuspiciousPIDs(malfindOutput))
		if dllErr == nil && dllOutput != "" {
			conf := validator.QuickValidate("vol_windows_dlllist", dllOutput, "", "", "")
			trackConfidence(conf, &confirmed, &inferred, &unverified)
			allFindings = append(allFindings,
				fmt.Sprintf("[DLL CHECK (self-corrected, triggered by malfind) | %s]\n%s",
					conf, truncate(dllOutput, 800)))
		}
	}
	report := composeSummary(dumpPath, allFindings, confirmed, inferred, unverified)

	log.SessionSummary(confirmed, inferred, unverified, confirmed+inferred+unverified)
	return report, nil
}


func runWithReasoning(log *logger.Logger, dumpPath, tool, intent, hypothesis string) (string, error) {
	rec, start := logger.NewRecord(tool, agentName, intent, hypothesis)
	rec.Input = map[string]string{"dump_path": dumpPath}

	output, err := wrappers.RunRegistryTool(toolNameToRegistryKey(tool), dumpPath)

	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runMalfind(log *logger.Logger, dumpPath string) (string, error) {
	rec, start := logger.NewRecord("vol_windows_malfind", agentName,
		"Detect code injection, process hollowing, and shellcode in all processes",
		"Expect clean processes; any MZ header in writable memory = strong IOC")
	rec.Input = map[string]string{"dump_path": dumpPath}

	output, err := wrappers.RunRegistryTool("vol_windows_malfind", dumpPath)
	confidence := "UNVERIFIED"
	if err == nil {
		if strings.Contains(output, "MZ") || strings.Contains(output, "4d5a") {
			confidence = "CONFIRMED"
			rec.Delta = "MZ header found in non-executable memory region — confirmed code injection"
		} else if output != "" {
			confidence = "INFERRED"
		}
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runCmdline(log *logger.Logger, dumpPath string) (string, error) {
	rec, start := logger.NewRecord("vol_windows_cmdline", agentName,
		"Extract command line arguments to identify attacker tooling and lateral movement",
		"Expect benign system commands; flag powershell -enc, certutil downloads, net use commands")
	rec.Input = map[string]string{"dump_path": dumpPath}

	output, err := wrappers.RunRegistryTool("vol_windows_cmdline", dumpPath)
	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		suspiciousPatterns := []string{"-enc", "-EncodedCommand", "certutil", "bitsadmin",
			"net use", "net user", "reg add", "wscript", "cscript", "mshta"}
		for _, p := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(output), strings.ToLower(p)) {
				confidence = "CONFIRMED"
				rec.Delta = fmt.Sprintf("Suspicious command pattern detected: %q", p)
				break
			}
		}
		if confidence == "UNVERIFIED" {
			confidence = "INFERRED"
		}
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runDLLCheck(log *logger.Logger, dumpPath string, pids []string) (string, error) {
	if len(pids) == 0 {
		return "", nil
	}
	rec, start := logger.NewRecord("vol_windows_dlllist", agentName,
		fmt.Sprintf("Self-correction: check DLLs for processes flagged by malfind (PIDs: %s)", strings.Join(pids, ",")),
		"Expect legitimate system DLLs; flag unsigned DLLs from temp/download directories")
	rec.Input = map[string]string{"dump_path": dumpPath, "triggered_by": "malfind_self_correction"}

	output, err := wrappers.RunRegistryTool("vol_windows_dlllist", dumpPath)
	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}


func toolNameToRegistryKey(tool string) string {
	mapping := map[string]string{
		"analyze_memory_windows_info": "vol_windows_info",
		"analyze_memory_pslist":       "vol_windows_pslist",
		"analyze_memory_netscan":      "vol_windows_netscan",
		"vol_windows_malfind":         "vol_windows_malfind",
		"vol_windows_cmdline":         "vol_windows_cmdline",
		"vol_windows_dlllist":         "vol_windows_dlllist",
	}
	if key, ok := mapping[tool]; ok {
		return key
	}
	return tool 
}

func extractSuspiciousPIDs(malfindOutput string) []string {
	var pids []string
	for _, line := range strings.Split(malfindOutput, "\n") {
		if strings.HasPrefix(line, "Process:") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "PID:" && i+1 < len(fields) {
					pids = append(pids, fields[i+1])
				}
			}
		}
	}
	return pids
}

func trackConfidence(conf string, confirmed, inferred, unverified *int) {
	switch conf {
	case "CONFIRMED":
		*confirmed++
	case "INFERRED":
		*inferred++
	default:
		*unverified++
	}
}

func composeSummary(dumpPath string, findings []string, confirmed, inferred, unverified int) string {
	var sb strings.Builder
	sb.WriteString("══════════════════════════════════════════════\n")
	sb.WriteString("       MEMORY AGENT — TRIAGE REPORT\n")
	sb.WriteString("══════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("Source : %s\n", dumpPath))
	sb.WriteString(fmt.Sprintf("Time   : %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Confidence: ✓ %d CONFIRMED  ~ %d INFERRED  ? %d UNVERIFIED\n\n",
		confirmed, inferred, unverified))
	for _, f := range findings {
		sb.WriteString(f)
		sb.WriteString("\n\n")
	}
	sb.WriteString("══════════════════════════════════════════════\n")
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…[truncated]"
}