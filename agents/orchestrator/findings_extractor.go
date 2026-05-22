package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type ToolFindings struct {
	PScanOutput   string
	NetScanOutput string
	OtherOutputs  map[string]string
}

func NewToolFindings() *ToolFindings {
	return &ToolFindings{OtherOutputs: make(map[string]string)}
}

func (f *ToolFindings) Record(toolName, output string) {
	switch toolName {
	case "analyze_memory_pslist":
		f.PScanOutput = output
	case "analyze_memory_netscan":
		f.NetScanOutput = output
	}
}

func PreTriage(evidencePath string) string {
	var sb strings.Builder
	sb.WriteString("=== PRE-TRIAGE: CONFIRMED TOOL OUTPUT — MUST USE IN REPORT ===\n\n")

	// psscan
	fmt.Print("[*] Pre-triage: running psscan... ")
	psscanOut := runVol(evidencePath, "windows.psscan")
	if len(psscanOut) > 200 {
		fmt.Printf("got %d chars\n", len(psscanOut))
		sb.WriteString("PROCESS SCAN (psscan) OUTPUT:\n")
		chunk := psscanOut
		if len(chunk) > 3000 {
			chunk = chunk[:3000] + "\n...[truncated]"
		}
		sb.WriteString(chunk + "\n\n")

		suspicious := extractSuspiciousProcesses(psscanOut)
		if len(suspicious) > 0 {
			sb.WriteString("⚠ SUSPICIOUS PROCESSES DETECTED:\n")
			for _, p := range suspicious {
				sb.WriteString("  → " + p + "\n")
			}
			sb.WriteString("\n")
		}
	} else {
		fmt.Println("empty")
		sb.WriteString("psscan returned no processes.\n\n")
	}
	fmt.Print("[*] Pre-triage: running netscan... ")
	netscanOut := runVol(evidencePath, "windows.netscan")
	if len(netscanOut) > 200 {
		fmt.Printf("got %d chars\n", len(netscanOut))
		sb.WriteString("NETWORK SCAN (netscan) OUTPUT:\n")
		chunk := netscanOut
		if len(chunk) > 3000 {
			chunk = chunk[:3000] + "\n...[truncated]"
		}
		sb.WriteString(chunk + "\n\n")

		c2 := extractC2Connections(netscanOut)
		if len(c2) > 0 {
			sb.WriteString("⚠ SUSPICIOUS NETWORK CONNECTIONS:\n")
			for _, c := range c2 {
				sb.WriteString("  → " + c + "\n")
			}
			sb.WriteString("\n")
		}
	} else {
		fmt.Println("empty")
		sb.WriteString("netscan returned no connections.\n\n")
	}
	fmt.Print("[*] Pre-triage: running windows.info... ")
	infoOut := runVol(evidencePath, "windows.info")
	if len(infoOut) > 100 {
		fmt.Printf("got %d chars\n", len(infoOut))
		sb.WriteString("WINDOWS INFO:\n" + infoOut + "\n\n")
	} else {
		fmt.Println("empty")
	}

	sb.WriteString("=== END PRE-TRIAGE DATA ===\n")
	sb.WriteString("YOUR REPORT MUST QUOTE ACTUAL PROCESS NAMES, PIDS, AND IPS FROM ABOVE.\n\n")
	return sb.String()
}

func runVol(imagePath, plugin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "vol", "-f", imagePath, plugin)
	cmd.Stdout = &out
	_ = cmd.Run()
	return out.String()
}

var knownGoodProcesses = map[string]bool{
	"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "services.exe": true, "lsass.exe": true,
	"svchost.exe": true, "spoolsv.exe": true, "explorer.exe": true,
	"taskhostw.exe": true, "dwm.exe": true, "sihost.exe": true,
	"runtimebroker.": true, "searchui.exe": true, "searchindexer.": true,
	"applicationfra": true, "shellexperienc": true, "microsoftedge.": true,
	"microsoftedgec": true, "onedrive.exe": true, "vmtoolsd.exe": true,
	"vgauthservice.": true, "msmpseng.exe": true, "nissrv.exe": true,
	"memcompression": true, "fontdrvhost.ex": true, "wudfshost.exe": true,
	"wudfhost.exe": true, "dllhost.exe": true, "conhost.exe": true,
	"userinit.exe": true, "hxoutlook.exe": true, "hxtsr.exe": true,
	"msascuil.exe": true, "skypehost.exe": true, "browser_broker": true,
	"systemsettings": true, "wmiprvse.exe": true, "msdtc.exe": true,
	"msiexec.exe": true, "installAgent.e": true, "ftk imager.exe": true,
	"accessdata_ftk": true, "ruby.exe": true, "rubyw.exe": true,
	"mctray.exe": true, "masvc.exe": true, "macmnsvc.exe": true,
	"macompatsvc.ex": true, "mfemactl.exe": true, "armsvc.exe": true,
	"ftusbsrvc.exe": true, "updaterrui.exe": true, "wmiprvsé.exe": true,
}

func extractSuspiciousProcesses(output string) []string {
	var suspicious []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") ||
			strings.HasPrefix(line, "Volatility") || strings.HasPrefix(line, "Offset") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var procName, pid, ppid string
		if isNumeric(fields[0]) {
			pid = fields[0]
			if len(fields) > 1 {
				ppid = fields[1]
			}
			if len(fields) > 2 {
				procName = strings.ToLower(fields[2])
			}
		} else {
			procName = strings.ToLower(fields[0])
			if len(fields) > 1 {
				pid = fields[1]
			}
			if len(fields) > 2 {
				ppid = fields[2]
			}
		}
		if procName == "" || knownGoodProcesses[procName] {
			continue
		}
		key := procName + pid
		if seen[key] {
			continue
		}
		seen[key] = true
		suspicious = append(suspicious, fmt.Sprintf("PID=%s PPID=%s %s", pid, ppid, fields[0]))
	}
	return suspicious
}

func extractC2Connections(output string) []string {
	var c2 []string
	seen := map[string]bool{}
	suspiciousPorts := map[string]bool{
		"8080": true, "4444": true, "1337": true, "9999": true, "6666": true,
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "LISTENING") || strings.Contains(line, "0.0.0.0") ||
			strings.HasPrefix(line, "Offset") || strings.HasPrefix(line, "Volatility") {
			continue
		}
		for port := range suspiciousPorts {
			if strings.Contains(line, ":"+port) {
				trimmed := strings.TrimSpace(line)
				if !seen[trimmed] {
					seen[trimmed] = true
					c2 = append(c2, trimmed[:minInt(len(trimmed), 150)])
				}
			}
		}
		if (strings.Contains(line, "CLOSED") || strings.Contains(line, "ESTABLISHED")) &&
			!strings.Contains(line, "0.0.0.0") && !strings.Contains(line, "127.0.0") {
			trimmed := strings.TrimSpace(line)
			if !seen[trimmed] && len(trimmed) > 20 {
				seen[trimmed] = true
				c2 = append(c2, trimmed[:minInt(len(trimmed), 150)])
			}
		}
	}
	return c2
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}