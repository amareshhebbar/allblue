package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/gvamaresh/allblue/agents/disk_agent"
	"github.com/gvamaresh/allblue/agents/memory_agent"
	"github.com/gvamaresh/allblue/agents/orchestrator"
	"github.com/gvamaresh/allblue/internal/correlator"
	"github.com/gvamaresh/allblue/internal/splunk"
	"github.com/gvamaresh/allblue/internal/wrappers"
)

func main() {
	mode        := flag.String("mode", "mcp", "Execution mode: 'mcp' or 'ai'")
	target      := flag.String("target", "", "Evidence file path (--mode=ai only)")
	evidenceType := flag.String("type", "memory", "Evidence type: memory | disk | both")
	splunkPush  := flag.Bool("splunk-push", false, "Push findings to Splunk HEC after triage")
	sessionID   := flag.String("session-id", "", "Optional session ID (auto-generated if empty)")
	flag.Parse()

	switch *mode {
	case "ai":
		if *target == "" {
			fmt.Println("[!] --target is required in ai mode.")
			os.Exit(1)
		}
		eng := orchestrator.NewEngine()
		eng.RunTriage(*target, *evidenceType)

		// Push findings to Splunk if requested
		if *splunkPush {
			sid := *sessionID
			if sid == "" {
				sid = fmt.Sprintf("allblue-%d", os.Getpid())
			}
			fmt.Printf("[SPLUNK] Pushing findings for session %s...\n", sid)
			summary := splunk.TriageSummary{
				SessionID:    sid,
				EvidenceFile: *target,
				EvidenceType: *evidenceType,
				AgentEngine:  "claude",
				TotalFindings: 1,
				Findings: []splunk.Finding{
					{
						SessionID:   sid,
						Severity:    "INFO",
						Category:    "triage",
						IOC:         "triage-complete",
						Description: "AllBlue triage completed — check session logs for findings",
						Confidence:  "CONFIRMED",
						Tool:        "orchestrator",
					},
				},
			}
			if err := splunk.PushFindings(summary); err != nil {
				fmt.Printf("[SPLUNK] Warning: push failed: %v\n", err)
			} else {
				fmt.Println("[SPLUNK] Findings pushed successfully")
			}
		}

	case "mcp":
		// Start Splunk webhook receiver in background
		go splunk.StartAlertWebhook()
		runMCPServer()

	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func runMCPServer() {
	fmt.Println("[*] Initializing AllBlue Custom MCP Server v2.0...")

	s := server.NewMCPServer("AllBlue-Engine", "2.0.0", server.WithLogging())

	mustStr := func(args map[string]interface{}, key string) (string, error) {
		v, ok := args[key]
		if !ok {
			return "", fmt.Errorf("required argument %q missing", key)
		}
		sv, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("argument %q must be a string", key)
		}
		return sv, nil
	}
	optStr := func(args map[string]interface{}, key string) string {
		if v, ok := args[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	getArgs := func(req mcp.CallToolRequest) map[string]interface{} {
		if m, ok := req.Params.Arguments.(map[string]interface{}); ok {
			return m
		}
		return map[string]interface{}{}
	}

	// ══════════════════════════════════════════════════════
	// MEMORY — raw Volatility plugins
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("analyze_memory_windows_info",
			mcp.WithDescription("Extract OS version and kernel details from a Windows memory dump."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.GetWindowsInfo(p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("analyze_memory_pslist",
			mcp.WithDescription("List running processes from a memory dump. Flags unusual names, parents, and orphaned PIDs."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.RunRegistryTool("vol_windows_pslist", p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("analyze_memory_netscan",
			mcp.WithDescription("List active and closed network connections. Identifies C2 IPs and lateral movement."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.RunRegistryTool("vol_windows_netscan", p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("analyze_memory_malfind",
			mcp.WithDescription("Detect code injection, process hollowing, shellcode. MZ header in writable memory = confirmed injection."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.RunRegistryTool("vol_windows_malfind", p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("analyze_memory_cmdline",
			mcp.WithDescription("Extract command line arguments. Flags powershell -enc, certutil, bitsadmin, net use."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.RunRegistryTool("vol_windows_cmdline", p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("hunt_memory_malware",
			mcp.WithDescription("AUTONOMOUS: full memory triage — pslist→netscan→malfind→cmdline→self-correction. Returns CONFIRMED/INFERRED/UNVERIFIED findings."),
			mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute path to memory dump.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "dump_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := memory_agent.HuntMalware(p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// DISK
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("analyze_disk_timeline",
			mcp.WithDescription("AUTONOMOUS: full disk triage — log2timeline→psort→FLS→mmls."),
			mcp.WithString("image_path", mcp.Required(), mcp.Description("Absolute path to disk image.")),
			mcp.WithString("output_csv", mcp.Required(), mcp.Description("Output path for timeline CSV.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			imgPath, err := mustStr(args, "image_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			outCSV, err := mustStr(args, "output_csv")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := disk_agent.ExtractAndParseTimeline(imgPath, outCSV)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	s.AddTool(
		mcp.NewTool("analyze_disk_fls",
			mcp.WithDescription("List all files and directories in a disk image filesystem."),
			mcp.WithString("image_path", mcp.Required(), mcp.Description("Absolute path to disk image.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p, err := mustStr(getArgs(req), "image_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, err := wrappers.RunRegistryTool("tsk_fls", p)
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// REGISTRY
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("analyze_registry",
			mcp.WithDescription("Extract Windows registry artifacts. Returns typed JSON with CONFIRMED/INFERRED confidence per artifact."),
			mcp.WithString("hive_path", mcp.Required(), mcp.Description("Absolute path to registry hive.")),
			mcp.WithString("hive_type", mcp.Required(), mcp.Description("system | software | ntuser | sam | security")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			hivePath, err := mustStr(args, "hive_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			hiveType, err := mustStr(args, "hive_type")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			result, execErr := wrappers.RunRegRipper(wrappers.RegRipperInput{
				HivePath: hivePath, HiveType: hiveType,
			})
			if execErr != nil { return mcp.NewToolResultError(execErr.Error()), nil }
			b, _ := result.ToJSON()
			return mcp.NewToolResultText(string(b)), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// YARA
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("run_yara_scan",
			mcp.WithDescription("Scan a file or directory with YARA rules."),
			mcp.WithString("rules_path", mcp.Required(), mcp.Description("Path to YARA rules file or directory.")),
			mcp.WithString("target_path", mcp.Required(), mcp.Description("File or directory to scan.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			rulesPath, err := mustStr(args, "rules_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			targetPath, err := mustStr(args, "target_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			result, execErr := wrappers.RunYara(wrappers.YaraInput{
				RulesPath: rulesPath, TargetPath: targetPath, Recursive: true,
			})
			if execErr != nil { return mcp.NewToolResultError(execErr.Error()), nil }
			b, _ := result.ToJSON()
			return mcp.NewToolResultText(string(b)), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// INTEGRITY
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("verify_hashes",
			mcp.WithDescription("Compute or audit SHA-256/MD5 hashes. Mode 'compute' generates hashset; 'audit' compares against known-good."),
			mcp.WithString("target_path", mcp.Required(), mcp.Description("File or directory to hash.")),
			mcp.WithString("mode", mcp.Required(), mcp.Description("compute | audit")),
			mcp.WithString("hashset_path", mcp.Description("Known-good hashset path (audit mode only).")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			targetPath, err := mustStr(args, "target_path")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			mode, err := mustStr(args, "mode")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			result, execErr := wrappers.RunHashdeep(wrappers.HashdeepInput{
				Mode:        wrappers.HashdeepMode(mode),
				TargetPath:  targetPath,
				HashsetPath: optStr(args, "hashset_path"),
				Recursive:   true,
			})
			if execErr != nil { return mcp.NewToolResultError(execErr.Error()), nil }
			b, _ := result.ToJSON()
			return mcp.NewToolResultText(string(b)), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// CORRELATION
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("correlate_findings",
			mcp.WithDescription("Cross-reference memory and disk findings. Detects fileless malware, timestomping, orphaned artefacts."),
			mcp.WithString("memory_output", mcp.Required(), mcp.Description("Raw output from hunt_memory_malware.")),
			mcp.WithString("disk_output", mcp.Required(), mcp.Description("Raw output from analyze_disk_timeline.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			memOut, err := mustStr(args, "memory_output")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			diskOut, err := mustStr(args, "disk_output")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			out, execErr := dispatchCorrelation(memOut, diskOut)
			if execErr != nil { return mcp.NewToolResultError(execErr.Error()), nil }
			return mcp.NewToolResultText(out), nil
		},
	)

	// ══════════════════════════════════════════════════════
	// SPLUNK TOOLS (3 new) — Splunk Agentic Ops Hackathon
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("push_findings_to_splunk",
			mcp.WithDescription("Push DFIR findings to Splunk HEC as structured IOC events. Call after triage to ship results to Splunk index=main."),
			mcp.WithString("session_id", mcp.Required(), mcp.Description("Triage session ID.")),
			mcp.WithString("evidence_file", mcp.Required(), mcp.Description("Evidence file that was triaged.")),
			mcp.WithString("findings_json", mcp.Required(), mcp.Description("JSON array of findings to push.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			sessionID, err := mustStr(args, "session_id")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			evidenceFile, err := mustStr(args, "evidence_file")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			findingsJSON, err := mustStr(args, "findings_json")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }

			var findings []splunk.Finding
			if jsonErr := json.Unmarshal([]byte(findingsJSON), &findings); jsonErr != nil {
				// Single finding fallback
				findings = []splunk.Finding{{
					SessionID:   sessionID,
					Severity:    "HIGH",
					Category:    "triage",
					IOC:         findingsJSON,
					Description: "Finding from AllBlue triage",
					Confidence:  "CONFIRMED",
					Tool:        "allblue",
				}}
			}

			summary := splunk.TriageSummary{
				SessionID:     sessionID,
				EvidenceFile:  evidenceFile,
				EvidenceType:  "memory",
				AgentEngine:   "claude",
				TotalFindings: len(findings),
				Findings:      findings,
			}
			if pushErr := splunk.PushFindings(summary); pushErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("HEC push failed: %v", pushErr)), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf(
				`{"status":"pushed","session_id":"%s","findings_count":%d,"splunk_index":"main"}`,
				sessionID, len(findings),
			)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("query_splunk_alerts",
			mcp.WithDescription("Query Splunk MCP Server for recent security alerts. Returns events from Splunk index matching the query."),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search terms e.g. 'malware suspicious powershell'")),
			mcp.WithString("time_range", mcp.Description("Time range e.g. -1h -24h -7d (default: -1h)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			query, err := mustStr(args, "query")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			timeRange := optStr(args, "time_range")
			if timeRange == "" { timeRange = "-1h" }

			client := splunk.NewSplunkMCPClient()
			results, queryErr := client.SearchAlerts(query, timeRange)
			if queryErr != nil {
				return mcp.NewToolResultText(fmt.Sprintf(
					`{"status":"unavailable","message":"Splunk MCP Server not reachable: %v","query":"%s"}`,
					queryErr, query,
				)), nil
			}
			b, _ := json.MarshalIndent(results, "", "  ")
			return mcp.NewToolResultText(string(b)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_splunk_context",
			mcp.WithDescription("Enrich a finding with historical Splunk data. Searches Splunk for past events related to an IP or process name."),
			mcp.WithString("ioc_type", mcp.Required(), mcp.Description("ip | process | hostname")),
			mcp.WithString("ioc_value", mcp.Required(), mcp.Description("The IOC value to enrich e.g. 192.168.1.100 or svchost.exe")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(req)
			iocType, err := mustStr(args, "ioc_type")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }
			iocValue, err := mustStr(args, "ioc_value")
			if err != nil { return mcp.NewToolResultError(err.Error()), nil }

			client := splunk.NewSplunkMCPClient()
			var results []map[string]interface{}
			var queryErr error

			switch iocType {
			case "ip":
				results, queryErr = client.EnrichIP(iocValue)
			case "process":
				results, queryErr = client.EnrichProcess(iocValue)
			default:
				results, queryErr = client.SearchAlerts(iocValue, "-24h")
			}

			if queryErr != nil {
				return mcp.NewToolResultText(fmt.Sprintf(
					`{"status":"unavailable","ioc_type":"%s","ioc_value":"%s","message":"Splunk MCP not reachable: %v"}`,
					iocType, iocValue, queryErr,
				)), nil
			}
			b, _ := json.MarshalIndent(map[string]interface{}{
				"ioc_type":  iocType,
				"ioc_value": iocValue,
				"results":   results,
				"count":     len(results),
			}, "", "  ")
			return mcp.NewToolResultText(string(b)), nil
		},
	)

	printToolSummary()
	fmt.Println("[*] Listening on stdio...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}

func dispatchCorrelation(memOutput, diskOutput string) (string, error) {
	engine := correlator.New("memory_agent", "disk_agent")

	memFindings := correlator.ParsePSList(memOutput)
	memFindings = append(memFindings, correlator.ParseNetScan(memOutput)...)
	memFindings = append(memFindings, correlator.ParseMalfind(memOutput)...)

	var diskFindings []correlator.DiskFinding
	for _, line := range strings.Split(diskOutput, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && len(line) > 4 {
			diskFindings = append(diskFindings, correlator.DiskFinding{
				Type: "timeline", Path: line, Details: line,
			})
		}
	}

	report := engine.Correlate(memFindings, diskFindings)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func printToolSummary() {
	tools := []string{
		"analyze_memory_windows_info", "analyze_memory_pslist",
		"analyze_memory_netscan",      "analyze_memory_malfind",
		"analyze_memory_cmdline",      "hunt_memory_malware",
		"analyze_disk_timeline",       "analyze_disk_fls",
		"analyze_registry",            "run_yara_scan",
		"verify_hashes",               "correlate_findings",
		"push_findings_to_splunk",     "query_splunk_alerts",
		"get_splunk_context",
	}
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Printf("  │         Registered MCP Tools (%d)               │\n", len(tools))
	fmt.Println("  ├──────────────────────────────────────────────────┤")
	for i, t := range tools {
		marker := "  "
		if i >= 12 { marker = "✦ " } // highlight new Splunk tools
		fmt.Printf("  │  %2d. %s%-43s│\n", i+1, marker, t)
	}
	fmt.Println("  └──────────────────────────────────────────────────┘")
}