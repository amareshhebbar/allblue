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

	"github.com/gvamaresh/logposesift/agents/disk_agent"
	"github.com/gvamaresh/logposesift/agents/memory_agent"
	"github.com/gvamaresh/logposesift/agents/orchestrator"
	"github.com/gvamaresh/logposesift/internal/correlator"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

func main() {
	mode := flag.String("mode", "mcp", "Execution mode: 'mcp' or 'ai'")
	target := flag.String("target", "", "Evidence file path (--mode=ai only)")
	evidenceType := flag.String("type", "memory", "Evidence type: memory | disk | both")
	flag.Parse()

	switch *mode {
	case "ai":
		if *target == "" {
			fmt.Println("[!] --target is required in ai mode.")
			os.Exit(1)
		}
		eng := orchestrator.NewEngine()
		eng.RunTriage(*target, *evidenceType)
	case "mcp":
		runMCPServer()
	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func runMCPServer() {
	fmt.Println("[*] Initializing LogPoseSIFT Custom MCP Server v1.1...")

	s := server.NewMCPServer("LogPoseSIFT-Engine", "1.1.0", server.WithLogging())

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

	// ── Full autonomous memory triage ─────────────────────
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
	// DISK — timeline + filesystem
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("analyze_disk_timeline",
			mcp.WithDescription("AUTONOMOUS: full disk triage — log2timeline→psort→FLS→mmls. Self-corrects on sparse FLS."),
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
	// REGISTRY — RegRipper typed wrapper
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
	// YARA — pattern matching
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("run_yara_scan",
			mcp.WithDescription("Scan a file or directory with YARA rules. Returns matched rule names, tags, and string hit offsets."),
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
	// EVIDENCE INTEGRITY — hashdeep
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("verify_hashes",
			mcp.WithDescription("Compute or audit SHA-256/MD5 hashes. Mode 'compute' generates hashset; 'audit' compares against known-good. Returns CONFIRMED/MISMATCH/UNKNOWN per file."),
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
	// CORRELATION ENGINE — disk vs memory cross-reference
	// ══════════════════════════════════════════════════════

	s.AddTool(
		mcp.NewTool("correlate_findings",
			mcp.WithDescription("Cross-reference memory and disk findings. Detects: fileless malware (process in memory, no disk trace), timestomping (timestamp contradiction), orphaned disk artefacts. Returns CONFIRMED/SUSPICIOUS/CONTRADICTED per finding."),
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

	printToolSummary()
	fmt.Println("[*] Listening on stdio...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}

// dispatchCorrelation runs the correlator package directly.
func dispatchCorrelation(memOutput, diskOutput string) (string, error) {
	engine := correlator.New("memory_agent", "disk_agent")

	memFindings := correlator.ParsePSList(memOutput)
	memFindings = append(memFindings, correlator.ParseNetScan(memOutput)...)
	memFindings = append(memFindings, correlator.ParseMalfind(memOutput)...)

	// Build DiskFindings from raw text (each non-empty line = one disk artefact path)
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
	}
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Println("  │             Registered MCP Tools (12)            │")
	fmt.Println("  ├──────────────────────────────────────────────────┤")
	for i, t := range tools {
		fmt.Printf("  │  %2d. %-45s│\n", i+1, t)
	}
	fmt.Println("  └──────────────────────────────────────────────────┘")
}