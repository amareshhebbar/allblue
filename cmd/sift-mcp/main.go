package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/gvamaresh/logposesift/agents/orchestrator"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

func main() {
	mode := flag.String("mode", "mcp", "Execution mode: 'mcp' to run the server, 'ai' to run the orchestrator")
	flag.Parse()

	if *mode == "ai" {
		runOrchestrator()
	} else if *mode == "mcp" {
		runMCPServer()
	} else {
		fmt.Printf("Unknown mode: %s. Please use --mode=mcp or --mode=ai\n", *mode)
		os.Exit(1)
	}
}

// ---------------------------------------------------------
// AI ORCHESTRATOR LOGIC (The "Brain")
// ---------------------------------------------------------
func runOrchestrator() {
	fmt.Println("[*] Booting LogPoseSIFT AI Orchestrator...")
	aiEngine := orchestrator.NewEngine()
	evidencePath := "/mnt/sift_data/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001" 
	aiEngine.RunTriage(evidencePath)
}

// ---------------------------------------------------------
// MCP SERVER LOGIC (The "Hands")
// ---------------------------------------------------------
func runMCPServer() {
	fmt.Println("[*] Initializing LogPoseSIFT Custom MCP Server...")

	s := server.NewMCPServer(
		"LogPoseSIFT-Engine",
		"1.0.0",
		server.WithLogging(),
	)

	windowsInfoTool := mcp.NewTool("analyze_memory_windows_info",
		mcp.WithDescription("Extracts basic OS information and kernel details from a Windows memory dump using Volatility 3."),
		mcp.WithString("dump_path", mcp.Required(), mcp.Description("Absolute file path to the memory dump.")),
	)

	s.AddTool(windowsInfoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("invalid arguments format from AI"), nil
		}
		dumpPath, ok := args["dump_path"].(string)
		if !ok {
			return mcp.NewToolResultError("dump_path argument is missing or not a string"), nil
		}
		output, err := wrappers.GetWindowsInfo(dumpPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Tool Execution Failed: %v", err)), nil
		}

		return mcp.NewToolResultText(output), nil
	})
	fmt.Println("[*] MCP Server is actively listening for AI commands...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}