package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gvamaresh/logposesift/agents/disk_agent"
	"github.com/gvamaresh/logposesift/agents/memory_agent"
	"github.com/gvamaresh/logposesift/internal/wrappers"
	"github.com/gvamaresh/logposesift/internal/logger"

	"github.com/google/generative-ai-go/genai"
	"github.com/joho/godotenv"
	"github.com/liushuangls/go-anthropic/v2"
	"google.golang.org/api/option"
)

type Engine struct {
	AnthropicClient *anthropic.Client
	AnthropicModel  anthropic.Model
	GeminiClient    *genai.Client
	GeminiModel     *genai.GenerativeModel
}

func NewEngine() *Engine {
	godotenv.Load()
	eng := &Engine{}

	antKey := os.Getenv("ANTHROPIC_API_KEY")
	if antKey != "" {
		eng.AnthropicClient = anthropic.NewClient(antKey)
		eng.AnthropicModel = anthropic.Model("claude-4-6-sonnet-latest")
	}

	gemKey := os.Getenv("GEMINI_API_KEY")
	if gemKey != "" {
		client, err := genai.NewClient(context.Background(), option.WithAPIKey(gemKey))
		if err == nil {
			eng.GeminiClient = client
			eng.GeminiModel = client.GenerativeModel("gemini-2.5-flash-lite")
		} else {
			fmt.Printf("Warning: Failed to initialize Gemini client: %v\n", err)
		}
	}

	if eng.AnthropicClient == nil && eng.GeminiClient == nil {
		log.Fatal("CRITICAL: Neither ANTHROPIC_API_KEY nor GEMINI_API_KEY is set in .env")
	}

	return eng
}

func (e *Engine) TestConnection() {
	fmt.Println("[*] Dual-Engine Bridge is Active.")
}

func (e *Engine) RunTriage(evidencePath string, evidenceType string) {
	fmt.Println("\n[*] AI Orchestrator initialized. Beginning autonomous triage...")

	prompt := fmt.Sprintf("You are LogPoseSIFT, an autonomous DFIR agent. I have a %s evidence file at: %s\nPlease run the appropriate tools or agents to triage this evidence, hunt for malware, and summarize the target system's status.", evidenceType, evidencePath)

	if e.AnthropicClient != nil {
		fmt.Println("[*] Primary Engine Selected: Claude 4.6 Sonnet")
		err := e.runClaude(prompt)
		if err != nil {
			fmt.Printf("\n[!] Claude Engine Failed: %v\n", err)
			fmt.Println("[*] ===================================================")
			fmt.Println("[*] FAILOVER TRIGGERED: Rerouting request to Gemini...")
			fmt.Println("[*] ===================================================")
			
			if e.GeminiClient != nil {
				err := e.runGemini(prompt)
				if err != nil {
					log.Fatalf("\n[!] FATAL: Gemini Engine Failed: %v\n", err)
				}
			} else {
				log.Fatal("Gemini fallback failed: No Gemini API Key configured.")
			}
		}
	} else if e.GeminiClient != nil {
		fmt.Println("[*] Primary Engine (Claude) missing. Defaulting to Gemini...")
		err := e.runGemini(prompt)
		if err != nil {
			log.Fatalf("\n[!] FATAL: Gemini Engine Failed: %v\n", err)
		}
	}
}

// ---------------------------------------------------------
// CLAUDE EXECUTION LOGIC (Merged Raw Tools + Agents)
// ---------------------------------------------------------

func (e *Engine) runClaude(prompt string) error {
	winInfoTool := anthropic.ToolDefinition{
		Name:        "analyze_memory_windows_info",
		Description: "Extracts basic OS info from a Windows memory dump using Volatility 3.",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"dump_path": map[string]interface{}{"type": "string", "description": "Absolute file path to the memory dump."}}, "required": []string{"dump_path"}},
	}
	psListTool := anthropic.ToolDefinition{
		Name:        "analyze_memory_pslist",
		Description: "Lists running processes to find malware.",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"dump_path": map[string]interface{}{"type": "string", "description": "Absolute file path to the memory dump."}}, "required": []string{"dump_path"}},
	}
	netScanTool := anthropic.ToolDefinition{
		Name:        "analyze_memory_netscan",
		Description: "Lists network connections to find attacker IPs.",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"dump_path": map[string]interface{}{"type": "string", "description": "Absolute file path to the memory dump."}}, "required": []string{"dump_path"}},
	}

	memoryAgentTool := anthropic.ToolDefinition{
		Name:        "hunt_memory_malware",
		Description: "Triggers the Memory Agent to automatically extract running processes and network connections to find malware.",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"dump_path": map[string]interface{}{"type": "string", "description": "Absolute file path to the memory dump."}}, "required": []string{"dump_path"}},
	}
	diskAgentTool := anthropic.ToolDefinition{
		Name:        "analyze_disk_timeline",
		Description: "Triggers the Disk Agent to extract a Plaso timeline and identify suspicious file activity.",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"image_path": map[string]interface{}{"type": "string", "description": "Absolute file path to the disk image."}, "output_csv": map[string]interface{}{"type": "string", "description": "Absolute path where the timeline CSV should be saved."}}, "required": []string{"image_path", "output_csv"}},
	}

	messages := []anthropic.Message{
		anthropic.NewUserTextMessage(prompt),
	}

	fmt.Println("[*] Sending task to Claude...")
	resp, err := e.AnthropicClient.CreateMessages(context.Background(), anthropic.MessagesRequest{
		Model:     e.AnthropicModel,
		Messages:  messages,
		MaxTokens: 2000,
		Tools:     []anthropic.ToolDefinition{winInfoTool, psListTool, netScanTool, memoryAgentTool, diskAgentTool},
	})

	if err != nil {
		return err 
	}

	var toolUse *anthropic.MessageContentToolUse
	for _, block := range resp.Content {
		if block.Type == anthropic.MessagesContentTypeToolUse {
			toolUse = block.MessageContentToolUse
			break
		}
	}

	if toolUse == nil {
		return fmt.Errorf("Claude decided not to use any tools")
	}

	fmt.Printf("\n[*] Claude requested tool: %s\n", toolUse.Name)

	var output string
	var executionErr error

	var args map[string]interface{}
	json.Unmarshal(toolUse.Input, &args)
	switch toolUse.Name {
	case "analyze_memory_windows_info":
		dumpPath := args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility on: %s\n", dumpPath)
		output, executionErr = wrappers.GetWindowsInfo(dumpPath)
	case "analyze_memory_pslist":
		dumpPath := args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility pslist on: %s\n", dumpPath)
		output, executionErr = wrappers.GetPSList(dumpPath)
	case "analyze_memory_netscan":
		dumpPath := args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility netscan on: %s\n", dumpPath)
		output, executionErr = wrappers.GetNetScan(dumpPath)
	case "hunt_memory_malware":
		dumpPath := args["dump_path"].(string)
		fmt.Println("[*] Routing to Memory Agent...")
		output, executionErr = memory_agent.HuntMalware(dumpPath)
	case "analyze_disk_timeline":
		imagePath := args["image_path"].(string)
		outputCsv := args["output_csv"].(string)
		fmt.Println("[*] Routing to Disk Agent...")
		output, executionErr = disk_agent.ExtractAndParseTimeline(imagePath, outputCsv)
	default:
		executionErr = fmt.Errorf("unknown tool requested by AI: %s", toolUse.Name)
	}
	
	toolResultContent := output
	if executionErr != nil {
		toolResultContent = fmt.Sprintf("Error: %v", executionErr)
	}

	messages = append(messages, anthropic.Message{
		Role:    anthropic.RoleAssistant,
		Content: resp.Content,
	})

	resultMap := map[string]interface{}{
		"type":        "tool_result",
		"tool_use_id": toolUse.ID,
		"content":     toolResultContent,
	}
	resultBytes, _ := json.Marshal(resultMap)
	var toolResultBlock anthropic.MessageContent
	json.Unmarshal(resultBytes, &toolResultBlock)

	messages = append(messages, anthropic.Message{
		Role: anthropic.RoleUser,
		Content: []anthropic.MessageContent{toolResultBlock},
	})

	finalResp, err := e.AnthropicClient.CreateMessages(context.Background(), anthropic.MessagesRequest{
		Model:     e.AnthropicModel,
		Messages:  messages,
		MaxTokens: 2000,
	})

	if err != nil {
		return err
	}

	fmt.Printf("\n================ CLAUDE'S FINAL REPORT ================\n")
	fmt.Println(finalResp.Content[0].Text)
	fmt.Printf("=======================================================\n\n")
	return nil
}

// ---------------------------------------------------------
// GEMINI EXECUTION LOGIC (Merged Raw Tools + Agents)
// ---------------------------------------------------------
func (e *Engine) runGemini(prompt string) error {
	ctx := context.Background()

	dumpPathSchema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"dump_path": {Type: genai.TypeString, Description: "Absolute file path to the memory dump."},
		},
		Required: []string{"dump_path"},
	}

	diskToolSchema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"image_path": {Type: genai.TypeString, Description: "Absolute file path to the disk image."},
			"output_csv": {Type: genai.TypeString, Description: "Absolute path where the timeline CSV should be saved."},
		},
		Required: []string{"image_path", "output_csv"},
	}

	// Supply BOTH raw wrappers AND high-level agents to Gemini
	allTools := &genai.Tool{
		FunctionDeclarations: []*genai.FunctionDeclaration{
			{Name: "analyze_memory_windows_info", Description: "Extracts basic OS info from a Windows memory dump using Volatility 3.", Parameters: dumpPathSchema},
			{Name: "analyze_memory_pslist", Description: "Lists running processes to find malware.", Parameters: dumpPathSchema},
			{Name: "analyze_memory_netscan", Description: "Lists network connections to find attacker IPs.", Parameters: dumpPathSchema},
			{Name: "hunt_memory_malware", Description: "Triggers the Memory Agent to extract running processes and network connections to find malware.", Parameters: dumpPathSchema},
			{Name: "analyze_disk_timeline", Description: "Triggers the Disk Agent to extract a Plaso timeline and identify suspicious file activity.", Parameters: diskToolSchema},
		},
	}
	e.GeminiModel.Tools = []*genai.Tool{allTools}

	session := e.GeminiModel.StartChat()

	fmt.Println("[*] Sending task to Gemini...")
	resp, err := session.SendMessage(ctx, genai.Text(prompt))
	if err != nil {
		return fmt.Errorf("Gemini API error: %v", err)
	}

	if len(resp.Candidates) == 0 {
		return fmt.Errorf("Gemini returned an empty response (possible safety block)")
	}

	var toolCall *genai.FunctionCall
	for _, part := range resp.Candidates[0].Content.Parts {
		if fc, ok := part.(genai.FunctionCall); ok {
			toolCall = &fc
			break
		}
	}

	if toolCall == nil {
		return fmt.Errorf("Gemini decided not to use any tools")
	}

	fmt.Printf("\n[*] Gemini requested tool: %s\n", toolCall.Name)

	var output string
	var executionErr error

	// Route to the appropriate wrapper OR agent based on Gemini's choice
	switch toolCall.Name {
	case "analyze_memory_windows_info":
		dumpPath := toolCall.Args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility on: %s\n", dumpPath)
		output, executionErr = wrappers.GetWindowsInfo(dumpPath)
	case "analyze_memory_pslist":
		dumpPath := toolCall.Args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility pslist on: %s\n", dumpPath)
		output, executionErr = wrappers.GetPSList(dumpPath)
	case "analyze_memory_netscan":
		dumpPath := toolCall.Args["dump_path"].(string)
		fmt.Printf("[*] Executing raw Volatility netscan on: %s\n", dumpPath)
		output, executionErr = wrappers.GetNetScan(dumpPath)
	case "hunt_memory_malware":
		dumpPath := toolCall.Args["dump_path"].(string)
		fmt.Println("[*] Routing to Memory Agent...")
		output, executionErr = memory_agent.HuntMalware(dumpPath)
	case "analyze_disk_timeline":
		imagePath := toolCall.Args["image_path"].(string)
		outputCsv := toolCall.Args["output_csv"].(string)
		fmt.Println("[*] Routing to Disk Agent...")
		output, executionErr = disk_agent.ExtractAndParseTimeline(imagePath, outputCsv)
	default:
		executionErr = fmt.Errorf("unknown tool requested by AI: %s", toolCall.Name)
	}
	
	toolResultContent := output
	if executionErr != nil {
		toolResultContent = fmt.Sprintf("Error: %v", executionErr)
	}

	finalResp, err := session.SendMessage(ctx, genai.FunctionResponse{
		Name: toolCall.Name,
		Response: map[string]any{
			"terminal_output": toolResultContent,
		},
	})
	
	if err != nil {
		return fmt.Errorf("Gemini final response error: %v", err)
	}

	fmt.Printf("\n================ GEMINI'S FINAL REPORT ================\n")
	for _, part := range finalResp.Candidates[0].Content.Parts {
		fmt.Println(part)
	}
	fmt.Printf("=======================================================\n\n")
	return nil
}