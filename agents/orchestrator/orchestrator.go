package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
	"strings" 

	"github.com/gvamaresh/logposesift/agents/disk_agent"
	"github.com/gvamaresh/logposesift/agents/memory_agent"
	"github.com/gvamaresh/logposesift/internal/correlator"
	"github.com/gvamaresh/logposesift/internal/logger"
	"github.com/gvamaresh/logposesift/internal/wrappers"

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
		eng.AnthropicModel = anthropic.Model("claude-sonnet-4-6")
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
func (e *Engine) RunTriage(evidencePath string, evidenceType string) {
	sessionID := fmt.Sprintf("triage_%s", time.Now().Format("20060102_150405"))
	if err := logger.Init(sessionID, "./logs"); err != nil {
		fmt.Printf("[!] Logger init failed: %v\n", err)
	}
 
	fmt.Printf("\n[*] LogPoseSIFT AI Orchestrator -- Session %s\n", sessionID)
	fmt.Printf("[*] Evidence: %s (type: %s)\n\n", evidencePath, evidenceType)
 
	// ── Run key tools BEFORE the AI loop ─────────────────────────────────────
	// This prevents Claude from ignoring real tool output in its final report.
	fmt.Println("[*] Running pre-triage to gather confirmed facts...")
	factSheet := PreTriage(evidencePath)
	fmt.Printf("[*] Pre-triage complete (%d chars of confirmed findings)\n\n", len(factSheet))
 
	// ── Build prompt with confirmed facts already embedded ────────────────────
	prompt := fmt.Sprintf(
		"You are LogPoseSIFT, an autonomous DFIR triage agent.\n"+
			"Evidence: %s | Type: %s\n\n"+
			"%s\n"+ // ← factSheet injected here
			"INSTRUCTIONS:\n"+
			"1. Use the confirmed findings above as your primary evidence base.\n"+
			"2. Run additional tools to gather more evidence (malfind, cmdline, dlllist, correlate).\n"+
			"3. Your final report MUST quote actual process names, PIDs, and IPs from the pre-triage data.\n"+
			"4. Tag every finding: CONFIRMED (from tool output), INFERRED (logical deduction), UNVERIFIED (needs more evidence).\n"+
			"5. Empty malfind/cmdline = rootkit hiding processes = CONFIRMED IOC — say so explicitly.\n"+
			"6. Write the report as a professional DFIR analyst would — specific, evidence-based, actionable.",
		evidencePath, evidenceType, factSheet)
 
	if e.AnthropicClient != nil {
		fmt.Println("[*] Primary Engine: Claude")
		if err := e.runClaude(prompt, evidencePath, evidenceType); err != nil {
			fmt.Printf("\n[!] Claude failed: %v\n[*] Failing over to Gemini...\n\n", err)
			if e.GeminiClient != nil {
				if err := e.runGemini(prompt, evidencePath, evidenceType); err != nil {
					log.Fatalf("[!] Gemini also failed: %v\n", err)
				}
			} else {
				log.Fatal("[!] No Gemini fallback configured.")
			}
		}
	} else if e.GeminiClient != nil {
		fmt.Println("[*] Primary Engine: Gemini")
		if err := e.runGemini(prompt, evidencePath, evidenceType); err != nil {
			log.Fatalf("[!] Gemini failed: %v\n", err)
		}
	}
}

// ── Tool definitions ──────────────────────────────────────────

func allToolDefs() []anthropic.ToolDefinition {
	dumpSchema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{"dump_path": map[string]interface{}{"type": "string", "description": "Absolute path to memory dump."}},
		"required":   []string{"dump_path"},
	}
	diskSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"image_path": map[string]interface{}{"type": "string", "description": "Absolute path to disk image."},
			"output_csv": map[string]interface{}{"type": "string", "description": "Path for output CSV."},
		},
		"required": []string{"image_path", "output_csv"},
	}
	hiveSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"hive_path": map[string]interface{}{"type": "string", "description": "Absolute path to registry hive file."},
			"hive_type": map[string]interface{}{"type": "string", "description": "Hive type: system|software|ntuser|sam|security"},
		},
		"required": []string{"hive_path", "hive_type"},
	}
	imageSchema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{"image_path": map[string]interface{}{"type": "string"}},
		"required":   []string{"image_path"},
	}
	yaraSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"rules_path":  map[string]interface{}{"type": "string", "description": "Path to YARA rules directory."},
			"target_path": map[string]interface{}{"type": "string", "description": "File or directory to scan."},
		},
		"required": []string{"rules_path", "target_path"},
	}
	hashSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target_path":  map[string]interface{}{"type": "string"},
			"mode":         map[string]interface{}{"type": "string", "description": "compute or audit"},
			"hashset_path": map[string]interface{}{"type": "string"},
		},
		"required": []string{"target_path", "mode"},
	}
	correlateSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"memory_output": map[string]interface{}{"type": "string", "description": "Raw output from memory agent."},
			"disk_output":   map[string]interface{}{"type": "string", "description": "Raw output from disk agent."},
		},
		"required": []string{"memory_output", "disk_output"},
	}

	return []anthropic.ToolDefinition{
		{Name: "analyze_memory_windows_info", Description: "Extract OS info from Windows memory dump.", InputSchema: dumpSchema},
		{Name: "analyze_memory_pslist", Description: "List running processes -- find malware by name/parent anomalies.", InputSchema: dumpSchema},
		{Name: "analyze_memory_netscan", Description: "List network connections -- find C2 IPs.", InputSchema: dumpSchema},
		{Name: "analyze_memory_malfind", Description: "Detect code injection and process hollowing.", InputSchema: dumpSchema},
		{Name: "analyze_memory_cmdline", Description: "Extract command lines -- find attacker tooling.", InputSchema: dumpSchema},
		{Name: "analyze_memory_dlllist", Description: "List loaded DLLs -- find unsigned/suspicious modules.", InputSchema: dumpSchema},
		{Name: "analyze_memory_filescan", Description: "Scan memory for file object references.", InputSchema: dumpSchema},
		{Name: "analyze_memory_pstree", Description: "Show process tree -- find orphaned and suspicious parent-child chains.", InputSchema: dumpSchema},
		{Name: "hunt_memory_malware", Description: "Full autonomous memory triage: pslist->netscan->malfind->cmdline->self-correction.", InputSchema: dumpSchema},
		{Name: "analyze_disk_timeline", Description: "Full disk triage: log2timeline -> psort -> FLS -> partition map.", InputSchema: diskSchema},
		{Name: "analyze_disk_fls", Description: "List files and directories in disk image.", InputSchema: imageSchema},
		{Name: "analyze_disk_mmls", Description: "Show partition layout of disk image.", InputSchema: imageSchema},
		{Name: "analyze_registry", Description: "Extract Windows registry artifacts (SAM, SOFTWARE, SYSTEM, NTUSER).", InputSchema: hiveSchema},
		{Name: "run_yara_scan", Description: "Scan file or directory with YARA rules for malware patterns.", InputSchema: yaraSchema},
		{Name: "verify_hashes", Description: "Compute or audit SHA-256/MD5 hashes for evidence integrity.", InputSchema: hashSchema},
		{Name: "correlate_findings", Description: "Cross-reference memory and disk findings. Detects fileless malware and timestomping.", InputSchema: correlateSchema},
	}
}

// ── Claude agentic loop ───────────────────────────────────────

func (e *Engine) runClaude(prompt, evidencePath, evidenceType string) error {
	messages := []anthropic.Message{anthropic.NewUserTextMessage(prompt)}
	tools := allToolDefs()
	findings := NewToolFindings() // ← tracks real output
 
	const maxIterations = 10
	for iteration := 0; iteration < maxIterations; iteration++ {
		fmt.Printf("[*] Claude iteration %d/%d\n", iteration+1, maxIterations)
 
		resp, err := e.AnthropicClient.CreateMessages(context.Background(), anthropic.MessagesRequest{
			Model:     e.AnthropicModel,
			Messages:  messages,
			MaxTokens: 8192,
			Tools:     tools,
		})
		if err != nil {
			return err
		}
 
		messages = append(messages, anthropic.Message{
			Role:    anthropic.RoleAssistant,
			Content: resp.Content,
		})
 
		if resp.StopReason == "end_turn" {
			fmt.Printf("\n================================ FINAL REPORT ================================\n")
			for _, block := range resp.Content {
				if block.Type == anthropic.MessagesContentTypeText && block.Text != nil {
					fmt.Println(*block.Text)
				}
			}
			fmt.Printf("==============================================================================\n\n")
			return nil
		}
 
		var toolResults []anthropic.MessageContent
		anyToolCalled := false
 
		for _, block := range resp.Content {
			if block.Type != anthropic.MessagesContentTypeToolUse {
				continue
			}
			toolUse := block.MessageContentToolUse
			anyToolCalled = true
 
			fmt.Printf("  -> Tool: %s\n", toolUse.Name)
			var args map[string]interface{}
			json.Unmarshal(toolUse.Input, &args)
 
			output, execErr := e.dispatchTool(toolUse.Name, args, evidenceType)
			resultContent := output
			if execErr != nil {
				resultContent = fmt.Sprintf("ERROR: %v", execErr)
				fmt.Printf("    [!] Error: %v\n", execErr)
			} else {
				fmt.Printf("    [ok] %d chars returned\n", len(output))
				findings.Record(toolUse.Name, output) // ← record every real output
			}
 
			resultMap := map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": toolUse.ID,
				"content":     resultContent,
			}
			resultBytes, _ := json.Marshal(resultMap)
			var resultBlock anthropic.MessageContent
			json.Unmarshal(resultBytes, &resultBlock)
			toolResults = append(toolResults, resultBlock)
		}
 
		if !anyToolCalled {
    // Claude stopped calling tools — check if it wrote a text response
    for _, block := range resp.Content {
        if block.Type == anthropic.MessagesContentTypeText && block.Text != nil {
            fmt.Printf("\n================================ FINAL REPORT ================================\n")
            fmt.Println(*block.Text)
            fmt.Printf("==============================================================================\n\n")
            return nil
        }
    }
    // No text either — send a nudge
    nudge := "Based on the pre-triage data and tools you have run, please now write your complete DFIR triage report. Quote actual process names, PIDs, and IPs from the confirmed findings."
    messages = append(messages, anthropic.Message{
        Role: anthropic.RoleUser,
        Content: []anthropic.MessageContent{{
            Type: anthropic.MessagesContentTypeText,
            Text: &nudge,
        }},
    })
    continue
}
 
		messages = append(messages, anthropic.Message{
			Role:    anthropic.RoleUser,
			Content: toolResults,
		})
	}
 
	return fmt.Errorf("reached max iterations (%d) without end_turn", maxIterations)
}
 
// Append this to agents/orchestrator/findings_extractor.go

func (f *ToolFindings) BuildSummary() string {
	var sb strings.Builder
	sb.WriteString("=== ADDITIONAL TOOL OUTPUT COLLECTED DURING AI LOOP ===\n\n")

	if f.PScanOutput != "" && len(f.PScanOutput) > 100 {
		sb.WriteString("PROCESS SCAN:\n")
		chunk := f.PScanOutput
		if len(chunk) > 1500 {
			chunk = chunk[:1500] + "\n...[truncated]"
		}
		sb.WriteString(chunk + "\n\n")
	}

	if f.NetScanOutput != "" && len(f.NetScanOutput) > 100 {
		sb.WriteString("NETWORK SCAN:\n")
		chunk := f.NetScanOutput
		if len(chunk) > 1500 {
			chunk = chunk[:1500] + "\n...[truncated]"
		}
		sb.WriteString(chunk + "\n\n")
	}

	if len(f.OtherOutputs) > 0 {
		for tool, out := range f.OtherOutputs {
			sb.WriteString(fmt.Sprintf("%s:\n%s\n\n", tool, out))
		}
	}

	sb.WriteString("=== USE THE ABOVE IN YOUR FINAL REPORT ===\n")
	return sb.String()
}
// ── Gemini agentic loop ───────────────────────────────────────

func (e *Engine) runGemini(prompt, evidencePath, evidenceType string) error {
	ctx := context.Background()

	dumpSchema := &genai.Schema{
		Type:       genai.TypeObject,
		Properties: map[string]*genai.Schema{"dump_path": {Type: genai.TypeString}},
		Required:   []string{"dump_path"},
	}
	diskSchema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"image_path": {Type: genai.TypeString},
			"output_csv": {Type: genai.TypeString},
		},
		Required: []string{"image_path", "output_csv"},
	}
	correlateSchema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"memory_output": {Type: genai.TypeString},
			"disk_output":   {Type: genai.TypeString},
		},
		Required: []string{"memory_output", "disk_output"},
	}

	e.GeminiModel.Tools = []*genai.Tool{{
		FunctionDeclarations: []*genai.FunctionDeclaration{
			{Name: "analyze_memory_windows_info", Description: "Extract OS info from Windows memory dump.", Parameters: dumpSchema},
			{Name: "analyze_memory_pslist", Description: "List running processes.", Parameters: dumpSchema},
			{Name: "analyze_memory_netscan", Description: "List network connections.", Parameters: dumpSchema},
			{Name: "analyze_memory_malfind", Description: "Detect code injection.", Parameters: dumpSchema},
			{Name: "analyze_memory_cmdline", Description: "Extract command lines.", Parameters: dumpSchema},
			{Name: "hunt_memory_malware", Description: "Full autonomous memory triage.", Parameters: dumpSchema},
			{Name: "analyze_disk_timeline", Description: "Full disk triage.", Parameters: diskSchema},
			{Name: "correlate_findings", Description: "Cross-reference memory and disk findings.", Parameters: correlateSchema},
		},
	}}

	session := e.GeminiModel.StartChat()
	const maxIterations = 10

	// FIX 1: declare currentMsg as genai.Part interface, not genai.Text
	// This allows reassignment to genai.FunctionResponse later in the loop.
	var currentMsg genai.Part = genai.Text(prompt)

	for iteration := 0; iteration < maxIterations; iteration++ {
		fmt.Printf("[*] Gemini iteration %d/%d\n", iteration+1, maxIterations)

		resp, err := session.SendMessage(ctx, currentMsg)
		if err != nil {
			return fmt.Errorf("Gemini API error: %v", err)
		}
		if len(resp.Candidates) == 0 {
			return fmt.Errorf("Gemini returned empty response")
		}

		var toolCalls []genai.FunctionCall
		for _, part := range resp.Candidates[0].Content.Parts {
			if fc, ok := part.(genai.FunctionCall); ok {
				toolCalls = append(toolCalls, fc)
			}
		}

		if len(toolCalls) == 0 {
			fmt.Printf("\n================================ GEMINI FINAL REPORT ================================\n")
			for _, part := range resp.Candidates[0].Content.Parts {
				if text, ok := part.(genai.Text); ok {
					fmt.Println(string(text))
				}
			}
			fmt.Printf("=====================================================================================\n\n")
			return nil
		}

		tc := toolCalls[0]
		fmt.Printf("  -> Tool: %s\n", tc.Name)

		argsMap := make(map[string]interface{})
		for k, v := range tc.Args {
			argsMap[k] = v
		}

		output, execErr := e.dispatchTool(tc.Name, argsMap, evidenceType)
		resultContent := output
		if execErr != nil {
			resultContent = fmt.Sprintf("ERROR: %v", execErr)
		}

		// FIX 1 continued: assign FunctionResponse to genai.Part variable -- now works
		currentMsg = genai.FunctionResponse{
			Name:     tc.Name,
			Response: map[string]any{"terminal_output": resultContent},
		}
	}
	return fmt.Errorf("Gemini reached max iterations (%d)", maxIterations)
}

// ── Tool dispatcher ───────────────────────────────────────────

func (e *Engine) dispatchTool(name string, args map[string]interface{}, evidenceType string) (string, error) {
	str := func(key string) string {
		if v, ok := args[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	switch name {
	case "analyze_memory_windows_info":
		return wrappers.GetWindowsInfo(str("dump_path"))

	// FIX 2: GetPSList does not exist -- use RunRegistryTool
	case "analyze_memory_pslist":
		return wrappers.RunRegistryTool("vol_windows_pslist", str("dump_path"))

	// FIX 3: GetNetScan does not exist -- use RunRegistryTool
	case "analyze_memory_netscan":
		return wrappers.RunRegistryTool("vol_windows_netscan", str("dump_path"))

	case "analyze_memory_malfind":
		return wrappers.RunRegistryTool("vol_windows_malfind", str("dump_path"))
	case "analyze_memory_cmdline":
		return wrappers.RunRegistryTool("vol_windows_cmdline", str("dump_path"))
	case "analyze_memory_dlllist":
		return wrappers.RunRegistryTool("vol_windows_dlllist", str("dump_path"))
	case "analyze_memory_filescan":
		return wrappers.RunRegistryTool("vol_windows_filescan", str("dump_path"))
	case "analyze_memory_pstree":
		return wrappers.RunRegistryTool("vol_windows_pstree", str("dump_path"))
	case "hunt_memory_malware":
		return memory_agent.HuntMalware(str("dump_path"))
	case "analyze_disk_timeline":
		return disk_agent.ExtractAndParseTimeline(str("image_path"), str("output_csv"))
	case "analyze_disk_fls":
		return wrappers.RunRegistryTool("tsk_fls", str("image_path"))
	case "analyze_disk_mmls":
		return wrappers.RunRegistryTool("tsk_mmls", str("image_path"))

	case "analyze_registry":
		result, err := wrappers.RunRegRipper(wrappers.RegRipperInput{
			HivePath: str("hive_path"),
			HiveType: str("hive_type"),
		})
		if err != nil {
			return "", err
		}
		b, _ := result.ToJSON()
		return string(b), nil

	case "run_yara_scan":
		result, err := wrappers.RunYara(wrappers.YaraInput{
			RulesPath:  str("rules_path"),
			TargetPath: str("target_path"),
			Recursive:  true,
		})
		if err != nil {
			return "", err
		}
		b, _ := result.ToJSON()
		return string(b), nil

	case "verify_hashes":
		result, err := wrappers.RunHashdeep(wrappers.HashdeepInput{
			Mode:        wrappers.HashdeepMode(str("mode")),
			TargetPath:  str("target_path"),
			HashsetPath: str("hashset_path"),
			Recursive:   true,
		})
		if err != nil {
			return "", err
		}
		b, _ := result.ToJSON()
		return string(b), nil

	case "correlate_findings":
		return runCorrelation(str("memory_output"), str("disk_output"))

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// ── Correlator runner ─────────────────────────────────────────

func runCorrelation(memOutput, diskOutput string) (string, error) {
	rec, start := logger.NewRecord(
		"correlate_findings", "Orchestrator",
		"Cross-reference memory and disk findings to detect fileless malware and timestomping",
		"Expect CONFIRMED for legit processes; SUSPICIOUS for fileless; CONTRADICTED for timestomped",
	)
	rec.Input = map[string]string{
		"memory_chars": fmt.Sprintf("%d", len(memOutput)),
		"disk_chars":   fmt.Sprintf("%d", len(diskOutput)),
	}

	eng := correlator.New("memory_agent_output", "disk_agent_output")

	memFindings := correlator.ParsePSList(memOutput)
	memFindings = append(memFindings, correlator.ParseNetScan(memOutput)...)
	memFindings = append(memFindings, correlator.ParseMalfind(memOutput)...)

	var diskFindings []correlator.DiskFinding
	for _, line := range splitLines(diskOutput) {
		if len(line) > 4 {
			diskFindings = append(diskFindings, correlator.DiskFinding{
				Type: "timeline", Path: line, Details: line,
			})
		}
	}

	report := eng.Correlate(memFindings, diskFindings)

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.Finish(&rec, start, "marshal error", err, "UNVERIFIED")
		return "", err
	}

	// FIX 4: HighCount is inside Summary, not at report top level
	confidence := "INFERRED"
	if report.Summary.HighCount > 0 {
		confidence = "CONFIRMED"
	}
	logger.Finish(&rec, start,
		fmt.Sprintf("%d results, %d high", len(report.Results), report.Summary.HighCount),
		nil, confidence)

	return string(b), nil
}

// ── String helpers (no stdlib strings import needed) ──────────

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := trimSpace(s[start:i])
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		if line := trimSpace(s[start:]); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}