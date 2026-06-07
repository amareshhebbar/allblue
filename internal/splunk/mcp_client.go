package splunk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)


type SplunkMCPClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewSplunkMCPClient() *SplunkMCPClient {
	url := os.Getenv("SPLUNK_MCP_URL")
	if url == "" {
		url = "http://localhost:3000"
	}
	return &SplunkMCPClient{
		BaseURL: url,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *SplunkMCPClient) SearchAlerts(query string, timeRange string) ([]map[string]interface{}, error) {
	if timeRange == "" {
		timeRange = "-1h"
	}

	splunkQuery := fmt.Sprintf(
		`search index=main (sourcetype=syslog OR sourcetype=wineventlog) %s earliest=%s | head 50 | table _time, host, source, message`,
		query, timeRange,
	)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "search",
			"arguments": map[string]string{
				"query":      splunkQuery,
				"time_range": timeRange,
			},
		},
	}

	return c.callMCP(req)
}

func (c *SplunkMCPClient) EnrichIP(ip string) ([]map[string]interface{}, error) {
	query := fmt.Sprintf(`search index=main "%s" earliest=-24h | stats count by sourcetype, source | head 20`, ip)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "search",
			"arguments": map[string]string{
				"query":      query,
				"time_range": "-24h",
			},
		},
	}

	return c.callMCP(req)
}

func (c *SplunkMCPClient) EnrichProcess(processName string) ([]map[string]interface{}, error) {
	query := fmt.Sprintf(
		`search index=main (sourcetype=wineventlog EventCode=4688 OR sourcetype=sysmon EventCode=1) "%s" earliest=-7d | table _time, host, ParentProcessName, CommandLine | head 30`,
		processName,
	)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "search",
			"arguments": map[string]string{
				"query": query,
			},
		},
	}

	return c.callMCP(req)
}

func (c *SplunkMCPClient) callMCP(req MCPRequest) ([]map[string]interface{}, error) {
	payload, _ := json.Marshal(req)
	resp, err := c.HTTPClient.Post(c.BaseURL+"/mcp", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("splunk MCP call failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var mcpResp MCPResponse
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to parse MCP response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("MCP error %d: %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	resultBytes, _ := json.Marshal(mcpResp.Result)
	var results []map[string]interface{}
	if err := json.Unmarshal(resultBytes, &results); err != nil {
		var single map[string]interface{}
		_ = json.Unmarshal(resultBytes, &single)
		results = []map[string]interface{}{single}
	}

	return results, nil
}