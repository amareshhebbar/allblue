package splunk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type HECEvent struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host"`
	Source     string      `json:"source"`
	Sourcetype string      `json:"sourcetype"`
	Index      string      `json:"index"`
	Event      interface{} `json:"event"`
}

type Finding struct {
	SessionID   string   `json:"session_id"`
	Severity    string   `json:"severity"`    
	Category    string   `json:"category"`    
	IOC         string   `json:"ioc"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Confidence  string   `json:"confidence"`  
	Tool        string   `json:"tool"`
	Timestamp   string   `json:"timestamp"`
	ThreatScore int      `json:"threat_score"` 
}

type TriageSummary struct {
	SessionID     string    `json:"session_id"`
	EvidenceFile  string    `json:"evidence_file"`
	EvidenceType  string    `json:"evidence_type"`
	StartTime     string    `json:"start_time"`
	EndTime       string    `json:"end_time"`
	TotalFindings int       `json:"total_findings"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	OverallScore  int       `json:"overall_threat_score"`
	AgentEngine   string    `json:"agent_engine"` 
	Iterations    int       `json:"iterations"`
	Findings      []Finding `json:"findings"`
}

func PushFindings(summary TriageSummary) error {
	hecURL := os.Getenv("SPLUNK_HEC_URL")
	hecToken := os.Getenv("SPLUNK_HEC_TOKEN")

	if hecURL == "" || hecToken == "" {
		return fmt.Errorf("SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not set")
	}

	endpoint := hecURL + "/services/collector/event"

	summaryEvent := HECEvent{
		Time:       time.Now().Unix(),
		Host:       "allblue",
		Source:     "allblue:triage",
		Sourcetype: "allblue:summary",
		Index:      "main",
		Event:      summary,
	}

	if err := sendEvent(endpoint, hecToken, summaryEvent); err != nil {
		return fmt.Errorf("failed to push summary: %w", err)
	}

	for _, finding := range summary.Findings {
		findingEvent := HECEvent{
			Time:       time.Now().Unix(),
			Host:       "allblue",
			Source:     "allblue:finding",
			Sourcetype: "allblue:ioc",
			Index:      "main",
			Event:      finding,
		}
		if err := sendEvent(endpoint, hecToken, findingEvent); err != nil {
			fmt.Printf("[SPLUNK] Warning: failed to push finding %s: %v\n", finding.IOC, err)
		}
	}

	fmt.Printf("[SPLUNK] Pushed %d findings to Splunk HEC\n", len(summary.Findings))
	return nil
}

func sendEvent(endpoint, token string, event HECEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HEC returned status %d", resp.StatusCode)
	}
	return nil
}

func PushRawLog(sessionID, level, message string) {
	hecURL := os.Getenv("SPLUNK_HEC_URL")
	hecToken := os.Getenv("SPLUNK_HEC_TOKEN")
	if hecURL == "" || hecToken == "" {
		return
	}

	event := HECEvent{
		Time:       time.Now().Unix(),
		Host:       "allblue",
		Source:     "allblue:agent",
		Sourcetype: "allblue:log",
		Index:      "main",
		Event: map[string]string{
			"session_id": sessionID,
			"level":      level,
			"message":    message,
		},
	}

	endpoint := hecURL + "/services/collector/event"
	_ = sendEvent(endpoint, hecToken, event)
}