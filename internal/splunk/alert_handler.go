package splunk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
	"path/filepath"
)

type SplunkAlert struct {
	SearchName   string                 `json:"search_name"`
	ResultsLink  string                 `json:"results_link"`
	Owner        string                 `json:"owner"`
	App          string                 `json:"app"`
	Result       map[string]interface{} `json:"result"`
	SessionKey   string                 `json:"session_key"`
	TriggerTime  string                 `json:"trigger_time"`
}

type AlertResponse struct {
	Status     string `json:"status"`
	SessionID  string `json:"session_id"`
	Message    string `json:"message"`
	TriageURL  string `json:"triage_url,omitempty"`
}

func StartAlertWebhook() {
	mux := http.NewServeMux()
	mux.HandleFunc("/splunk-alert", handleSplunkAlert)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/status", handleStatus)

	addr := ":8718"
	fmt.Printf("[WEBHOOK] AllBlue alert receiver listening on %s\n", addr)
	fmt.Println("[WEBHOOK] Splunk can POST alerts to http://your-host:8718/splunk-alert")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[WEBHOOK] Failed to start: %v", err)
	}
}

func handleSplunkAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var alert SplunkAlert
	if err := json.Unmarshal(body, &alert); err != nil {
		fmt.Printf("[WEBHOOK] Received alert (non-JSON): %s\n", string(body))
	} else {
		fmt.Printf("[WEBHOOK] Received Splunk alert: %s\n", alert.SearchName)
	}

	sessionID := fmt.Sprintf("splunk-%d", time.Now().Unix())

	go triggerTriage(sessionID, alert)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(AlertResponse{
		Status:    "accepted",
		SessionID: sessionID,
		Message:   "allblue triage initiated",
	})
}

func triggerTriage(sessionID string, alert SplunkAlert) {
	fmt.Printf("[TRIAGE] Starting autonomous triage for session %s\n", sessionID)
	PushRawLog(sessionID, "INFO", fmt.Sprintf("Triage triggered by Splunk alert: %s", alert.SearchName))

	evidencePath := ""
	if alert.Result != nil {
		if path, ok := alert.Result["evidence_path"].(string); ok {
			evidencePath = path
		}
	}

	if evidencePath == "" {
		evidencePath = "/tmp/evidence/latest.img"
		fmt.Printf("[TRIAGE] No evidence path in alert, using default: %s\n", evidencePath)
	}

	cwd, err := os.Getwd()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get current directory: %v", err)
		fmt.Printf("[TRIAGE] ERROR: %s\n", errMsg)
		PushRawLog(sessionID, "ERROR", errMsg)
		return
	}

	aiExecutablePath := filepath.Join(cwd, "allblue-ai")

	cmd := exec.Command(aiExecutablePath,
		"--mode=ai",
		"--target="+evidencePath,
		"--type=memory",
		"--session-id="+sessionID,
		"--splunk-push=true",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := fmt.Sprintf("Triage failed: %v\nOutput: %s", err, string(output))
		fmt.Printf("[TRIAGE] %s\n", errMsg)
		PushRawLog(sessionID, "ERROR", errMsg)
		return
	}

	fmt.Printf("[TRIAGE] Session %s completed\n", sessionID)
	PushRawLog(sessionID, "INFO", "Triage completed successfully")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "allblue-webhook",
		"version": "2.0.0-splunk",
	})
}

var triageSessions []string

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_sessions": len(triageSessions),
		"sessions":        triageSessions,
	})
}