
package reasoning_logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ReasoningRecord struct {
	Sequence int `json:"sequence"`
	Timestamp string `json:"timestamp"`
	Agent string `json:"agent"`
	Tool string `json:"tool"`
	Input interface{} `json:"input"`
	Intent string `json:"intent"`
	Hypothesis string `json:"hypothesis"`
	Result string `json:"result,omitempty"`
	Delta string `json:"delta,omitempty"`
	SelfCorrection bool `json:"self_correction,omitempty"`
	DurationMs int64 `json:"duration_ms"`
	Confidence string `json:"confidence"`
	Error string `json:"error,omitempty"`
	SessionID string `json:"session_id"`
}

type SessionReport struct {
	SessionID    string            `json:"session_id"`
	StartTime    string            `json:"start_time"`
	EndTime      string            `json:"end_time"`
	EvidencePath string            `json:"evidence_path"`
	EvidenceType string            `json:"evidence_type"`
	Records      []ReasoningRecord `json:"reasoning_chain"`
	Summary      SessionSummary    `json:"summary"`
}

type SessionSummary struct {
	TotalToolCalls int            `json:"total_tool_calls"`
	Confirmed      int            `json:"confirmed"`
	Inferred       int            `json:"inferred"`
	Unverified     int            `json:"unverified"`
	SelfCorrections int           `json:"self_corrections"`
	ByAgent        map[string]int `json:"by_agent"`
	IOCsFound      []string       `json:"iocs_found,omitempty"`
}

type ReasoningLogger struct {
	mu           sync.Mutex
	sessionID    string
	evidencePath string
	evidenceType string
	startTime    time.Time
	records      []ReasoningRecord
	logDir       string
	sequence     int
	iocs         []string
}

var global *ReasoningLogger
var once sync.Once

func Init(sessionID, logDir, evidencePath, evidenceType string) {
	once = sync.Once{}
	once.Do(func() {
		_ = os.MkdirAll(logDir, 0755)
		global = &ReasoningLogger{
			sessionID:    sessionID,
			evidencePath: evidencePath,
			evidenceType: evidenceType,
			startTime:    time.Now(),
			logDir:       logDir,
		}
	})
}

func Get() *ReasoningLogger {
	if global == nil {
		Init("noinit_"+time.Now().Format("150405"), "/tmp/allblue_reasoning",
			"unknown", "unknown")
	}
	return global
}

func (r *ReasoningLogger) Record(rec ReasoningRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++
	rec.Sequence = r.sequence
	rec.SessionID = r.sessionID
	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.records = append(r.records, rec)

	icon := confidenceIcon(rec.Confidence)
	correction := ""
	if rec.SelfCorrection {
		correction = " [SELF-CORRECTION]"
	}
	fmt.Printf("  %s [%s]%s %-28s | %dms | %s\n",
		icon, rec.Agent, correction, rec.Tool, rec.DurationMs, rec.Confidence)
	if rec.Delta != "" {
		fmt.Printf("    ↳ DELTA: %s\n", truncate(rec.Delta, 120))
	}
}

func (r *ReasoningLogger) AddIOC(ioc string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.iocs = append(r.iocs, ioc)
}

func (r *ReasoningLogger) WriteReport() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := r.buildSummary()
	report := SessionReport{
		SessionID:    r.sessionID,
		StartTime:    r.startTime.UTC().Format(time.RFC3339),
		EndTime:      time.Now().UTC().Format(time.RFC3339),
		EvidencePath: r.evidencePath,
		EvidenceType: r.evidenceType,
		Records:      r.records,
		Summary:      summary,
	}

	jsonPath := filepath.Join(r.logDir, r.sessionID+"_reasoning.json")
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("reasoning logger: marshal failed: %v", err)
	}
	if err := os.WriteFile(jsonPath, b, 0644); err != nil {
		return fmt.Errorf("reasoning logger: write failed: %v", err)
	}

	mdPath := filepath.Join(r.logDir, r.sessionID+"_reasoning.md")
	if err := os.WriteFile(mdPath, []byte(r.buildMarkdown(report)), 0644); err != nil {
		return fmt.Errorf("reasoning logger: markdown write failed: %v", err)
	}

	fmt.Printf("\n[ReasoningLogger] Audit trail written:\n  JSON: %s\n  Markdown: %s\n",
		jsonPath, mdPath)
	return nil
}

func (r *ReasoningLogger) PrintSummary() {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.buildSummary()
	fmt.Printf("\n╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║      AllBlue Reasoning Chain Summary     ║\n")
	fmt.Printf("╠══════════════════════════════════════════════╣\n")
	fmt.Printf("║  Session    : %-30s║\n", r.sessionID)
	fmt.Printf("║  Tool Calls : %-30d║\n", s.TotalToolCalls)
	fmt.Printf("║  ✓ CONFIRMED  : %-27d║\n", s.Confirmed)
	fmt.Printf("║  ~ INFERRED   : %-27d║\n", s.Inferred)
	fmt.Printf("║  ? UNVERIFIED : %-27d║\n", s.Unverified)
	fmt.Printf("║  Self-corrections: %-24d║\n", s.SelfCorrections)
	if len(r.iocs) > 0 {
		fmt.Printf("║  IOCs Found : %-30d║\n", len(r.iocs))
	}
	fmt.Printf("╚══════════════════════════════════════════════╝\n\n")
}


func (r *ReasoningLogger) buildSummary() SessionSummary {
	s := SessionSummary{
		TotalToolCalls: len(r.records),
		ByAgent:        make(map[string]int),
		IOCsFound:      r.iocs,
	}
	for _, rec := range r.records {
		switch rec.Confidence {
		case "CONFIRMED":
			s.Confirmed++
		case "INFERRED":
			s.Inferred++
		default:
			s.Unverified++
		}
		if rec.SelfCorrection {
			s.SelfCorrections++
		}
		s.ByAgent[rec.Agent]++
	}
	return s
}

func (r *ReasoningLogger) buildMarkdown(report SessionReport) string {
	var sb strings.Builder
	sb.WriteString("# AllBlue Reasoning Chain\n\n")
	sb.WriteString(fmt.Sprintf("**Session:** `%s`  \n", report.SessionID))
	sb.WriteString(fmt.Sprintf("**Evidence:** `%s` (%s)  \n", report.EvidencePath, report.EvidenceType))
	sb.WriteString(fmt.Sprintf("**Duration:** %s → %s  \n\n", report.StartTime, report.EndTime))

	sb.WriteString("## Summary\n\n")
	s := report.Summary
	sb.WriteString(fmt.Sprintf("| Metric | Value |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| Total tool calls | %d |\n", s.TotalToolCalls))
	sb.WriteString(fmt.Sprintf("| CONFIRMED findings | %d |\n", s.Confirmed))
	sb.WriteString(fmt.Sprintf("| INFERRED findings | %d |\n", s.Inferred))
	sb.WriteString(fmt.Sprintf("| UNVERIFIED findings | %d |\n", s.Unverified))
	sb.WriteString(fmt.Sprintf("| Self-corrections | %d |\n\n", s.SelfCorrections))

	if len(s.IOCsFound) > 0 {
		sb.WriteString("## IOCs Found\n\n")
		for _, ioc := range s.IOCsFound {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ioc))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Reasoning Chain\n\n")
	for _, rec := range report.Records {
		icon := confidenceIcon(rec.Confidence)
		correction := ""
		if rec.SelfCorrection {
			correction = " *(self-correction)*"
		}
		sb.WriteString(fmt.Sprintf("### %d. `%s` — %s [%s%s]%s\n\n",
			rec.Sequence, rec.Tool, rec.Agent, icon, rec.Confidence, correction))
		sb.WriteString(fmt.Sprintf("**Intent:** %s  \n", rec.Intent))
		sb.WriteString(fmt.Sprintf("**Hypothesis:** %s  \n", rec.Hypothesis))
		if rec.Result != "" {
			sb.WriteString(fmt.Sprintf("**Result:** `%s`  \n", truncate(rec.Result, 200)))
		}
		if rec.Delta != "" {
			sb.WriteString(fmt.Sprintf("**Delta:** ⚠ %s  \n", rec.Delta))
		}
		sb.WriteString(fmt.Sprintf("**Duration:** %dms | **Confidence:** %s\n\n", rec.DurationMs, rec.Confidence))
		sb.WriteString("---\n\n")
	}
	return sb.String()
}

func confidenceIcon(c string) string {
	switch c {
	case "CONFIRMED":
		return "✓ "
	case "INFERRED":
		return "~ "
	default:
		return "? "
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

type RecordBuilder struct {
	rec       ReasoningRecord
	startTime time.Time
	logger    *ReasoningLogger
}

func (r *ReasoningLogger) Start(tool, agent, intent, hypothesis string) *RecordBuilder {
	return &RecordBuilder{
		rec: ReasoningRecord{
			Tool:       tool,
			Agent:      agent,
			Intent:     intent,
			Hypothesis: hypothesis,
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		},
		startTime: time.Now(),
		logger:    r,
	}
}

func (b *RecordBuilder) SelfCorrection() *RecordBuilder {
	b.rec.SelfCorrection = true
	return b
}

func (b *RecordBuilder) WithInput(input interface{}) *RecordBuilder {
	b.rec.Input = input
	return b
}

func (b *RecordBuilder) Complete(result string, err error, confidence, delta string) {
	b.rec.DurationMs = time.Since(b.startTime).Milliseconds()
	b.rec.Result = truncate(result, 500)
	b.rec.Confidence = confidence
	b.rec.Delta = delta
	if err != nil {
		b.rec.Error = err.Error()
		b.rec.Confidence = "UNVERIFIED"
	}
	b.logger.Record(b.rec)
}