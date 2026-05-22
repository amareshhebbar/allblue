package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ToolCallRecord struct {
	SessionID   string      `json:"session_id"`
	Sequence    int         `json:"sequence"`
	Timestamp   string      `json:"timestamp"`
	Tool        string      `json:"tool"`
	Input       interface{} `json:"input"`
	Output      interface{} `json:"output,omitempty"`
	Error       string      `json:"error,omitempty"`
	DurationMs  int64       `json:"duration_ms"`
	Confidence  string      `json:"confidence"`         
	Intent      string      `json:"intent"`             
	Hypothesis  string      `json:"hypothesis"`          
	Delta       string      `json:"delta,omitempty"`     
	Agent       string      `json:"agent"`               
	TokensUsed  int         `json:"tokens_used,omitempty"`
}

type AgentMessage struct {
	SessionID string `json:"session_id"`
	Timestamp string `json:"timestamp"`
	From      string `json:"from"`
	To        string `json:"to"`
	MessageType string `json:"message_type"` 
	Content   string `json:"content"`
}

type Logger struct {
	mu        sync.Mutex
	sessionID string
	logDir    string
	toolFile  *os.File
	msgFile   *os.File
	sequence  int
}

var globalLogger *Logger
var once sync.Once

func Init(sessionID, logDir string) error {
	var initErr error
	once = sync.Once{} 
	once.Do(func() {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			initErr = fmt.Errorf("logger: cannot create log dir: %v", err)
			return
		}
		tf, err := os.Create(filepath.Join(logDir, sessionID+"_tools.jsonl"))
		if err != nil {
			initErr = err
			return
		}
		mf, err := os.Create(filepath.Join(logDir, sessionID+"_messages.jsonl"))
		if err != nil {
			initErr = err
			return
		}
		globalLogger = &Logger{
			sessionID: sessionID,
			logDir:    logDir,
			toolFile:  tf,
			msgFile:   mf,
		}
	})
	return initErr
}

func Get() *Logger {
	if globalLogger == nil {
		_ = Init("fallback_"+time.Now().Format("20060102_150405"), "/tmp/logposesift_logs")
	}
	return globalLogger
}

func (l *Logger) LogToolCall(record ToolCallRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sequence++
	record.SessionID = l.sessionID
	record.Sequence = l.sequence
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(record)
	fmt.Fprintf(l.toolFile, "%s\n", b)
	icon := confidenceIcon(record.Confidence)
	fmt.Printf("  %s [%s] %-30s | %dms | %s\n",
		icon, record.Agent, record.Tool, record.DurationMs, record.Confidence)
}

func (l *Logger) LogMessage(msg AgentMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg.SessionID = l.sessionID
	if msg.Timestamp == "" {
		msg.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(msg)
	fmt.Fprintf(l.msgFile, "%s\n", b)
}

func (l *Logger) SessionSummary(confirmed, inferred, unverified, total int) {
	fmt.Printf("\n╔═══════════════════════════════════════════╗\n")
	fmt.Printf("║         LogPoseSIFT Session Summary        ║\n")
	fmt.Printf("╠═══════════════════════════════════════════╣\n")
	fmt.Printf("║  Session ID : %-29s║\n", l.sessionID)
	fmt.Printf("║  Tool Calls : %-29d║\n", total)
	fmt.Printf("║  ✓ CONFIRMED  : %-27d║\n", confirmed)
	fmt.Printf("║  ~ INFERRED   : %-27d║\n", inferred)
	fmt.Printf("║  ? UNVERIFIED : %-27d║\n", unverified)
	fmt.Printf("║  Logs → %-35s║\n", l.logDir)
	fmt.Printf("╚═══════════════════════════════════════════╝\n\n")
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.toolFile != nil {
		l.toolFile.Close()
	}
	if l.msgFile != nil {
		l.msgFile.Close()
	}
}

func confidenceIcon(c string) string {
	switch c {
	case "CONFIRMED":
		return "✓"
	case "INFERRED":
		return "~"
	default:
		return "?"
	}
}

func NewRecord(tool, agent, intent, hypothesis string) (ToolCallRecord, time.Time) {
	return ToolCallRecord{
		Tool:       tool,
		Agent:      agent,
		Intent:     intent,
		Hypothesis: hypothesis,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Confidence: "UNVERIFIED",
	}, time.Now()
}

func Finish(rec *ToolCallRecord, start time.Time, output interface{}, err error, confidence string) {
	rec.DurationMs = time.Since(start).Milliseconds()
	rec.Output = output
	rec.Confidence = confidence
	if err != nil {
		rec.Error = err.Error()
		rec.Confidence = "UNVERIFIED"
	}
	Get().LogToolCall(*rec)
}