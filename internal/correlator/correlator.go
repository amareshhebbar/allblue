package correlator

import (
	"fmt"
	"strings"
	"time"
)

// CorrelationStatus tags each finding after cross-referencing.
type CorrelationStatus string

const (
	StatusConfirmed    CorrelationStatus = "CONFIRMED"    // memory + disk agree
	StatusSuspicious   CorrelationStatus = "SUSPICIOUS"   // in memory, no disk trace (fileless)
	StatusContradicted CorrelationStatus = "CONTRADICTED" // timestamps disagree (timestomping)
	StatusOrphaned     CorrelationStatus = "ORPHANED"     // one source only
)

// MemoryFinding is one artefact from the memory agent.
// Type values: process, network, malfind, dll
type MemoryFinding struct {
	Type        string
	Name        string // process name, IP:port, or module name
	PID         int
	PPID        int
	CommandLine string
	Timestamp   string // process create time, RFC3339 if available
	Details     string // raw line from tool output
}

// DiskFinding is one artefact from the disk agent.
// Type values: timeline, registry, file, prefetch
type DiskFinding struct {
	Type      string
	Path      string // filesystem or registry path
	Timestamp string // MACB timestamp, RFC3339
	Size      int64
	Hash      string
	Details   string // raw line from tool output
}

// CorrelationResult is one matched or unmatched finding pair.
type CorrelationResult struct {
	Status      CorrelationStatus `json:"status"`
	MemoryRef   *MemoryFinding    `json:"memory_ref,omitempty"`
	DiskRef     *DiskFinding      `json:"disk_ref,omitempty"`
	Explanation string            `json:"explanation"`
	Severity    string            `json:"severity"` // high, medium, low
	IOC         string            `json:"ioc,omitempty"`
}

// AuditSummary holds aggregate counts across all results.
type AuditSummary struct {
	TotalMemory  int `json:"total_memory_findings"`
	TotalDisk    int `json:"total_disk_findings"`
	Confirmed    int `json:"confirmed"`
	Suspicious   int `json:"suspicious"`
	Contradicted int `json:"contradicted"`
	Orphaned     int `json:"orphaned"`
	HighCount    int `json:"high_severity_count"`
}

// CorrelationReport is the full output returned to the orchestrator.
type CorrelationReport struct {
	GeneratedAt  string              `json:"generated_at"`
	MemorySource string              `json:"memory_source"`
	DiskSource   string              `json:"disk_source"`
	Results      []CorrelationResult `json:"results"`
	Summary      AuditSummary        `json:"summary"`
	Narrative    string              `json:"narrative"`
}

// Engine cross-references memory findings against disk findings.
type Engine struct {
	MemorySource string
	DiskSource   string
}

// New creates a correlator engine.
func New(memorySource, diskSource string) *Engine {
	return &Engine{MemorySource: memorySource, DiskSource: diskSource}
}

// Correlate runs the full cross-reference and returns a CorrelationReport.
func (e *Engine) Correlate(memFindings []MemoryFinding, diskFindings []DiskFinding) CorrelationReport {
	report := CorrelationReport{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		MemorySource: e.MemorySource,
		DiskSource:   e.DiskSource,
	}

	diskMatched := make([]bool, len(diskFindings))

	for i := range memFindings {
		result := e.correlateOne(memFindings[i], diskFindings, diskMatched)
		report.Results = append(report.Results, result)
	}

	// Orphan any disk findings that were not matched by a memory finding
	for i, df := range diskFindings {
		if !diskMatched[i] {
			dfCopy := df
			report.Results = append(report.Results, CorrelationResult{
				Status:      StatusOrphaned,
				DiskRef:     &dfCopy,
				Explanation: fmt.Sprintf("Disk artefact %q has no memory counterpart -- process terminated before capture or artefact is historical.", df.Path),
				Severity:    "low",
			})
		}
	}

	report.Summary = e.buildSummary(report.Results, len(memFindings), len(diskFindings))
	report.Narrative = e.buildNarrative(report.Summary)
	return report
}

func (e *Engine) correlateOne(mf MemoryFinding, diskFindings []DiskFinding, diskMatched []bool) CorrelationResult {
	mfCopy := mf
	result := CorrelationResult{MemoryRef: &mfCopy}

	switch mf.Type {

	case "process":
		for i, df := range diskFindings {
			if matchProcessToDisk(mf, df) {
				diskMatched[i] = true
				dfCopy := df
				result.DiskRef = &dfCopy
				result.Status = StatusConfirmed
				result.Severity = "low"
				result.Explanation = fmt.Sprintf("Process %q (PID %d) confirmed in both memory and disk artefact %q.", mf.Name, mf.PID, df.Path)

				// Timestamp contradiction = timestomping indicator
				if mf.Timestamp != "" && df.Timestamp != "" && !timestampsClose(mf.Timestamp, df.Timestamp) {
					result.Status = StatusContradicted
					result.Severity = "high"
					result.IOC = fmt.Sprintf("timestomp_candidate:%s", mf.Name)
					result.Explanation = fmt.Sprintf("CONTRADICTION: process %q in memory at %s but disk shows %s -- possible timestomping.", mf.Name, mf.Timestamp, df.Timestamp)
				}
				return result
			}
		}
		// No disk match = fileless malware candidate
		result.Status = StatusSuspicious
		result.Severity = "high"
		result.IOC = fmt.Sprintf("fileless_candidate:%s:PID%d", mf.Name, mf.PID)
		result.Explanation = fmt.Sprintf("Process %q (PID %d) running in memory with NO disk trace -- possible fileless malware, process hollowing, or deleted executable.", mf.Name, mf.PID)

	case "network":
		ip := extractIP(mf.Name)
		for i, df := range diskFindings {
			if ip != "" && strings.Contains(df.Details, ip) {
				diskMatched[i] = true
				dfCopy := df
				result.DiskRef = &dfCopy
				result.Status = StatusConfirmed
				result.Severity = "medium"
				result.Explanation = fmt.Sprintf("Network connection to %s confirmed in both memory and disk artefact %q.", mf.Name, df.Path)
				return result
			}
		}
		result.Status = StatusSuspicious
		result.Severity = "medium"
		result.IOC = fmt.Sprintf("network_no_disk_trace:%s", mf.Name)
		result.Explanation = fmt.Sprintf("Network connection to %s found in memory but no disk log -- possible active-only connection or log deletion.", mf.Name)

	case "malfind":
		result.Status = StatusSuspicious
		result.Severity = "high"
		result.IOC = fmt.Sprintf("code_injection:%s:PID%d", mf.Name, mf.PID)
		result.Explanation = fmt.Sprintf("Code injection detected in %q (PID %d) -- MZ header or shellcode in writable memory.", mf.Name, mf.PID)

	default:
		result.Status = StatusOrphaned
		result.Severity = "low"
		result.Explanation = fmt.Sprintf("Memory artefact %q (%s) could not be correlated.", mf.Name, mf.Type)
	}

	return result
}

// matchProcessToDisk returns true if the process name appears in the disk path.
func matchProcessToDisk(mf MemoryFinding, df DiskFinding) bool {
	name := strings.ToLower(mf.Name)
	path := strings.ToLower(df.Path)
	if strings.HasSuffix(path, name) {
		return true
	}
	if strings.Contains(path, "/"+name) || strings.Contains(path, "\\"+name) {
		return true
	}
	if mf.CommandLine != "" {
		exe := extractExeName(mf.CommandLine)
		if exe != "" && strings.Contains(path, exe) {
			return true
		}
	}
	return false
}

// timestampsClose returns true if two RFC3339 timestamps are within 24 hours.
// A gap greater than 24h on the same artefact is a timestomping signal.
func timestampsClose(ts1, ts2 string) bool {
	t1, err1 := time.Parse(time.RFC3339, ts1)
	t2, err2 := time.Parse(time.RFC3339, ts2)
	if err1 != nil || err2 != nil {
		return true // cannot compare, do not flag
	}
	diff := t1.Sub(t2)
	if diff < 0 {
		diff = -diff
	}
	return diff < 24*time.Hour
}

func extractIP(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractExeName(cmdLine string) string {
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return ""
	}
	exe := parts[0]
	if idx := strings.LastIndexAny(exe, `/\`); idx >= 0 {
		exe = exe[idx+1:]
	}
	return strings.ToLower(strings.Trim(exe, "\""))
}

func (e *Engine) buildSummary(results []CorrelationResult, memTotal, diskTotal int) AuditSummary {
	s := AuditSummary{TotalMemory: memTotal, TotalDisk: diskTotal}
	for _, r := range results {
		switch r.Status {
		case StatusConfirmed:
			s.Confirmed++
		case StatusSuspicious:
			s.Suspicious++
		case StatusContradicted:
			s.Contradicted++
		case StatusOrphaned:
			s.Orphaned++
		}
		if r.Severity == "high" {
			s.HighCount++
		}
	}
	return s
}

func (e *Engine) buildNarrative(s AuditSummary) string {
	var parts []string
	parts = append(parts, fmt.Sprintf(
		"Correlated %d memory findings against %d disk artefacts: %d confirmed, %d suspicious, %d contradicted, %d orphaned.",
		s.TotalMemory, s.TotalDisk, s.Confirmed, s.Suspicious, s.Contradicted, s.Orphaned))
	if s.Contradicted > 0 {
		parts = append(parts, fmt.Sprintf("%d CONTRADICTION(s) -- investigate timestomping.", s.Contradicted))
	}
	if s.Suspicious > 0 {
		parts = append(parts, fmt.Sprintf("%d process(es) in memory with no disk trace -- possible fileless malware.", s.Suspicious))
	}
	return strings.Join(parts, " ")
}

// ParsePSList converts raw pslist/pstree output into MemoryFindings.
func ParsePSList(raw string) []MemoryFinding {
	var findings []MemoryFinding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" ||
			strings.HasPrefix(line, "Volatility") ||
			strings.HasPrefix(line, "PID") ||
			strings.HasPrefix(line, "-") ||
			strings.HasPrefix(line, "*") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		findings = append(findings, MemoryFinding{
			Type:    "process",
			Name:    fields[0],
			Details: line,
		})
	}
	return findings
}

// ParseNetScan converts raw netscan output into MemoryFindings.
// Column order: Offset Proto LocalAddr ForeignAddr State PID Owner
func ParseNetScan(raw string) []MemoryFinding {
	var findings []MemoryFinding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" ||
			strings.HasPrefix(line, "Volatility") ||
			strings.HasPrefix(line, "Offset") ||
			strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		findings = append(findings, MemoryFinding{
			Type:    "network",
			Name:    fields[3], // ForeignAddr
			Details: line,
		})
	}
	return findings
}

// ParseMalfind converts raw malfind output into MemoryFindings.
func ParseMalfind(raw string) []MemoryFinding {
	var findings []MemoryFinding
	var current MemoryFinding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Process:") {
			if current.Name != "" {
				findings = append(findings, current)
			}
			fields := strings.Fields(line)
			current = MemoryFinding{Type: "malfind"}
			if len(fields) > 1 {
				current.Name = fields[1]
			}
		} else if current.Name != "" {
			current.Details += line + " "
		}
	}
	if current.Name != "" {
		findings = append(findings, current)
	}
	return findings
}