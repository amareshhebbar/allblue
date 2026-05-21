package wrappers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type HashdeepMode string

const (
	HashdeepCompute HashdeepMode = "compute"
	HashdeepAudit   HashdeepMode = "audit"
)

type HashdeepInput struct {
	Mode HashdeepMode `json:"mode"`

	TargetPath string `json:"target_path"`

	HashsetPath string `json:"hashset_path,omitempty"`

	OutputPath string `json:"output_path,omitempty"`

	Algorithms []string `json:"algorithms,omitempty"`

	Recursive bool `json:"recursive,omitempty"`

	StrictTimestamps bool `json:"strict_timestamps,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type HashEntry struct {
	FilePath string            `json:"file_path"`
	SizeBytes int64            `json:"size_bytes"`
	Hashes   map[string]string `json:"hashes"`
	AuditResult string         `json:"audit_result,omitempty"` 
}

type HashdeepOutput struct {
	Mode          HashdeepMode `json:"mode"`
	TargetPath    string       `json:"target_path"`
	Algorithms    []string     `json:"algorithms"`
	Entries       []HashEntry  `json:"entries"`
	EntryCnt      int          `json:"entry_count"`
	AuditSummary  *AuditSummary `json:"audit_summary,omitempty"`
	OutputPath    string        `json:"output_path,omitempty"`
	DurationMs    int64         `json:"duration_ms"`
	Error         string        `json:"error,omitempty"`
	Confidence    string        `json:"confidence"`
}

type AuditSummary struct {
	TotalFiles  int `json:"total_files"`
	Matched     int `json:"matched"`
	Mismatched  int `json:"mismatched"`
	Unknown     int `json:"unknown"`
	Missing     int `json:"missing"` 
}

var allowedHashAlgorithms = map[string]bool{
	"md5": true, "sha1": true, "sha256": true,
	"tiger": true, "whirlpool": true,
}

func RunHashdeep(input HashdeepInput) (HashdeepOutput, error) {
	start := time.Now()
	algs := resolveHashAlgorithms(input.Algorithms)
	out := HashdeepOutput{
		Mode:       input.Mode,
		TargetPath: input.TargetPath,
		Algorithms: algs,
		Confidence: "UNVERIFIED",
	}
	if err := validateHashdeepInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}
	args := buildHashdeepArgs(input, algs)

	timeout := clampTimeout(input.TimeoutSecs, 120, 3600)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "hashdeep", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if runErr != nil && stdout.Len() == 0 {
		out.Error = fmt.Sprintf("hashdeep error: %v | %s", runErr, truncate(stderr.String(), 512))
		out.DurationMs = time.Since(start).Milliseconds()
		return out, runErr
	}

	switch input.Mode {
	case HashdeepAudit:
		out.Entries, out.AuditSummary = parseHashdeepAudit(stdout.String(), stderr.String())
	default:
		out.Entries = parseHashdeepCompute(stdout.String(), algs)
		if input.OutputPath != "" {
			if err := writeHashsetFile(input.OutputPath, stdout.String()); err != nil {
				out.Error = fmt.Sprintf("failed to write hashset: %v", err)
			} else {
				out.OutputPath = input.OutputPath
			}
		}
	}

	out.EntryCnt = len(out.Entries)
	out.DurationMs = time.Since(start).Milliseconds()

	if input.Mode == HashdeepAudit && out.AuditSummary != nil {
		if out.AuditSummary.Mismatched == 0 && out.AuditSummary.Unknown == 0 {
			out.Confidence = "CONFIRMED"
		} else {
			out.Confidence = "INFERRED"
		}
	} else if out.EntryCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func validateHashdeepInput(input HashdeepInput) error {
	if input.Mode != HashdeepCompute && input.Mode != HashdeepAudit {
		return fmt.Errorf("mode must be 'compute' or 'audit'")
	}
	if input.TargetPath == "" {
		return fmt.Errorf("target_path is required")
	}
	for _, f := range []string{input.TargetPath, input.HashsetPath, input.OutputPath} {
		if containsShellMeta(f) {
			return fmt.Errorf("path contains disallowed shell metacharacters")
		}
	}
	if input.Mode == HashdeepAudit && input.HashsetPath == "" {
		return fmt.Errorf("hashset_path is required for audit mode")
	}
	if input.OutputPath != "" {
		if err := validateOutputPath(input.OutputPath); err != nil {
			return err
		}
	}
	for _, alg := range input.Algorithms {
		if !allowedHashAlgorithms[alg] {
			return fmt.Errorf("algorithm %q not allowed; use md5|sha1|sha256|tiger|whirlpool", alg)
		}
	}
	return nil
}

func buildHashdeepArgs(input HashdeepInput, algs []string) []string {
	args := []string{}

	args = append(args, "-c", strings.Join(algs, ","))

	if input.Recursive {
		args = append(args, "-r")
	}

	switch input.Mode {
	case HashdeepAudit:
		args = append(args, "-a", "-k", input.HashsetPath)
		if input.StrictTimestamps {
			args = append(args, "-e") 
		}
	default:
		args = append(args, "-l") 
	}

	args = append(args, input.TargetPath)
	return args
}

func resolveHashAlgorithms(algs []string) []string {
	if len(algs) == 0 {
		return []string{"md5", "sha256"}
	}
	return algs
}

func parseHashdeepCompute(raw string, algs []string) []HashEntry {
	var entries []HashEntry
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "%%%") || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.SplitN(line, ",", len(algs)+2)
		if len(cols) < len(algs)+2 {
			continue
		}
		entry := HashEntry{
			Hashes: make(map[string]string),
		}
		sz, _ := strconv.ParseInt(strings.TrimSpace(cols[0]), 10, 64)
		entry.SizeBytes = sz
		for i, alg := range algs {
			if i+1 < len(cols) {
				entry.Hashes[alg] = strings.TrimSpace(cols[i+1])
			}
		}
		entry.FilePath = strings.TrimSpace(cols[len(cols)-1])
		entries = append(entries, entry)
	}
	return entries
}


func parseHashdeepAudit(stdout, stderr string) ([]HashEntry, *AuditSummary) {
	summary := &AuditSummary{}
	var entries []HashEntry

	// Parse the detail lines from stderr (hashdeep writes per-file results there)
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ": No match") || strings.Contains(line, ": Matched") ||
			strings.Contains(line, ": Unknown") {
			entry := HashEntry{Hashes: make(map[string]string)}
			if strings.Contains(line, ": No match") {
				entry.FilePath = extractPathFromAuditLine(line, ": No match")
				entry.AuditResult = "MISMATCH"
				summary.Mismatched++
			} else if strings.Contains(line, ": Unknown") {
				entry.FilePath = extractPathFromAuditLine(line, ": Unknown")
				entry.AuditResult = "UNKNOWN"
				summary.Unknown++
			} else {
				entry.FilePath = extractPathFromAuditLine(line, ": Matched")
				entry.AuditResult = "MATCH"
				summary.Matched++
			}
			entries = append(entries, entry)
		}
	}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "hashdeep: audit") {
			summary.TotalFiles = summary.Matched + summary.Mismatched + summary.Unknown
		}
	}

	return entries, summary
}

func extractPathFromAuditLine(line, suffix string) string {
	s := strings.TrimPrefix(line, "hashdeep: ")
	s = strings.TrimSuffix(s, suffix)
	return filepath.Clean(s)
}

func writeHashsetFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func (o HashdeepOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(o, "", "  ")
}