package wrappers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Log2TimelineInput struct {
	SourcePath string `json:"source_path"`

	PlasoPath string `json:"plaso_path"`

	Parsers string `json:"parsers,omitempty"`

	Timezone string `json:"timezone,omitempty"`

	Workers int `json:"workers,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type PsortInput struct {
	PlasoPath string `json:"plaso_path"`

	OutputPath string `json:"output_path"`

	OutputFormat string `json:"output_format,omitempty"`

	DateFilter string `json:"date_filter,omitempty"`

	FilterQuery string `json:"filter_query,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type TimelineEvent struct {
	Timestamp   string `json:"timestamp"`
	TimestampDesc string `json:"timestamp_desc"`
	Source      string `json:"source"`
	SourceLong  string `json:"source_long"`
	Message     string `json:"message"`
	Filename    string `json:"filename,omitempty"`
	Parser      string `json:"parser,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

type Log2TimelineOutput struct {
	SourcePath  string `json:"source_path"`
	PlasoPath   string `json:"plaso_path"`
	ParsersUsed string `json:"parsers_used"`
	EventCount  int    `json:"event_count_estimate"`
	DurationMs  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	Confidence  string `json:"confidence"`
}

type PsortOutput struct {
	PlasoPath   string          `json:"plaso_path"`
	OutputPath  string          `json:"output_path"`
	Format      string          `json:"output_format"`
	Events      []TimelineEvent `json:"events"`
	EventCnt    int             `json:"event_count"`
	DurationMs  int64           `json:"duration_ms"`
	Error       string          `json:"error,omitempty"`
	Confidence  string          `json:"confidence"`
}

var allowedPsortFormats = map[string]bool{
	"l2tcsv": true, "json_line": true, "dynamic": true,
}

var allowedParserPresets = map[string]bool{
	"win_gen": true, "win7": true, "win10": true,
	"linux": true, "macos": true, "all": true,
}

func RunLog2Timeline(input Log2TimelineInput) (Log2TimelineOutput, error) {
	start := time.Now()
	out := Log2TimelineOutput{
		SourcePath:  input.SourcePath,
		PlasoPath:   input.PlasoPath,
		ParsersUsed: resolveL2TParsers(input.Parsers),
		Confidence:  "UNVERIFIED",
	}

	if err := validateL2TInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}

	args := buildL2TArgs(input)
	timeout := clampTimeout(input.TimeoutSecs, 600, 7200) 
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "log2timeline.py", args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("log2timeline error: %v | %s", err, truncate(stderr.String(), 512))
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}

	if info, err := os.Stat(input.PlasoPath); err == nil {
		out.EventCount = int(info.Size() / 200)
	}
	out.DurationMs = time.Since(start).Milliseconds()
	out.Confidence = "INFERRED"
	return out, nil
}

func validateL2TInput(input Log2TimelineInput) error {
	if input.SourcePath == "" {
		return fmt.Errorf("source_path is required")
	}
	if input.PlasoPath == "" {
		return fmt.Errorf("plaso_path is required")
	}
	for _, f := range []string{input.SourcePath, input.PlasoPath} {
		if containsShellMeta(f) {
			return fmt.Errorf("path contains disallowed shell metacharacters")
		}
	}
	if err := validateOutputPath(input.PlasoPath); err != nil {
		return err
	}
	if input.Parsers != "" {
		for _, p := range splitAndTrim(input.Parsers) {
			if !allowedParserPresets[p] {
				if containsShellMeta(p) {
					return fmt.Errorf("parser name %q contains disallowed characters", p)
				}
			}
		}
	}
	return nil
}

func buildL2TArgs(input Log2TimelineInput) []string {
	tz := input.Timezone
	if tz == "" {
		tz = "UTC"
	}
	workers := input.Workers
	if workers <= 0 {
		workers = 4
	}
	if workers > 8 {
		workers = 8
	}
	args := []string{
		"--timezone", tz,
		"--workers", fmt.Sprintf("%d", workers),
	}
	if input.Parsers != "" {
		args = append(args, "--parsers", resolveL2TParsers(input.Parsers))
	}
	args = append(args, input.PlasoPath, input.SourcePath)
	return args
}

func resolveL2TParsers(parsers string) string {
	if parsers == "" {
		return "all"
	}
	return parsers
}

func RunPsort(input PsortInput) (PsortOutput, error) {
	start := time.Now()
	format := input.OutputFormat
	if format == "" {
		format = "l2tcsv"
	}
	out := PsortOutput{
		PlasoPath:  input.PlasoPath,
		OutputPath: input.OutputPath,
		Format:     format,
		Confidence: "UNVERIFIED",
	}

	if err := validatePsortInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}

	args := buildPsortArgs(input, format)
	timeout := clampTimeout(input.TimeoutSecs, 180, 1800)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "psort.py", args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("psort error: %v | %s", err, truncate(stderr.String(), 512))
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}

	out.Events = parsePsortOutput(input.OutputPath, format)
	out.EventCnt = len(out.Events)
	out.DurationMs = time.Since(start).Milliseconds()
	if out.EventCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func validatePsortInput(input PsortInput) error {
	if input.PlasoPath == "" || input.OutputPath == "" {
		return fmt.Errorf("plaso_path and output_path are required")
	}
	for _, f := range []string{input.PlasoPath, input.OutputPath} {
		if containsShellMeta(f) {
			return fmt.Errorf("path contains disallowed shell metacharacters")
		}
	}
	if err := validateOutputPath(input.OutputPath); err != nil {
		return err
	}
	if input.OutputFormat != "" && !allowedPsortFormats[input.OutputFormat] {
		return fmt.Errorf("output_format %q not allowed; use l2tcsv|json_line|dynamic", input.OutputFormat)
	}
	if input.FilterQuery != "" {
		for _, ch := range input.FilterQuery {
			if !isAllowedFilterChar(ch) {
				return fmt.Errorf("filter_query contains disallowed character: %q", ch)
			}
		}
	}
	return nil
}

func buildPsortArgs(input PsortInput, format string) []string {
	args := []string{
		"-o", format,
		"-w", input.OutputPath,
	}
	if input.DateFilter != "" {
		args = append(args, "--slice", input.DateFilter)
	}
	if input.FilterQuery != "" {
		args = append(args, input.FilterQuery)
	}
	args = append(args, input.PlasoPath)
	return args
}

func parsePsortOutput(path, format string) []TimelineEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var events []TimelineEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) 

	switch format {
	case "l2tcsv":
		
		isHeader := true
		for scanner.Scan() {
			line := scanner.Text()
			if isHeader {
				isHeader = false
				continue
			}
			cols := strings.SplitN(line, ",", 17)
			if len(cols) < 13 {
				continue
			}
			events = append(events, TimelineEvent{
				Timestamp:     cols[0] + " " + cols[1],
				TimestampDesc: cols[6],
				Source:        cols[4],
				SourceLong:    cols[5],
				Message:       cols[10],
				Filename:      cols[12],
				Hostname:      cols[8],
			})
		}
	case "json_line":
		for scanner.Scan() {
			line := scanner.Text()
			var ev map[string]interface{}
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				continue
			}
			events = append(events, TimelineEvent{
				Timestamp:     strVal(ev, "datetime"),
				TimestampDesc: strVal(ev, "timestamp_desc"),
				Source:        strVal(ev, "source_short"),
				SourceLong:    strVal(ev, "source"),
				Message:       strVal(ev, "message"),
				Filename:      strVal(ev, "filename"),
				Parser:        strVal(ev, "parser"),
				Hostname:      strVal(ev, "hostname"),
			})
		}
	}
	if len(events) > 2000 {
		events = events[:2000]
	}
	return events
}

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func (o Log2TimelineOutput) ToJSON() ([]byte, error) { return json.MarshalIndent(o, "", "  ") }
func (o PsortOutput) ToJSON() ([]byte, error)        { return json.MarshalIndent(o, "", "  ") }