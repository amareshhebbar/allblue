package wrappers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)


// ── fls ──────────────────────────────────────────────────────

type FlsInput struct {
	ImagePath   string `json:"image_path"`   
	Inode       string `json:"inode,omitempty"` 
	Recursive   bool   `json:"recursive"`    
	Deleted     bool   `json:"deleted"`     
	OffsetBytes int64  `json:"offset_bytes,omitempty"` 
	OutputMode  string `json:"output_mode,omitempty"`  
	TimeoutSecs int    `json:"timeout_secs,omitempty"`
}

// FlsEntry is one parsed row from fls output.
type FlsEntry struct {
	EntryType  string `json:"entry_type"`   
	Inode      string `json:"inode"`
	FileName   string `json:"file_name"`
	MACBTimes  MACBTimes `json:"macb_times,omitempty"`
	Size       int64  `json:"size_bytes,omitempty"`
	Allocated  bool   `json:"allocated"`
}

// MACBTimes holds Modified/Accessed/Changed/Born timestamps
type MACBTimes struct {
	Modified string `json:"modified,omitempty"`
	Accessed string `json:"accessed,omitempty"`
	Changed  string `json:"changed,omitempty"`
	Born     string `json:"born,omitempty"`
}

type FlsOutput struct {
	ImagePath  string     `json:"image_path"`
	Entries    []FlsEntry `json:"entries"`
	EntryCnt   int        `json:"entry_count"`
	DurationMs int64      `json:"duration_ms"`
	Error      string     `json:"error,omitempty"`
	Confidence string     `json:"confidence"`
}

func RunFls(input FlsInput) (FlsOutput, error) {
	start := time.Now()
	out := FlsOutput{ImagePath: input.ImagePath, Confidence: "UNVERIFIED"}

	if input.ImagePath == "" {
		out.Error = "image_path is required"
		return out, fmt.Errorf(out.Error)
	}
	if containsShellMeta(input.ImagePath) {
		out.Error = "image_path contains disallowed characters"
		return out, fmt.Errorf(out.Error)
	}

	args := buildFlsArgs(input)
	timeout := clampTimeout(input.TimeoutSecs, 180, 600)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "fls", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("fls error: %v | %s", err, stderr.String())
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}

	mode := input.OutputMode
	if mode == "" {
		mode = "bodyfile"
	}
	out.Entries = parseFlsOutput(stdout.String(), mode)
	out.EntryCnt = len(out.Entries)
	out.DurationMs = time.Since(start).Milliseconds()

	if out.EntryCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func buildFlsArgs(input FlsInput) []string {
	args := []string{}
	if input.Recursive {
		args = append(args, "-r")
	}
	if input.Deleted {
		args = append(args, "-d")
	}
	// Always emit bodyfile format so we can parse timestamps cleanly
	args = append(args, "-m", "/")
	if input.OffsetBytes > 0 {
		args = append(args, "-o", strconv.FormatInt(input.OffsetBytes, 10))
	}
	args = append(args, input.ImagePath)
	if input.Inode != "" {
		args = append(args, input.Inode)
	}
	return args
}

func parseFlsOutput(raw, mode string) []FlsEntry {
	var entries []FlsEntry
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "|")
		if mode == "bodyfile" && len(cols) >= 11 {
			entry := FlsEntry{
				FileName:  cols[1],
				Inode:     cols[2],
				Allocated: !strings.HasPrefix(cols[1], "$OrphanFiles"),
			}
			if size, err := strconv.ParseInt(cols[6], 10, 64); err == nil {
				entry.Size = size
			}
			entry.MACBTimes = MACBTimes{
				Accessed: unixToRFC3339(cols[7]),
				Modified: unixToRFC3339(cols[8]),
				Changed:  unixToRFC3339(cols[9]),
				Born:     unixToRFC3339(cols[10]),
			}
			// Determine entry type from mode string
			if len(cols[3]) > 0 {
				switch cols[3][0] {
				case 'd':
					entry.EntryType = "d"
				case 'r', '-':
					entry.EntryType = "r"
				default:
					entry.EntryType = string(cols[3][0])
				}
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// ── mactime ──────────────────────────────────────────────────

type MactimeInput struct {
	BodyfilePath string `json:"bodyfile_path"` 
	StartDate    string `json:"start_date,omitempty"` 
	EndDate      string `json:"end_date,omitempty"`  
	TimeoutSecs  int    `json:"timeout_secs,omitempty"`
}

type TimelineEntry struct {
	Timestamp string `json:"timestamp"`
	Size      int64  `json:"size_bytes"`
	Activity  string `json:"activity"` 
	FileName  string `json:"file_name"`
	Inode     string `json:"inode"`
}

type MactimeOutput struct {
	BodyfilePath string          `json:"bodyfile_path"`
	Entries      []TimelineEntry `json:"entries"`
	EntryCnt     int             `json:"entry_count"`
	DurationMs   int64           `json:"duration_ms"`
	Error        string          `json:"error,omitempty"`
	Confidence   string          `json:"confidence"`
}

func RunMactime(input MactimeInput) (MactimeOutput, error) {
	start := time.Now()
	out := MactimeOutput{BodyfilePath: input.BodyfilePath, Confidence: "UNVERIFIED"}

	if input.BodyfilePath == "" {
		out.Error = "bodyfile_path is required"
		return out, fmt.Errorf(out.Error)
	}
	if containsShellMeta(input.BodyfilePath) {
		out.Error = "bodyfile_path contains disallowed characters"
		return out, fmt.Errorf(out.Error)
	}

	args := buildMactimeArgs(input)
	timeout := clampTimeout(input.TimeoutSecs, 120, 300)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "mactime", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("mactime error: %v | %s", err, stderr.String())
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}

	out.Entries = parseMactimeOutput(stdout.String())
	out.EntryCnt = len(out.Entries)
	out.DurationMs = time.Since(start).Milliseconds()
	if out.EntryCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func buildMactimeArgs(input MactimeInput) []string {
	args := []string{"-b", input.BodyfilePath, "-d"} 
	if input.StartDate != "" && input.EndDate != "" {
		args = append(args, "-s", input.StartDate, "-e", input.EndDate)
	} else if input.StartDate != "" {
		args = append(args, input.StartDate)
	}
	return args
}

func parseMactimeOutput(raw string) []TimelineEntry {
	var entries []TimelineEntry
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // skip header
		}
		cols := strings.SplitN(line, ",", 8)
		if len(cols) < 8 {
			continue
		}
		entry := TimelineEntry{
			Timestamp: cols[0], 
			Activity:  cols[2],
			Inode:     cols[6],
			FileName:  strings.Trim(cols[7], "\""),
		}
		if sz, err := strconv.ParseInt(strings.TrimSpace(cols[1]), 10, 64); err == nil {
			entry.Size = sz
		}
		entries = append(entries, entry)
	}
	return entries
}

// ── icat ──────────────────────────────────────────────────────

type IcatInput struct {
	ImagePath    string `json:"image_path"`
	Inode        string `json:"inode"`          
	OutputPath   string `json:"output_path"`    
	OffsetBytes  int64  `json:"offset_bytes,omitempty"`
	TimeoutSecs  int    `json:"timeout_secs,omitempty"`
}

type IcatOutput struct {
	ImagePath   string `json:"image_path"`
	Inode       string `json:"inode"`
	OutputPath  string `json:"output_path"`
	BytesWritten int64 `json:"bytes_written"`
	SHA256Hash  string `json:"sha256_hash,omitempty"` 
	DurationMs  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	Confidence  string `json:"confidence"`
}

func RunIcat(input IcatInput) (IcatOutput, error) {
	start := time.Now()
	out := IcatOutput{
		ImagePath:  input.ImagePath,
		Inode:      input.Inode,
		OutputPath: input.OutputPath,
		Confidence: "UNVERIFIED",
	}

	if input.ImagePath == "" || input.Inode == "" || input.OutputPath == "" {
		out.Error = "image_path, inode, and output_path are all required"
		return out, fmt.Errorf(out.Error)
	}
	for _, f := range []string{input.ImagePath, input.Inode, input.OutputPath} {
		if containsShellMeta(f) {
			out.Error = "input contains disallowed shell metacharacters"
			return out, fmt.Errorf(out.Error)
		}
	}
	if err := validateOutputPath(input.OutputPath); err != nil {
		out.Error = err.Error()
		return out, err
	}

	args := buildIcatArgs(input)
	timeout := clampTimeout(input.TimeoutSecs, 60, 300)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	outFile, err := createOutputFile(input.OutputPath)
	if err != nil {
		out.Error = fmt.Sprintf("cannot create output file: %v", err)
		return out, err
	}
	defer outFile.Close()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "icat", args...)
	cmd.Stdout = outFile
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("icat error: %v | %s", err, stderr.String())
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}

	info, _ := outFile.Stat()
	if info != nil {
		out.BytesWritten = info.Size()
	}
	out.SHA256Hash, _ = sha256File(input.OutputPath)
	out.DurationMs = time.Since(start).Milliseconds()
	if out.BytesWritten > 0 {
		out.Confidence = "CONFIRMED" 
	}
	return out, nil
}

func buildIcatArgs(input IcatInput) []string {
	args := []string{}
	if input.OffsetBytes > 0 {
		args = append(args, "-o", strconv.FormatInt(input.OffsetBytes, 10))
	}
	args = append(args, input.ImagePath, input.Inode)
	return args
}


func (o FlsOutput) ToJSON() ([]byte, error)     { return json.MarshalIndent(o, "", "  ") }
func (o MactimeOutput) ToJSON() ([]byte, error)  { return json.MarshalIndent(o, "", "  ") }
func (o IcatOutput) ToJSON() ([]byte, error)     { return json.MarshalIndent(o, "", "  ") }