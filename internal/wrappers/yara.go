package wrappers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type YaraInput struct {
	RulesPath string `json:"rules_path"`

	TargetPath string `json:"target_path,omitempty"`
	TargetPID  int    `json:"target_pid,omitempty"`

	Recursive bool `json:"recursive,omitempty"`

	MatchOnly bool `json:"match_only,omitempty"`

	PrintStrings bool `json:"print_strings,omitempty"`

	TagFilter string `json:"tag_filter,omitempty"`

	MaxFileSize int64 `json:"max_file_size,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type YaraMatch struct {
	RuleName  string        `json:"rule_name"`
	Namespace string        `json:"namespace,omitempty"`
	Tags      []string      `json:"tags,omitempty"`
	Target    string        `json:"target"`        
	Strings   []YaraString  `json:"strings,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type YaraString struct {
	Identifier string `json:"identifier"`
	Offset     string `json:"offset"`
	Data       string `json:"data"` 
}

type YaraOutput struct {
	RulesPath   string      `json:"rules_path"`
	Target      string      `json:"target"`
	Matches     []YaraMatch `json:"matches"`
	MatchCnt    int         `json:"match_count"`
	FilesScanned int        `json:"files_scanned,omitempty"`
	DurationMs  int64       `json:"duration_ms"`
	Error       string      `json:"error,omitempty"`
	Confidence  string      `json:"confidence"`
}

const defaultApprovedRulesDir = "/opt/logposesift/yara-rules"

func approvedRulesDir() string {
	if d := os.Getenv("LOGPOSE_YARA_RULES_DIR"); d != "" {
		return d
	}
	return defaultApprovedRulesDir
}

func RunYara(input YaraInput) (YaraOutput, error) {
	start := time.Now()
	target := input.TargetPath
	if input.TargetPID > 0 {
		target = fmt.Sprintf("PID:%d", input.TargetPID)
	}
	out := YaraOutput{
		RulesPath:  input.RulesPath,
		Target:     target,
		Confidence: "UNVERIFIED",
	}

	if err := validateYaraInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}

	args := buildYaraArgs(input)

	timeout := clampTimeout(input.TimeoutSecs, 120, 600)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "yara", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() 

	if stderr.Len() > 0 && stdout.Len() == 0 {
		out.Error = truncate(stderr.String(), 512)
		out.DurationMs = time.Since(start).Milliseconds()
		return out, fmt.Errorf(out.Error)
	}

	out.Matches, out.FilesScanned = parseYaraOutput(stdout.String(), input.PrintStrings)
	out.MatchCnt = len(out.Matches)
	out.DurationMs = time.Since(start).Milliseconds()

	if out.MatchCnt > 0 {
		out.Confidence = "INFERRED" 
	}
	return out, nil
}

func validateYaraInput(input YaraInput) error {
	if input.RulesPath == "" {
		return fmt.Errorf("rules_path is required")
	}
	absRules, err := filepath.Abs(input.RulesPath)
	if err != nil || !strings.HasPrefix(absRules, approvedRulesDir()) {
		return fmt.Errorf("rules_path must be under %s", approvedRulesDir())
	}
	if input.TargetPath == "" && input.TargetPID == 0 {
		return fmt.Errorf("either target_path or target_pid is required")
	}
	if input.TargetPath != "" && input.TargetPID != 0 {
		return fmt.Errorf("supply target_path OR target_pid, not both")
	}
	for _, f := range []string{input.RulesPath, input.TargetPath, input.TagFilter} {
		if containsShellMeta(f) {
			return fmt.Errorf("input contains disallowed shell metacharacters")
		}
	}
	return nil
}

func buildYaraArgs(input YaraInput) []string {
	args := []string{}

	if input.Recursive {
		args = append(args, "-r")
	}
	if input.PrintStrings {
		args = append(args, "-s")
	}
	if input.TagFilter != "" {
		args = append(args, "-t", input.TagFilter)
	}
	maxSize := input.MaxFileSize
	if maxSize <= 0 {
		maxSize = 50 * 1024 * 1024 
	}
	args = append(args, "--max-filesize", fmt.Sprintf("%d", maxSize))

	args = append(args, input.RulesPath)

	if input.TargetPID > 0 {
		args = append(args, fmt.Sprintf("%d", input.TargetPID))
	} else {
		args = append(args, input.TargetPath)
	}
	return args
}

func parseYaraOutput(raw string, includeStrings bool) ([]YaraMatch, int) {
	var matches []YaraMatch
	filesScanned := 0

	scanner := bufio.NewScanner(strings.NewReader(raw))
	var current *YaraMatch

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "0x") && current != nil && includeStrings {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 {
				ys := YaraString{
					Offset:     parts[0],
					Identifier: strings.TrimPrefix(parts[1], "$"),
					Data:       truncate(strings.TrimSpace(parts[2]), 64),
				}
				current.Strings = append(current.Strings, ys)
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		match := YaraMatch{RuleName: fields[0]}

		rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		if strings.HasPrefix(rest, "[") {
			closeIdx := strings.Index(rest, "]")
			if closeIdx > 0 {
				tagStr := rest[1:closeIdx]
				for _, t := range strings.Split(tagStr, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						match.Tags = append(match.Tags, t)
					}
				}
				rest = strings.TrimSpace(rest[closeIdx+1:])
			}
		}
		match.Target = rest
		if match.Target != "" {
			filesScanned++ 
		}

		matches = append(matches, match)
		current = &matches[len(matches)-1]
	}
	return matches, filesScanned
}

func (o YaraOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(o, "", "  ")
}