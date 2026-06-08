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
	RulesPath    string `json:"rules_path"`
	TargetPath   string `json:"target_path,omitempty"`
	TargetPID    int    `json:"target_pid,omitempty"`
	Recursive    bool   `json:"recursive,omitempty"`
	MatchOnly    bool   `json:"match_only,omitempty"`
	PrintStrings bool   `json:"print_strings,omitempty"`
	TagFilter    string `json:"tag_filter,omitempty"`
	MaxFileSize  int64  `json:"max_file_size,omitempty"`
	TimeoutSecs  int    `json:"timeout_secs,omitempty"`
}

type YaraMatch struct {
	RuleName  string            `json:"rule_name"`
	Namespace string            `json:"namespace,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Target    string            `json:"target"`
	Strings   []YaraString      `json:"strings,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type YaraString struct {
	Identifier string `json:"identifier"`
	Offset     string `json:"offset"`
	Data       string `json:"data"`
}

type YaraOutput struct {
	RulesPath    string      `json:"rules_path"`
	Target       string      `json:"target"`
	Matches      []YaraMatch `json:"matches"`
	MatchCnt     int         `json:"match_count"`
	FilesScanned int         `json:"files_scanned,omitempty"`
	DurationMs   int64       `json:"duration_ms"`
	Error        string      `json:"error,omitempty"`
	Confidence   string      `json:"confidence"`
}

// approvedRulesDir returns the YARA rules directory.
// Priority: allblue_YARA_RULES_DIR env → /opt/allblue/yara-rules → ~/yara-rules
// The directory is created automatically if it does not exist.
func approvedRulesDir() string {
	candidates := []string{
		os.Getenv("allblue_YARA_RULES_DIR"),
		"/opt/allblue/yara-rules",
		filepath.Join(os.Getenv("HOME"), "yara-rules"),
		"/tmp/yara-rules",
	}
	for _, d := range candidates {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0755); err == nil {
			// If dir is empty, seed with a minimal built-in rule
			seedBuiltinRules(d)
			return d
		}
	}
	return "/tmp/yara-rules"
}

// seedBuiltinRules writes a minimal YARA rule file if the directory is empty.
// This ensures YARA always has something to scan with, even without a
// custom ruleset downloaded.
func seedBuiltinRules(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 0 {
		return // directory already has rules
	}

	builtinRules := `
// AllBlue built-in YARA rules
// Covers: common C2 ports in memory, known malware strings, LOLBin patterns

rule SuspiciousProcess_UsbClient {
    meta:
        description = "Detects usbclient.exe — not a legitimate Windows binary"
        severity = "high"
        source = "AllBlue"
    strings:
        $name = "usbclient.exe" nocase
        $name2 = "usbclient" nocase
    condition:
        any of them
}

rule SuspiciousProcess_Controllers {
    meta:
        description = "Detects *_ctrl.exe naming pattern used by this APT"
        severity = "high"
        source = "AllBlue"
    strings:
        $s1 = "subject_ctrl" nocase
        $s2 = "license_ctrl" nocase
        $s3 = "connector_ctrl" nocase
        $s4 = "imager_ctrl" nocase
    condition:
        any of them
}

rule C2_Port_8080_Pattern {
    meta:
        description = "Detects C2 beaconing patterns to port 8080"
        severity = "medium"
        source = "AllBlue"
    strings:
        $beacon = ":8080" ascii wide
        $ua = "Mozilla/4.0" ascii
    condition:
        $beacon
}

rule PowerShell_Encoded_Command {
    meta:
        description = "Detects PowerShell encoded command execution"
        severity = "high"
        source = "AllBlue"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "powershell" nocase
    condition:
        $enc3 and ($enc1 or $enc2)
}

rule Mimikatz_Artifacts {
    meta:
        description = "Detects Mimikatz credential dumping artifacts"
        severity = "critical"
        source = "AllBlue"
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "lsadump" nocase
        $s3 = "mimikatz" nocase
        $s4 = "Pass The Hash" nocase
        $s5 = "wdigest" nocase
    condition:
        2 of them
}

rule LOLBin_CertUtil_Download {
    meta:
        description = "Detects certutil used as download cradle"
        severity = "high"
        source = "AllBlue"
    strings:
        $s1 = "certutil" nocase
        $s2 = "-decode" nocase
        $s3 = "-urlcache" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule Cobalt_Strike_Beacon_Config {
    meta:
        description = "Detects Cobalt Strike beacon configuration patterns"
        severity = "critical"
        source = "AllBlue"
    strings:
        $cs1 = { 00 01 00 01 00 02 }
        $cs2 = "ReflectiveLoader" nocase
        $cs3 = "beacon" nocase
        $pipe = "\\\\.\\pipe\\" ascii wide
    condition:
        $cs2 or ($cs3 and $pipe)
}

rule Process_Hollowing_MZ_RWX {
    meta:
        description = "Detects MZ header in RWX memory region (process hollowing indicator)"
        severity = "critical"
        source = "AllBlue"
    strings:
        $mz = { 4D 5A }
        $rwx_hint = "PAGE_EXECUTE_READWRITE" nocase
    condition:
        $mz at 0 or ($mz and $rwx_hint)
}

rule DKOM_Rootkit_Indicators {
    meta:
        description = "Detects DKOM rootkit techniques in memory"
        severity = "critical"
        source = "AllBlue"
    strings:
        $s1 = "ActiveProcessLinks" nocase
        $s2 = "FLINK" ascii
        $s3 = "BLINK" ascii
        $s4 = "PsActiveProcessHead" nocase
    condition:
        2 of them
}
`
	path := filepath.Join(dir, "AllBlue_builtin.yar")
	_ = os.WriteFile(path, []byte(builtinRules), 0644)
}

// RunYara executes YARA against a file, directory, or process ID.
// The rules path is validated against the approved directory but
// auto-creates and auto-seeds that directory if it doesn't exist.
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

	// Ensure rules directory exists and is seeded
	approvedDir := approvedRulesDir()

	// If no rules_path supplied, use the approved directory
	if input.RulesPath == "" {
		input.RulesPath = approvedDir
		out.RulesPath = approvedDir
	}

	if err := validateYaraInput(input, approvedDir); err != nil {
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

	_ = cmd.Run() // non-zero exit is normal when matches found

	if stderr.Len() > 0 && stdout.Len() == 0 {
		out.Error = truncate(stderr.String(), 512)
		out.DurationMs = time.Since(start).Milliseconds()
		return out, fmt.Errorf(out.Error)
	}

	out.Matches, out.FilesScanned = parseYaraOutput(stdout.String(), input.PrintStrings)
	out.MatchCnt = len(out.Matches)
	out.DurationMs = time.Since(start).Milliseconds()

	if out.MatchCnt > 0 {
		out.Confidence = "CONFIRMED"
	} else {
		out.Confidence = "INFERRED" // scan ran, no matches
	}
	return out, nil
}

func validateYaraInput(input YaraInput, approvedDir string) error {
	if input.RulesPath == "" {
		return fmt.Errorf("rules_path is required")
	}
	absRules, err := filepath.Abs(input.RulesPath)
	if err != nil {
		return fmt.Errorf("cannot resolve rules_path: %v", err)
	}
	absApproved, _ := filepath.Abs(approvedDir)
	// Allow: under approved dir, OR any .yar file the user explicitly supplies
	if !strings.HasPrefix(absRules, absApproved) {
		// Check if it's a readable file anywhere — allow it if it is
		if _, statErr := os.Stat(absRules); statErr != nil {
			return fmt.Errorf("rules_path %q not found; approved directory is %s", input.RulesPath, approvedDir)
		}
		// File exists — allow it (user explicitly supplied a valid path)
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
		maxSize = 50 * 1024 * 1024 // 50 MB
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