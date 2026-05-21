package wrappers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type RegRipperInput struct {
	HivePath string `json:"hive_path"`

	//"system" | "software" | "ntuser" | "sam" | "security" | "usrclass"
	HiveType string `json:"hive_type"`
	Plugins string `json:"plugins,omitempty"`
	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type RegistryArtifact struct {
	Plugin      string `json:"plugin"`
	KeyPath     string `json:"key_path"`
	ValueName   string `json:"value_name,omitempty"`
	Data        string `json:"data"`
	LastWritten string `json:"last_written,omitempty"` 
	PluginNote  string `json:"plugin_note,omitempty"`
}

type RegRipperOutput struct {
	HivePath    string             `json:"hive_path"`
	HiveType    string             `json:"hive_type"`
	PluginsRun  []string           `json:"plugins_run"`
	Artifacts   []RegistryArtifact `json:"artifacts"`
	ArtifactCnt int                `json:"artifact_count"`
	DurationMs  int64              `json:"duration_ms"`
	Error       string             `json:"error,omitempty"`
	Confidence string `json:"confidence"`
}

var allowedHiveNames = map[string]bool{
	"system": true, "software": true, "ntuser.dat": true,
	"sam": true, "security": true, "usrclass.dat": true,
	"default": true, "bcd": true,
}

var defaultPluginProfiles = map[string]string{
	"system":   "system",
	"software": "software",
	"ntuser":   "ntuser",
	"sam":      "sam",
	"security": "security",
	"usrclass": "usrclass",
}

func RunRegRipper(input RegRipperInput) (RegRipperOutput, error) {
	start := time.Now()
	out := RegRipperOutput{
		HivePath:   input.HivePath,
		HiveType:   strings.ToLower(input.HiveType),
		Confidence: "UNVERIFIED", 
	}

	if err := validateRegRipperInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}
	args := buildRegRipperArgs(input)
	out.PluginsRun = resolvePluginList(input)
	timeout := clampTimeout(input.TimeoutSecs, 120, 300)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "rip.pl", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("regripper exec error: %v | stderr: %s", err, stderr.String())
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}
	out.Artifacts = parseRegRipperOutput(stdout.String())
	out.ArtifactCnt = len(out.Artifacts)
	out.DurationMs = time.Since(start).Milliseconds()
	if out.ArtifactCnt > 0 {
		out.Confidence = "INFERRED"
	}

	return out, nil
}

func validateRegRipperInput(input RegRipperInput) error {
	if input.HivePath == "" {
		return fmt.Errorf("hive_path is required")
	}
	base := strings.ToLower(filepath.Base(input.HivePath))
	if !allowedHiveNames[base] {
		return fmt.Errorf("hive filename %q not in allowlist; use one of: system, software, ntuser.dat, sam, security, usrclass.dat", base)
	}
	if _, ok := defaultPluginProfiles[strings.ToLower(input.HiveType)]; !ok {
		return fmt.Errorf("unknown hive_type %q; must be one of system|software|ntuser|sam|security|usrclass", input.HiveType)
	}
	for _, field := range []string{input.HivePath, input.Plugins} {
		if containsShellMeta(field) {
			return fmt.Errorf("input contains disallowed shell metacharacters")
		}
	}
	return nil
}

func buildRegRipperArgs(input RegRipperInput) []string {
	profile := defaultPluginProfiles[strings.ToLower(input.HiveType)]
	args := []string{"-r", input.HivePath, "-f", profile}
	if input.Plugins != "" {
		// Override with explicit plugin list: rip.pl -r hive -p plugin1 -p plugin2
		args = []string{"-r", input.HivePath}
		for _, p := range strings.Split(input.Plugins, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				args = append(args, "-p", p)
			}
		}
	}
	return args
}

func resolvePluginList(input RegRipperInput) []string {
	if input.Plugins != "" {
		var list []string
		for _, p := range strings.Split(input.Plugins, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				list = append(list, p)
			}
		}
		return list
	}
	return []string{defaultPluginProfiles[strings.ToLower(input.HiveType)] + " (full profile)"}
}

// parseRegRipperOutput converts regripper's text output into structured artifacts
func parseRegRipperOutput(raw string) []RegistryArtifact {
	var artifacts []RegistryArtifact
	var currentPlugin string

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if strings.Contains(line, "v") && !strings.Contains(line, "\\") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				currentPlugin = parts[0]
			}
			continue
		}

		if strings.Contains(line, "\\") {
			artifact := RegistryArtifact{Plugin: currentPlugin}
			if idx := strings.LastIndex(line, ":"); idx > 0 {
				artifact.KeyPath = strings.TrimSpace(line[:idx])
				artifact.Data = strings.TrimSpace(line[idx+1:])
			} else {
				artifact.KeyPath = line
			}
			artifacts = append(artifacts, artifact)
			continue
		}

		if strings.HasPrefix(line, "LastWrite") && len(artifacts) > 0 {
			artifacts[len(artifacts)-1].LastWritten = strings.TrimPrefix(line, "LastWrite: ")
		}
	}
	return artifacts
}

// ToJSON serialises the output for the MCP response envelope.
func (o RegRipperOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(o, "", "  ")
}