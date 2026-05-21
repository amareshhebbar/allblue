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

type BulkExtractorInput struct {
	ImagePath string `json:"image_path,omitempty"`
	PcapPath  string `json:"pcap_path,omitempty"`
	OutputDir string `json:"output_dir"`
	Scanners string `json:"scanners,omitempty"`
	DisableScanners string `json:"disable_scanners,omitempty"`
	Threads int `json:"threads,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type CarvedFeature struct {
	FeatureType string `json:"feature_type"` 
	Offset      string `json:"offset"`       
	Feature     string `json:"feature"`     
	Context     string `json:"context,omitempty"` 
}

type BulkExtractorOutput struct {
	Source         string          `json:"source"`
	OutputDir      string          `json:"output_dir"`
	ScannersRun    []string        `json:"scanners_run"`
	Features       []CarvedFeature `json:"features"`
	FeatureCnt     int             `json:"feature_count"`
	FeaturesByType map[string]int  `json:"features_by_type"`
	DurationMs     int64           `json:"duration_ms"`
	Error          string          `json:"error,omitempty"`
	Confidence     string          `json:"confidence"`
}

var allowedScanners = map[string]bool{
	"email": true, "url": true, "domain": true, "credit_card": true,
	"telephone": true, "zip": true, "base64": true, "json": true,
	"elf": true, "pdf": true, "vcard": true, "winprefetch": true,
	"exif": true, "gps": true, "net": true, "sqlite": true,
}

func RunBulkExtractor(input BulkExtractorInput) (BulkExtractorOutput, error) {
	start := time.Now()

	source := input.ImagePath
	if source == "" {
		source = input.PcapPath
	}
	out := BulkExtractorOutput{
		Source:         source,
		OutputDir:      input.OutputDir,
		FeaturesByType: make(map[string]int),
		Confidence:     "UNVERIFIED",
	}

	if err := validateBEInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}

	args, enabledScanners := buildBEArgs(input, source)
	out.ScannersRun = enabledScanners

	timeout := clampTimeout(input.TimeoutSecs, 300, 3600)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "bulk_extractor", args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		out.Error = fmt.Sprintf("bulk_extractor error: %v | %s", err, stderr.String())
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}
	out.Features = parseBEOutputDir(input.OutputDir, out.FeaturesByType)
	out.FeatureCnt = len(out.Features)
	out.DurationMs = time.Since(start).Milliseconds()

	if out.FeatureCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func validateBEInput(input BulkExtractorInput) error {
	if input.ImagePath == "" && input.PcapPath == "" {
		return fmt.Errorf("either image_path or pcap_path is required")
	}
	if input.ImagePath != "" && input.PcapPath != "" {
		return fmt.Errorf("supply image_path OR pcap_path, not both")
	}
	if input.OutputDir == "" {
		return fmt.Errorf("output_dir is required")
	}
	for _, f := range []string{input.ImagePath, input.PcapPath, input.OutputDir} {
		if containsShellMeta(f) {
			return fmt.Errorf("path contains disallowed shell metacharacters")
		}
	}
	if err := validateOutputPath(input.OutputDir); err != nil {
		return err
	}
	for _, s := range splitAndTrim(input.Scanners) {
		if !allowedScanners[s] {
			return fmt.Errorf("scanner %q not in allowlist", s)
		}
	}
	for _, s := range splitAndTrim(input.DisableScanners) {
		if !allowedScanners[s] {
			return fmt.Errorf("disable_scanner %q not in allowlist", s)
		}
	}
	return nil
}

func buildBEArgs(input BulkExtractorInput, source string) ([]string, []string) {
	var args []string
	var enabled []string
	args = append(args, "-o", input.OutputDir)

	threads := input.Threads
	if threads <= 0 {
		threads = 4
	}
	if threads > 16 {
		threads = 16
	}
	args = append(args, "-j", fmt.Sprintf("%d", threads))

	if input.Scanners != "" {
		args = append(args, "-x", "all")
		for _, s := range splitAndTrim(input.Scanners) {
			args = append(args, "-e", s)
			enabled = append(enabled, s)
		}
	} else {
		enabled = []string{"<all defaults>"}
	}

	for _, s := range splitAndTrim(input.DisableScanners) {
		args = append(args, "-x", s)
	}

	args = append(args, source)
	return args, enabled
}

func parseBEOutputDir(dir string, byType map[string]int) []CarvedFeature {
	var features []CarvedFeature

	entries, err := os.ReadDir(dir)
	if err != nil {
		return features
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".txt") {
			continue
		}
		if strings.Contains(name, "_histogram") || strings.Contains(name, "_context") {
			continue
		}
		featureType := strings.TrimSuffix(name, ".txt")
		if !allowedScanners[featureType] {
			continue 
		}

		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			// Format: offset\tfeature\tcontext
			cols := strings.SplitN(line, "\t", 3)
			if len(cols) < 2 {
				continue
			}
			cf := CarvedFeature{
				FeatureType: featureType,
				Offset:      cols[0],
				Feature:     cols[1],
			}
			if len(cols) == 3 {
				// Truncate context to 128 chars to protect context window
				ctx := cols[2]
				if len(ctx) > 128 {
					ctx = ctx[:128] + "…"
				}
				cf.Context = ctx
			}
			features = append(features, cf)
			byType[featureType]++
		}
		f.Close()
	}
	return features
}

func (o BulkExtractorOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(o, "", "  ")
}