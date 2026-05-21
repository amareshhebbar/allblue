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

type ForemostInput struct {
	ImagePath string `json:"image_path"`

	OutputDir string `json:"output_dir"`

	FileTypes string `json:"file_types,omitempty"`

	QuickMode bool `json:"quick_mode,omitempty"`

	Verbose bool `json:"verbose,omitempty"`

	TimeoutSecs int `json:"timeout_secs,omitempty"`
}

type CarvedFile struct {
	FileType   string `json:"file_type"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`
	SizeBytes  int64  `json:"size_bytes"`
	Offset     string `json:"offset,omitempty"` 
	SHA256Hash string `json:"sha256_hash,omitempty"`
}

type ForemostOutput struct {
	ImagePath    string       `json:"image_path"`
	OutputDir    string       `json:"output_dir"`
	FileTypes    []string     `json:"file_types_carved"`
	Recovered    []CarvedFile `json:"recovered_files"`
	RecoveredCnt int          `json:"recovered_count"`
	ByType       map[string]int `json:"recovered_by_type"`
	DurationMs   int64        `json:"duration_ms"`
	Error        string       `json:"error,omitempty"`
	Confidence   string       `json:"confidence"`
}

var allowedForemostTypes = map[string]bool{
	"jpg": true, "gif": true, "png": true, "bmp": true, "avi": true,
	"exe": true, "mpg": true, "wav": true, "riff": true, "wmv": true,
	"mov": true, "pdf": true, "ole": true, "doc": true, "zip": true,
	"rar": true, "htm": true, "cpp": true, "all": true,
}

func RunForemost(input ForemostInput) (ForemostOutput, error) {
	start := time.Now()
	out := ForemostOutput{
		ImagePath:  input.ImagePath,
		OutputDir:  input.OutputDir,
		ByType:     make(map[string]int),
		Confidence: "UNVERIFIED",
	}

	if err := validateForemostInput(input); err != nil {
		out.Error = err.Error()
		return out, err
	}

	types := resolveForemostTypes(input.FileTypes)
	out.FileTypes = types
	args := buildForemostArgs(input, types)

	timeout := clampTimeout(input.TimeoutSecs, 300, 3600)
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "foremost", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if !dirExists(input.OutputDir) {
			out.Error = fmt.Sprintf("foremost error: %v | %s", err, stderr.String())
			out.DurationMs = time.Since(start).Milliseconds()
			return out, err
		}
	}

	out.Recovered = parseForemostOutput(input.OutputDir, out.ByType)
	out.RecoveredCnt = len(out.Recovered)
	out.DurationMs = time.Since(start).Milliseconds()

	if out.RecoveredCnt > 0 {
		out.Confidence = "INFERRED"
	}
	return out, nil
}

func validateForemostInput(input ForemostInput) error {
	if input.ImagePath == "" {
		return fmt.Errorf("image_path is required")
	}
	if input.OutputDir == "" {
		return fmt.Errorf("output_dir is required")
	}
	for _, f := range []string{input.ImagePath, input.OutputDir} {
		if containsShellMeta(f) {
			return fmt.Errorf("path contains disallowed shell metacharacters")
		}
	}
	if err := validateOutputPath(input.OutputDir); err != nil {
		return err
	}
	for _, t := range splitAndTrim(input.FileTypes) {
		if !allowedForemostTypes[t] {
			return fmt.Errorf("file type %q not in allowlist", t)
		}
	}
	return nil
}

func buildForemostArgs(input ForemostInput, types []string) []string {
	args := []string{
		"-i", input.ImagePath,
		"-o", input.OutputDir,
		"-T", 
	}
	if input.QuickMode {
		args = append(args, "-q")
	}
	if input.Verbose {
		args = append(args, "-v")
	}
	if len(types) > 0 && !(len(types) == 1 && types[0] == "all") {
		args = append(args, "-t", strings.Join(types, ","))
	}
	return args
}

func resolveForemostTypes(raw string) []string {
	if raw == "" {
		return []string{"all"}
	}
	return splitAndTrim(raw)
}

func parseForemostOutput(outputDir string, byType map[string]int) []CarvedFile {
	var files []CarvedFile
	auditPath := filepath.Join(outputDir, "audit.txt")
	files = append(files, parseForemostAudit(auditPath, byType)...)

	if len(files) == 0 {
		files = walkForemostDir(outputDir, byType)
	}
	return files
}

func parseForemostAudit(auditPath string, byType map[string]int) []CarvedFile {
	f, err := os.Open(auditPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var files []CarvedFile
	var currentDir string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Foremost") || strings.HasPrefix(line, "Processing") {
			continue
		}
		if strings.HasPrefix(line, "Directory:") {
			currentDir = strings.TrimSpace(strings.TrimPrefix(line, "Directory:"))
			continue
		}
		cols := strings.Fields(line)
		if len(cols) < 2 {
			continue
		}
		ext := strings.TrimPrefix(filepath.Ext(cols[0]), ".")
		if ext == "" {
			continue
		}
		sz, _ := strconv.ParseInt(cols[1], 10, 64)
		cf := CarvedFile{
			FileType:  ext,
			FileName:  cols[0],
			FilePath:  filepath.Join(currentDir, cols[0]),
			SizeBytes: sz,
		}
		if len(cols) >= 3 {
			cf.Offset = cols[2]
		}
		files = append(files, cf)
		byType[ext]++
	}
	return files
}

func walkForemostDir(outputDir string, byType map[string]int) []CarvedFile {
	var files []CarvedFile
	_ = filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.TrimPrefix(filepath.Ext(d.Name()), ".")
		if ext == "" || ext == "txt" {
			return nil
		}
		info, _ := d.Info()
		var sz int64
		if info != nil {
			sz = info.Size()
		}
		cf := CarvedFile{
			FileType:  ext,
			FileName:  d.Name(),
			FilePath:  path,
			SizeBytes: sz,
		}
		files = append(files, cf)
		byType[ext]++
		return nil
	})
	return files
}

func (o ForemostOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(o, "", "  ")
}