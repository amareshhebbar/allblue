package wrappers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)


var shellMeta = []rune{
	';', '&', '|', '`', '$', '(', ')', '{', '}',
	'<', '>', '!', '#', '~', '*', '?', '[', ']',
	'\\', '\n', '\r', '\t',
}

func containsShellMeta(s string) bool {
	for _, ch := range s {
		for _, meta := range shellMeta {
			if ch == meta {
				return true
			}
		}
	}
	return false
}

func isAllowedFilterChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) ||
		ch == ' ' || ch == '\'' || ch == '"' || ch == '.' ||
		ch == '_' || ch == '-' || ch == '/' || ch == ':'
}

func workingDir() string {
	if d := os.Getenv("allblue_WORK_DIR"); d != "" {
		return d
	}
	return "/opt/allblue/work"
}

func validateOutputPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve output path: %v", err)
	}
	wd := workingDir()
	if !strings.HasPrefix(abs, wd) {
		return fmt.Errorf("output_path %q must be under working directory %s", abs, wd)
	}
	return nil
}

func clampTimeout(supplied, defaultSecs, maxSecs int) int {
	if supplied <= 0 {
		return defaultSecs
	}
	if supplied > maxSecs {
		return maxSecs
	}
	return supplied
}

func contextWithTimeout(timeoutSecs int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

func createOutputFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %v", filepath.Dir(path), err)
	}
	return os.Create(path)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func unixToRFC3339(ts string) string {
	ts = strings.TrimSpace(ts)
	if ts == "" || ts == "0" {
		return ""
	}
	var sec int64
	if _, err := fmt.Sscanf(ts, "%d", &sec); err != nil {
		return ts
	}
	t := time.Unix(sec, 0).UTC()
	if t.Year() < 1990 || t.Year() > 2100 {
		return ts
	}
	return t.Format(time.RFC3339)
}


const (
	ConfidenceConfirmed  = "CONFIRMED" 
	ConfidenceInferred   = "INFERRED"   
	ConfidenceUnverified = "UNVERIFIED" 
)