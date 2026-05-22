package validator

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	Confirmed  = "CONFIRMED"
	Inferred   = "INFERRED"
	Unverified = "UNVERIFIED"
)

type Finding struct {
	Source     string 
	Claim      string 
	FilePath   string 
	Timestamp  string 
	Hash       string 
	Confidence string 
	Reason     string 
}

type ValidationResult struct {
	Original   Finding
	Confidence string
	Checks     []CheckResult
	Reason     string
}

type CheckResult struct {
	Name    string
	Passed  bool
	Note    string
}


func Validate(f Finding) ValidationResult {
	var checks []CheckResult
	passCount := 0

	if f.FilePath != "" {
		c := checkFileExists(f.FilePath)
		checks = append(checks, c)
		if c.Passed {
			passCount++
		}
	}

	if f.Timestamp != "" {
		c := checkTimestampPlausible(f.Timestamp)
		checks = append(checks, c)
		if c.Passed {
			passCount++
		}
	}
	c := checkNoHallucinationMarkers(f.Claim)
	checks = append(checks, c)
	if c.Passed {
		passCount++
	}

	if f.Hash != "" {
		c := checkHashFormat(f.Hash)
		checks = append(checks, c)
		if c.Passed {
			passCount++
		}
	}

	total := len(checks)
	confidence := assignConfidence(passCount, total, f.Hash != "")
	reason := buildReason(checks, passCount, total)

	return ValidationResult{
		Original:   f,
		Confidence: confidence,
		Checks:     checks,
		Reason:     reason,
	}
}

func ValidateAll(findings []Finding) ([]ValidationResult, int, int, int) {
	results := make([]ValidationResult, len(findings))
	confirmed, inferred, unverified := 0, 0, 0
	for i, f := range findings {
		r := Validate(f)
		results[i] = r
		switch r.Confidence {
		case Confirmed:
			confirmed++
		case Inferred:
			inferred++
		default:
			unverified++
		}
	}
	return results, confirmed, inferred, unverified
}


func checkFileExists(path string) CheckResult {
	c := CheckResult{Name: "file_exists"}
	if _, err := os.Stat(path); err == nil {
		c.Passed = true
		c.Note = "file confirmed on disk"
	} else {
		c.Note = fmt.Sprintf("file not found: %v", err)
	}
	return c
}

func checkTimestampPlausible(ts string) CheckResult {
	c := CheckResult{Name: "timestamp_plausible"}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		for _, layout := range []string{
			"2006-01-02 15:04:05",
			"Mon Jan  2 15:04:05 2006",
			"01/02/2006 15:04:05",
		} {
			t, err = time.Parse(layout, ts)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		c.Note = fmt.Sprintf("cannot parse timestamp %q: %v", ts, err)
		return c
	}
	low := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	high := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	if t.Before(low) || t.After(high) {
		c.Note = fmt.Sprintf("timestamp %s outside plausible range (1990–2100)", t.Format(time.RFC3339))
		return c
	}
	c.Passed = true
	c.Note = fmt.Sprintf("timestamp %s is within plausible range", t.Format(time.RFC3339))
	return c
}

var hallucinationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bI (believe|think|assume|suspect)\b`),
	regexp.MustCompile(`(?i)\blikely (located|found|exists)\b`),
	regexp.MustCompile(`(?i)\bprobably (at|in|on|a)\b`),
	regexp.MustCompile(`(?i)\bcould not (find|locate|access)\b`),
	regexp.MustCompile(`(?i)\bno (data|output|results?) (available|returned|found)\b`),
	regexp.MustCompile(`(?i)\bas (an AI|a language model)\b`),
}

func checkNoHallucinationMarkers(claim string) CheckResult {
	c := CheckResult{Name: "no_hallucination_markers"}
	for _, pat := range hallucinationPatterns {
		if pat.MatchString(claim) {
			c.Note = fmt.Sprintf("hallucination marker detected: %q", pat.String())
			return c
		}
	}
	c.Passed = true
	c.Note = "no hallucination markers found"
	return c
}

var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
var md5Re = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func checkHashFormat(hash string) CheckResult {
	c := CheckResult{Name: "hash_format_valid"}
	h := strings.TrimSpace(hash)
	if sha256Re.MatchString(h) || md5Re.MatchString(h) {
		c.Passed = true
		c.Note = "hash format is valid"
	} else {
		c.Note = fmt.Sprintf("hash %q is not a valid MD5 or SHA-256", h)
	}
	return c
}


func assignConfidence(passCount, total int, hasHash bool) string {
	if total == 0 {
		return Unverified
	}
	ratio := float64(passCount) / float64(total)
	if hasHash && passCount == total {
		return Confirmed
	}
	if ratio == 1.0 {
		return Inferred
	}
	if ratio >= 0.6 {
		return Inferred
	}
	return Unverified
}

func buildReason(checks []CheckResult, passCount, total int) string {
	var failed []string
	for _, c := range checks {
		if !c.Passed {
			failed = append(failed, fmt.Sprintf("%s: %s", c.Name, c.Note))
		}
	}
	if len(failed) == 0 {
		return fmt.Sprintf("all %d checks passed", total)
	}
	return fmt.Sprintf("%d/%d checks passed; failures: %s", passCount, total, strings.Join(failed, "; "))
}

func QuickValidate(tool, claim, filePath, timestamp, hash string) string {
	r := Validate(Finding{
		Source:    tool,
		Claim:     claim,
		FilePath:  filePath,
		Timestamp: timestamp,
		Hash:      hash,
	})
	return r.Confidence
}