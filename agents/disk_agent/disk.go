package disk_agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gvamaresh/allblue/internal/logger"
	"github.com/gvamaresh/allblue/internal/validator"
	"github.com/gvamaresh/allblue/internal/wrappers"
)

const agentName = "DiskAgent"

// ExtractAndParseTimeline is the main disk triage entry point.
// Sequence: mmls → fls → log2timeline → psort → strings on executables
// Self-correction: if fls sparse → retry with deleted flag
// Evidence type detection: rejects memory dumps gracefully
func ExtractAndParseTimeline(imagePath, outputCSV string) (string, error) {
	fmt.Printf("\n[DiskAgent] Starting disk triage on: %s\n", imagePath)
	log := logger.Get()

	var allFindings []string
	var confirmed, inferred, unverified int

	// ── Guard: reject memory dumps ────────────────────────────
	// Disk tools fail silently on memory dumps. Detect and report clearly.
	if isDiskImage, reason := validateDiskImage(imagePath); !isDiskImage {
		return fmt.Sprintf(
			"══════════════════════════════════════════════\n"+
				"         DISK AGENT — TRIAGE REPORT\n"+
				"══════════════════════════════════════════════\n"+
				"Source : %s\n"+
				"Status : SKIPPED — %s\n"+
				"Action : Provide a disk image (.img/.dd/.E01) not a memory dump.\n"+
				"══════════════════════════════════════════════\n",
			imagePath, reason), nil
	}

	// ── Step 1: Partition map (orientation) ───────────────────
	mmlsOutput, mmlsErr := runMmls(log, imagePath)
	if mmlsErr == nil && len(mmlsOutput) > 50 {
		conf := "CONFIRMED" // partition table is deterministic
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[PARTITION MAP | %s]\n%s", conf, truncate(mmlsOutput, 400)))
	}

	// ── Step 2: Filesystem listing ────────────────────────────
	flsOutput, flsErr := runFLS(log, imagePath)
	if flsErr == nil && len(flsOutput) > 50 {
		conf := validator.QuickValidate("tsk_fls", flsOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		suspicious := extractSuspiciousFiles(flsOutput)
		finding := fmt.Sprintf("[FILE SYSTEM LISTING | %s]\n%s", conf, truncate(flsOutput, 1200))
		if len(suspicious) > 0 {
			finding += fmt.Sprintf("\n⚠ SUSPICIOUS FILES: %s", strings.Join(suspicious, ", "))
		}
		allFindings = append(allFindings, finding)
	}

	// ── Self-correction: sparse FLS → retry with deleted flag ─
	if flsErr == nil && countLines(flsOutput) < 10 {
		fmt.Printf("[DiskAgent] Self-correction: FLS returned %d lines — re-running with -d (deleted files)\n",
			countLines(flsOutput))
		deletedOutput, delErr := runFLSDeleted(log, imagePath)
		if delErr == nil && len(deletedOutput) > 50 {
			conf := validator.QuickValidate("tsk_fls_deleted", deletedOutput, "", "", "")
			trackConfidence(conf, &confirmed, &inferred, &unverified)
			allFindings = append(allFindings,
				fmt.Sprintf("[FLS DELETED (self-corrected: sparse initial output) | %s]\n%s",
					conf, truncate(deletedOutput, 800)))
		}
	}

	// ── Step 3: log2timeline super-timeline ──────────────────
	// Use a deterministic output path inside /tmp — not the CSV path
	plasoPath := filepath.Join("/tmp", "logpose_timeline.plaso")
	l2tOutput, l2tErr := runLog2Timeline(log, imagePath, plasoPath)
	if l2tErr != nil {
		fmt.Printf("[DiskAgent] log2timeline failed: %v — continuing with partial analysis\n", l2tErr)
		allFindings = append(allFindings,
			"[LOG2TIMELINE | UNVERIFIED]\nlog2timeline failed — image may be a memory dump or unsupported filesystem.\n"+
				"Use a raw disk image (.img/.dd) or E01 format.")
		unverified++
	} else {
		conf := "INFERRED"
		if _, statErr := os.Stat(plasoPath); statErr == nil {
			conf = "CONFIRMED"
		}
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[LOG2TIMELINE | %s]\n%s", conf, truncate(l2tOutput, 600)))
	}

	// ── Step 4: psort timeline export ─────────────────────────
	if l2tErr == nil {
		csvOutput, csvErr := runPsort(log, plasoPath, outputCSV)
		if csvErr == nil {
			conf := "INFERRED"
			if _, statErr := os.Stat(outputCSV); statErr == nil {
				conf = "CONFIRMED"
			}
			trackConfidence(conf, &confirmed, &inferred, &unverified)
			suspicious := extractTimelineIOCs(csvOutput)
			finding := fmt.Sprintf("[TIMELINE | %s]\n%s", conf, truncate(csvOutput, 1200))
			if len(suspicious) > 0 {
				finding += fmt.Sprintf("\n⚠ TIMELINE IOCs: %s", strings.Join(suspicious, " | "))
			}
			allFindings = append(allFindings, finding)
		}
	}

	// ── Step 5: Strings on suspicious executables (if any found) ─
	if flsErr == nil {
		execPaths := extractExecutablePaths(flsOutput)
		if len(execPaths) > 0 {
			fmt.Printf("[DiskAgent] Running strings on %d suspicious executables\n", len(execPaths))
			for _, execPath := range execPaths[:minInt(3, len(execPaths))] {
				strOutput, strErr := runStrings(log, execPath)
				if strErr == nil && len(strOutput) > 100 {
					conf := "INFERRED"
					trackConfidence(conf, &confirmed, &inferred, &unverified)
					allFindings = append(allFindings,
						fmt.Sprintf("[STRINGS | %s | %s]\n%s", conf, filepath.Base(execPath),
							truncate(strOutput, 600)))
				}
			}
		}
	}

	report := composeSummary(imagePath, allFindings, confirmed, inferred, unverified)
	log.SessionSummary(confirmed, inferred, unverified, confirmed+inferred+unverified)
	return report, nil
}

// ── Individual step runners ───────────────────────────────────

func runMmls(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_mmls", agentName,
		"Map partition layout to verify filesystem type and sector offsets for all subsequent tools",
		"Expect MBR or GPT with NTFS/EXT4 partitions; unusual partition types indicate wiping or encryption")
	rec.Input = map[string]string{"image_path": imagePath}

	output, err := wrappers.RunRegistryTool("tsk_mmls", imagePath)
	confidence := "UNVERIFIED"
	if err == nil && len(output) > 20 {
		confidence = "CONFIRMED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runFLS(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_fls", agentName,
		"List all allocated files and directories to identify suspicious executables, scripts, and data files",
		"Flag executables in: temp directories, AppData, ProgramData, root C:\\, unusual user profile locations")
	rec.Input = map[string]string{"image_path": imagePath}

	output, err := wrappers.RunRegistryTool("tsk_fls", imagePath)
	confidence := "UNVERIFIED"
	if err == nil && len(output) > 50 {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runFLSDeleted(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_fls_deleted", agentName,
		"Self-correction: re-run FLS with deleted-file flag after sparse initial output",
		"Attacker may have deleted executables after execution; deleted inodes may still be recoverable")
	rec.Input = map[string]string{"image_path": imagePath, "flags": "-d"}
	rec.Delta = "Triggered because initial FLS returned <10 entries — possible aggressive cleanup or sparse image"

	output, err := wrappers.SafeExec("fls", []string{"-r", "-d", imagePath}, 10)
	confidence := "UNVERIFIED"
	if err == nil && len(output) > 50 {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runLog2Timeline(log *logger.Logger, imagePath, plasoPath string) (string, error) {
	rec, start := logger.NewRecord("plaso_log2timeline", agentName,
		"Build a super-timeline ingesting all artefact sources: NTFS MFT, registry, prefetch, event logs, LNK files",
		"Expect .plaso storage file; execution time 5-30 min depending on image size")
	rec.Input = map[string]string{"image_path": imagePath, "plaso_path": plasoPath}

	// Remove old plaso file if exists to avoid "already exists" error
	os.Remove(plasoPath)

	// Build args directly — registry entry has hardcoded path, override here
	output, err := wrappers.SafeExec("log2timeline.py",
		[]string{"--storage-file", plasoPath, "--quiet", imagePath}, 120)

	confidence := "UNVERIFIED"
	if err == nil {
		if _, statErr := os.Stat(plasoPath); statErr == nil {
			confidence = "CONFIRMED"
		} else {
			confidence = "INFERRED"
		}
	} else {
		rec.Delta = fmt.Sprintf("log2timeline failed: %v — check image format and filesystem support", err)
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runPsort(log *logger.Logger, plasoPath, outputCSV string) (string, error) {
	rec, start := logger.NewRecord("plaso_psort", agentName,
		"Export filtered super-timeline to CSV for chronological event analysis",
		"Expect rows ordered by timestamp; look for rapid file creation bursts, off-hours activity, deleted MFT entries")
	rec.Input = map[string]string{"plaso_path": plasoPath, "output_csv": outputCSV}

	output, err := wrappers.SafeExec("psort.py",
		[]string{"-o", "l2tcsv", "-w", outputCSV, "--storage-file", plasoPath}, 30)

	confidence := "UNVERIFIED"
	if err == nil {
		if _, statErr := os.Stat(outputCSV); statErr == nil {
			confidence = "CONFIRMED"
		} else {
			confidence = "INFERRED"
		}
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runStrings(log *logger.Logger, filePath string) (string, error) {
	rec, start := logger.NewRecord("analyze_strings", agentName,
		fmt.Sprintf("Extract printable strings from suspicious binary: %s", filepath.Base(filePath)),
		"Flag: URLs (http/https), IP addresses, registry paths, command strings, encoded data patterns")
	rec.Input = map[string]string{"file_path": filePath}

	output, err := wrappers.RunRegistryTool("analyze_strings", filePath)
	confidence := "UNVERIFIED"
	if err == nil && len(output) > 100 {
		iocs := extractStringIOCs(output)
		if len(iocs) > 0 {
			confidence = "CONFIRMED"
			rec.Delta = fmt.Sprintf("IOC strings found: %s", strings.Join(iocs[:minInt(3, len(iocs))], "; "))
		} else {
			confidence = "INFERRED"
		}
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

// ── Evidence type detection ───────────────────────────────────

// validateDiskImage returns (true, "") if the path looks like a disk image,
// or (false, reason) if it looks like a memory dump or is invalid.
func validateDiskImage(imagePath string) (bool, string) {
	info, err := os.Stat(imagePath)
	if err != nil {
		return false, fmt.Sprintf("file not found: %v", err)
	}

	// Memory dumps are typically 1-32 GB with no partition table
	// Disk images can also be large, so check extension hints
	ext := strings.ToLower(filepath.Ext(imagePath))
	base := strings.ToLower(filepath.Base(imagePath))

	memoryExtensions := map[string]bool{
		".raw": true, ".vmem": true, ".lime": true, ".dmp": true, ".mem": true,
	}
	memoryKeywords := []string{"memory", "mem-", "mem.", "ram.", "vmem"}

	// If extension is unambiguously a memory format
	if memoryExtensions[ext] {
		for _, kw := range memoryKeywords {
			if strings.Contains(base, kw) {
				return false, fmt.Sprintf("path %q appears to be a memory dump (ext: %s, name: %s) — use a disk image instead", imagePath, ext, base)
			}
		}
	}

	// If it's very large (>4GB) with .img or .dd, it's likely a disk image — proceed
	if info.Size() > 4*1024*1024*1024 {
		return true, ""
	}

	// Default: attempt to proceed, let mmls validate
	return true, ""
}

// ── Analysis helpers ──────────────────────────────────────────

var suspiciousFilePatterns = []string{
	"temp\\", "tmp\\", "appdata\\local\\temp", "appdata\\roaming",
	"programdata\\", "c:\\users\\public\\", "recycle",
	".exe", ".ps1", ".bat", ".vbs", ".js", ".hta",
}

func extractSuspiciousFiles(flsOutput string) []string {
	var suspicious []string
	seen := map[string]bool{}
	lower := strings.ToLower(flsOutput)
	for _, line := range strings.Split(lower, "\n") {
		for _, pat := range suspiciousFilePatterns {
			if strings.Contains(line, pat) && !seen[line] {
				seen[line] = true
				if len(line) > 10 {
					suspicious = append(suspicious, strings.TrimSpace(line[:minInt(80, len(line))]))
				}
				break
			}
		}
		if len(suspicious) >= 10 {
			break
		}
	}
	return suspicious
}

func extractExecutablePaths(flsOutput string) []string {
	var paths []string
	for _, line := range strings.Split(flsOutput, "\n") {
		if strings.HasSuffix(strings.ToLower(line), ".exe") ||
			strings.HasSuffix(strings.ToLower(line), ".dll") {
			// Extract path from fls output format
			parts := strings.Fields(line)
			if len(parts) > 0 {
				paths = append(paths, parts[len(parts)-1])
			}
		}
		if len(paths) >= 5 {
			break
		}
	}
	return paths
}

func extractTimelineIOCs(csvOutput string) []string {
	var iocs []string
	suspiciousEvents := []string{
		"RunMRU", "UserAssist", "AppCompatCache", "ShimCache",
		"Prefetch", "LNK", "RecentDocs", "TypedURLs",
		"SYSTEM\\CurrentControlSet\\Services",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	}
	for _, event := range suspiciousEvents {
		if strings.Contains(csvOutput, event) {
			iocs = append(iocs, event)
		}
	}
	return iocs
}

func extractStringIOCs(strOutput string) []string {
	var iocs []string
	iocPatterns := []string{
		"http://", "https://", "cmd.exe", "powershell",
		"certutil", "bitsadmin", "net user", "reg add",
	}
	lower := strings.ToLower(strOutput)
	for _, pat := range iocPatterns {
		if strings.Contains(lower, pat) {
			iocs = append(iocs, pat)
		}
	}
	return iocs
}

// ── Utility helpers ───────────────────────────────────────────

func trackConfidence(conf string, confirmed, inferred, unverified *int) {
	switch conf {
	case "CONFIRMED":
		*confirmed++
	case "INFERRED":
		*inferred++
	default:
		*unverified++
	}
}

func countLines(s string) int {
	return len(strings.Split(strings.TrimSpace(s), "\n"))
}

func composeSummary(imagePath string, findings []string, confirmed, inferred, unverified int) string {
	var sb strings.Builder
	sb.WriteString("══════════════════════════════════════════════\n")
	sb.WriteString("         DISK AGENT — TRIAGE REPORT\n")
	sb.WriteString("══════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("Source : %s\n", imagePath))
	sb.WriteString(fmt.Sprintf("Time   : %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Confidence: ✓ %d CONFIRMED  ~ %d INFERRED  ? %d UNVERIFIED\n\n",
		confirmed, inferred, unverified))
	for _, f := range findings {
		sb.WriteString(f)
		sb.WriteString("\n\n")
	}
	sb.WriteString("══════════════════════════════════════════════\n")
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…[truncated]"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}