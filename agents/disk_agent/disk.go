package disk_agent

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gvamaresh/logposesift/internal/logger"
	"github.com/gvamaresh/logposesift/internal/validator"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

const agentName = "DiskAgent"

func ExtractAndParseTimeline(imagePath, outputCSV string) (string, error) {
	fmt.Printf("\n[DiskAgent] Starting disk triage on: %s\n", imagePath)
	log := logger.Get()

	var allFindings []string
	var confirmed, inferred, unverified int

	plasoPath := outputCSV + ".plaso"
	l2tOutput, l2tErr := runLog2Timeline(log, imagePath, plasoPath)
	if l2tErr != nil {
		fmt.Printf("[DiskAgent] log2timeline failed: %v — continuing with partial analysis\n", l2tErr)
	} else {
		conf := validator.QuickValidate("plaso_log2timeline", l2tOutput, plasoPath, "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[LOG2TIMELINE | %s]\n%s", conf, truncate(l2tOutput, 600)))
	}

	if l2tErr == nil {
		csvOutput, csvErr := runPsort(log, plasoPath, outputCSV)
		if csvErr == nil {
			conf := validator.QuickValidate("plaso_psort", csvOutput, outputCSV, "", "")
			trackConfidence(conf, &confirmed, &inferred, &unverified)
			allFindings = append(allFindings, fmt.Sprintf("[PSORT TIMELINE | %s]\n%s", conf, truncate(csvOutput, 1200)))
		}
	}

	flsOutput, flsErr := runFLS(log, imagePath)
	if flsErr == nil {
		conf := validator.QuickValidate("tsk_fls", flsOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[FILE SYSTEM LISTING | %s]\n%s", conf, truncate(flsOutput, 1000)))
	}

	mmlsOutput, mmlsErr := runMmls(log, imagePath)
	if mmlsErr == nil {
		conf := validator.QuickValidate("tsk_mmls", mmlsOutput, "", "", "")
		trackConfidence(conf, &confirmed, &inferred, &unverified)
		allFindings = append(allFindings, fmt.Sprintf("[PARTITION MAP | %s]\n%s", conf, truncate(mmlsOutput, 400)))
	}
	if flsErr == nil && countLines(flsOutput) < 10 {
		fmt.Printf("[DiskAgent] Self-correction: FLS returned few entries (%d lines), re-running with -d (deleted files)\n",
			countLines(flsOutput))
		deletedOutput, delErr := runFLSDeleted(log, imagePath)
		if delErr == nil && deletedOutput != "" {
			conf := validator.QuickValidate("tsk_fls_deleted", deletedOutput, "", "", "")
			trackConfidence(conf, &confirmed, &inferred, &unverified)
			allFindings = append(allFindings,
				fmt.Sprintf("[FLS DELETED (self-corrected: sparse initial output) | %s]\n%s",
					conf, truncate(deletedOutput, 800)))
		}
	}

	report := composeSummary(imagePath, allFindings, confirmed, inferred, unverified)
	log.SessionSummary(confirmed, inferred, unverified, confirmed+inferred+unverified)
	return report, nil
}


func runLog2Timeline(log *logger.Logger, imagePath, plasoPath string) (string, error) {
	rec, start := logger.NewRecord("plaso_log2timeline", agentName,
		"Build a super-timeline from all artefact sources in the disk image",
		"Expect a .plaso storage file with events from registry, NTFS, prefetch, event logs")
	rec.Input = map[string]string{"image_path": imagePath, "plaso_path": plasoPath}

	output, err := wrappers.RunRegistryToolMultiTarget("plaso_log2timeline",
		map[string]string{"TARGET": imagePath, "image_path": imagePath})

	confidence := "UNVERIFIED"
	if err == nil {
		if _, statErr := os.Stat(plasoPath); statErr == nil {
			confidence = "CONFIRMED"
		} else {
			confidence = "INFERRED"
		}
	} else {
		rec.Delta = fmt.Sprintf("log2timeline failed: %v — may indicate unsupported filesystem or corrupted image", err)
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runPsort(log *logger.Logger, plasoPath, outputCSV string) (string, error) {
	rec, start := logger.NewRecord("plaso_psort", agentName,
		"Export filtered timeline to CSV for event-by-event analysis",
		"Expect CSV rows ordered by timestamp with source, description, and filename columns")
	rec.Input = map[string]string{"plaso_path": plasoPath, "output_csv": outputCSV}

	output, err := wrappers.RunRegistryToolMultiTarget("plaso_psort",
		map[string]string{"TARGET": plasoPath, "plaso_file": plasoPath})

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

func runFLS(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_fls", agentName,
		"List all files and directories in the filesystem to identify suspicious artefacts",
		"Expect standard Windows/Linux directory structure; flag unusual executables in temp, appdata, root")
	rec.Input = map[string]string{"image_path": imagePath}

	output, err := wrappers.RunRegistryTool("tsk_fls", imagePath)
	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runFLSDeleted(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_fls_deleted", agentName,
		"Self-correction: re-run FLS with deleted-file flag after sparse initial output",
		"Expect deleted file entries — attacker may have cleaned up executables")
	rec.Input = map[string]string{"image_path": imagePath, "flags": "-d"}
	rec.Delta = "Triggered because initial FLS returned <10 entries — possible sparse image or aggressive cleanup"

	output, err := wrappers.SafeExec("fls", []string{"-r", "-d", imagePath}, 10)
	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		confidence = "INFERRED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}

func runMmls(log *logger.Logger, imagePath string) (string, error) {
	rec, start := logger.NewRecord("tsk_mmls", agentName,
		"Map partition layout to verify filesystem offsets for all subsequent tools",
		"Expect MBR or GPT partition table with sector offsets")
	rec.Input = map[string]string{"image_path": imagePath}

	output, err := wrappers.RunRegistryTool("tsk_mmls", imagePath)
	confidence := "UNVERIFIED"
	if err == nil && output != "" {
		confidence = "CONFIRMED"
	}
	logger.Finish(&rec, start, truncate(output, 200), err, confidence)
	return output, err
}


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