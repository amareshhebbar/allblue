package disk_agent

import (
	"fmt"
	"github.com/gvamaresh/logposesift/internal/parsers"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

// ExtractAndParseTimeline processes a disk image and returns a readable timeline for the AI
func ExtractAndParseTimeline(imagePath string, outputCsv string) (string, error) {
	storageFile := imagePath + ".plaso"

	fmt.Printf("[*] Disk Agent: Building timeline database for %s...\n", imagePath)
	_, err := wrappers.RunLog2Timeline(storageFile, imagePath)
	if err != nil {
		return "", fmt.Errorf("log2timeline execution failed: %v", err)
	}

	fmt.Println("[*] Disk Agent: Exporting timeline to CSV...")
	_, err = wrappers.RunPsort(outputCsv, storageFile, "")
	if err != nil {
		return "", fmt.Errorf("psort execution failed: %v", err)
	}

	fmt.Println("[*] Disk Agent: Parsing and formatting timeline for AI consumption...")
	
	// Pass the top 200 lines to the AI so it gets the most critical recent events
	timelineData, err := parsers.ParseTimeline(outputCsv, 200)
	if err != nil {
		return "", fmt.Errorf("failed to read timeline CSV: %v", err)
	}

	return timelineData, nil
}