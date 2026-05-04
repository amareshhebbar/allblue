package memory_agent

import (
	"fmt"
	"github.com/gvamaresh/logposesift/internal/parsers"
	"github.com/gvamaresh/logposesift/internal/wrappers"
)

// HuntMalware is a specialized workflow that checks processes and network connections
func HuntMalware(dumpPath string) (string, error) {
	fmt.Println("[*] Memory Agent: Extracting process list (pslist)...")
	pslist, err := wrappers.GetPSList(dumpPath)
	if err != nil {
		return "", fmt.Errorf("pslist failed: %v", err)
	}

	fmt.Println("[*] Memory Agent: Extracting network connections (netscan)...")
	netscan, err := wrappers.GetNetScan(dumpPath)
	if err != nil {
		return "", fmt.Errorf("netscan failed: %v", err)
	}

	// Combine and truncate the outputs to keep the LLM prompt clean and under the token limit
	combinedReport := fmt.Sprintf("=== RUNNING PROCESSES ===\n%s\n\n=== NETWORK CONNECTIONS ===\n%s",
		parsers.TruncateOutput(pslist, 150),
		parsers.TruncateOutput(netscan, 150),
	)

	return combinedReport, nil
}