package wrappers

import (
	"fmt"
)

const volSymbolsPath = "/opt/volatility3/lib/python3.12/site-packages/volatility3/symbols"

func GetWindowsInfo(memoryDumpPath string) (string, error) {
	output, err := SafeExec("vol", []string{
	//	"-s", volSymbolsPath,
		"-f", memoryDumpPath,
		"windows.info",
	}, 2)
	if err != nil {
		return "", fmt.Errorf("volatility windows.info failed: %w", err)
	}
	return output, nil
}