package wrappers

import (
	"fmt"
)

func GetWindowsInfo(memoryDumpPath string) (string, error) {
	binary := "vol"
	args := []string{
		"-f", memoryDumpPath,
		"windows.info",
	}

	output, err := SafeExec(binary, args, 2)
	if err != nil {
		return "", fmt.Errorf("volatility windows.info failed: %w", err)
	}

	return output, nil
}