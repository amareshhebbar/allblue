package wrappers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

func SafeExec(binary string, args []string, timeoutMinutes time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutMinutes*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("execution timed out after %d minutes", timeoutMinutes)
	}

	if err != nil {
		return "", fmt.Errorf("execution failed: %v | stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}