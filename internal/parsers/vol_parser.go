package parsers

import (
	"strings"
)
func TruncateOutput(rawOutput string, maxLines int) string {
	lines := strings.Split(rawOutput, "\n")
	if len(lines) <= maxLines {
		return rawOutput
	}
	
	truncated := lines[:maxLines]
	truncated = append(truncated, "\n... [WARNING: OUTPUT TRUNCATED FOR AI CONTEXT SIZE LIMIT] ...")
	return strings.Join(truncated, "\n")
}