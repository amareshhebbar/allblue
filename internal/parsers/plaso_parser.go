package parsers

import (
	"os"
)

func ParseTimeline(csvPath string, maxLines int) (string, error) {
	data, err := os.ReadFile(csvPath)
	if err != nil {
		return "", err
	}
	
	return TruncateOutput(string(data), maxLines), nil
}