package logger

import (
	"fmt"
	"os"
	"time"
)

func LogAction(engine string, action string, details string) {
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}

	filename := fmt.Sprintf("%s/execution_log_%s.txt", logDir, time.Now().Format("2006-01-02"))
	
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[!] Warning: Could not open log file: %v\n", err)
		return
	}
	defer f.Close()

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] [ENGINE: %s] | ACTION: %s | DETAILS: %s\n", timestamp, engine, action, details)
	
	if _, err := f.WriteString(logEntry); err != nil {
		fmt.Printf("[!] Warning: Could not write to log file: %v\n", err)
	}
}