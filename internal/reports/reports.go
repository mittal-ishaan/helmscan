package reports

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CreateSafeFileName creates a safe filename from a string by removing special characters
func CreateSafeFileName(input string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		".", "_",
		"@", "_",
		" ", "_",
	)
	return replacer.Replace(input)
}

// SaveToFile saves the report to a file in the working-files directory
func SaveToFile(report string, filename string) error {
	if err := os.MkdirAll("working-files", 0755); err != nil {
		return fmt.Errorf("error creating working-files directory: %w", err)
	}

	filepath := filepath.Join("working-files", filename)
	err := os.WriteFile(filepath, []byte(report), 0644)
	if err != nil {
		return fmt.Errorf("error writing report to file: %w", err)
	}

	fmt.Printf("\nReport saved to: %s\n", filepath)
	return nil
}

// Common table formatting functions
func FormatMarkdownTable(headers []string, rows [][]string) string {
	var sb strings.Builder

	// Write headers
	sb.WriteString("| " + strings.Join(headers, " | ") + " |\n")

	// Write separator
	sb.WriteString("|" + strings.Repeat("---------|", len(headers)) + "\n")

	// Write rows
	for _, row := range rows {
		sb.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}

	return sb.String()
}

// Common severity-related functions
func SeverityValue(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// Common report section formatting
func FormatSection(title string, content string) string {
	return fmt.Sprintf("### %s\n\n%s\n", title, content)
}
