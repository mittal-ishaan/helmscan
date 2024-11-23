package reports

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// Update type definitions to be exported (uppercase)
type SortableCVE struct {
	ID       string
	Severity string
	Images   []string
}

type SortableCVEList []SortableCVE

func (s SortableCVEList) Len() int      { return len(s) }
func (s SortableCVEList) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SortableCVEList) Less(i, j int) bool {
	if SeverityValue(s[i].Severity) == SeverityValue(s[j].Severity) {
		return s[i].ID < s[j].ID
	}
	return SeverityValue(s[i].Severity) > SeverityValue(s[j].Severity)
}

// Vulnerability interface that both packages' vulnerability types must implement
type Vulnerability interface {
	GetID() string
	GetSeverity() string
}

// ConvertToJSONCVEs now accepts a map of Vulnerability interface
func ConvertToJSONCVEs(cves map[string]map[string]Vulnerability) []CVE {
	var jsonCVEs []CVE
	var sortedCVEs SortableCVEList

	for cveID, imageVulns := range cves {
		var images []string
		var severity string
		for imageName, vuln := range imageVulns {
			images = append(images, imageName)
			severity = vuln.GetSeverity()
		}
		sortedCVEs = append(sortedCVEs, SortableCVE{
			ID:       cveID,
			Severity: severity,
			Images:   images,
		})
	}

	sort.Sort(sortedCVEs)

	for _, cve := range sortedCVEs {
		jsonCVEs = append(jsonCVEs, CVE{
			ID:             cve.ID,
			Severity:       cve.Severity,
			AffectedImages: cve.Images,
		})
	}

	return jsonCVEs
}
