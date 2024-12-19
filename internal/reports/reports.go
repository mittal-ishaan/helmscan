package reports

import (
	"encoding/json"
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

// Add these types after the existing types
type SingleScanReport struct {
	ArtifactType string // "helm" or "image"
	ArtifactRef  string // Full reference to the scanned artifact
	Summary      SeveritySummary
	CVEs         []CVE
}

type SeveritySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Add these functions after the existing functions
func GenerateSingleScanReport(artifactType string, artifactRef string, vulns map[string]Vulnerability, generateJSON bool) string {
	report := SingleScanReport{
		ArtifactType: artifactType,
		ArtifactRef:  artifactRef,
		Summary:      countVulnerabilities(vulns),
		CVEs:         convertVulnerabilitiesToCVEs(vulns),
	}

	if generateJSON {
		return generateJSONSingleReport(report)
	}
	return generateMarkdownSingleReport(report)
}

func countVulnerabilities(vulns map[string]Vulnerability) SeveritySummary {
	summary := SeveritySummary{}
	for _, vuln := range vulns {
		switch strings.ToLower(vuln.GetSeverity()) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}
	return summary
}

func convertVulnerabilitiesToCVEs(vulns map[string]Vulnerability) []CVE {
	var cves []CVE
	for id, vuln := range vulns {
		cves = append(cves, CVE{
			ID:       id,
			Severity: vuln.GetSeverity(),
		})
	}

	sort.Slice(cves, func(i, j int) bool {
		if SeverityValue(cves[i].Severity) == SeverityValue(cves[j].Severity) {
			return cves[i].ID < cves[j].ID
		}
		return SeverityValue(cves[i].Severity) > SeverityValue(cves[j].Severity)
	})

	return cves
}

func generateJSONSingleReport(report SingleScanReport) string {
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func generateMarkdownSingleReport(report SingleScanReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s Scan Report\n", strings.Title(report.ArtifactType)))
	sb.WriteString(fmt.Sprintf("## Artifact: %s\n\n", report.ArtifactRef))

	// Summary table
	sb.WriteString("### Vulnerability Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", report.Summary.Critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", report.Summary.High))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", report.Summary.Medium))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n\n", report.Summary.Low))

	// CVEs by severity
	sb.WriteString("### Vulnerabilities\n\n")
	currentSeverity := ""
	for _, cve := range report.CVEs {
		if cve.Severity != currentSeverity {
			if currentSeverity != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(cve.Severity)))
			sb.WriteString("| CVE ID | Severity |\n")
			sb.WriteString("|---------|----------|\n")
			currentSeverity = cve.Severity
		}
		sb.WriteString(fmt.Sprintf("| %s | %s |\n", cve.ID, cve.Severity))
	}

	return sb.String()
}
