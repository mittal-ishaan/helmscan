package imageScan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/reports"
)

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

type ScanResult struct {
	Image           string
	Vulnerabilities SeverityCounts
	VulnsByLevel    map[string][]string
	VulnList        []Vulnerability
}

type ImageComparisonReport struct {
	Image1        ScanResult
	Image2        ScanResult
	RemovedCVEs   map[string][]Vulnerability
	AddedCVEs     map[string][]Vulnerability
	UnchangedCVEs map[string][]Vulnerability
}

type Vulnerability struct {
	ID       string
	Severity string
}

type SeverityCounts struct {
	Low      int
	Medium   int
	High     int
	Critical int
}

func ScanImage(imageName string) (ScanResult, error) {
	if strings.Contains(imageName, "alpine") {
		return ScanResult{}, nil
	}

	// Create a safe filename from the image name
	safeFileName := reports.CreateSafeFileName(imageName)
	outputFile := fmt.Sprintf("working-files/%s_trivy_output.json", safeFileName)

	cmd := exec.Command("trivy", "image",
		"-f", "json",
		"-o", outputFile,
		"--severity", "HIGH,MEDIUM,LOW,CRITICAL",
		"--pkg-types", "os,library",
		"--scanners", "vuln,secret,misconfig",
		imageName)

	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		return ScanResult{}, fmt.Errorf("error running command: %w\nOutput: %s", err, string(combinedOutput))
	}

	jsonData, err := os.ReadFile(outputFile)
	if err != nil {
		return ScanResult{}, fmt.Errorf("error reading %s: %w", outputFile, err)
	}

	vulns := extractVulnerabilities(string(jsonData))

	result := ScanResult{
		Image:           imageName,
		Vulnerabilities: countVulnerabilities(vulns),
		VulnsByLevel:    groupVulnerabilitiesByLevel(vulns),
		VulnList:        vulns,
	}

	return result, nil
}

func countVulnerabilities(vulns []Vulnerability) SeverityCounts {
	counts := SeverityCounts{}
	for _, vuln := range vulns {
		incrementSeverityCount(&counts, vuln.Severity)
	}
	return counts
}

func groupVulnerabilitiesByLevel(vulns []Vulnerability) map[string][]string {
	grouped := make(map[string][]string)
	for _, vuln := range vulns {
		grouped[vuln.Severity] = append(grouped[vuln.Severity], vuln.ID)
	}
	return grouped
}

func CompareScans(firstScan, secondScan ScanResult) *ImageComparisonReport {
	comparison := &ImageComparisonReport{
		Image1:        firstScan,
		Image2:        secondScan,
		RemovedCVEs:   make(map[string][]Vulnerability),
		AddedCVEs:     make(map[string][]Vulnerability),
		UnchangedCVEs: make(map[string][]Vulnerability),
	}

	// Create maps for easier lookup
	firstVulns := make(map[string]Vulnerability)
	for _, vuln := range firstScan.VulnList {
		firstVulns[vuln.ID] = vuln
	}

	secondVulns := make(map[string]Vulnerability)
	for _, vuln := range secondScan.VulnList {
		secondVulns[vuln.ID] = vuln
	}

	// Find removed and unchanged vulnerabilities
	for id, vuln := range firstVulns {
		if _, exists := secondVulns[id]; exists {
			comparison.UnchangedCVEs[vuln.Severity] = append(comparison.UnchangedCVEs[vuln.Severity], vuln)
		} else {
			comparison.RemovedCVEs[vuln.Severity] = append(comparison.RemovedCVEs[vuln.Severity], vuln)
		}
	}

	// Find added vulnerabilities
	for id, vuln := range secondVulns {
		if _, exists := firstVulns[id]; !exists {
			comparison.AddedCVEs[vuln.Severity] = append(comparison.AddedCVEs[vuln.Severity], vuln)
		}
	}

	return comparison
}

func extractVulnerabilities(scan string) []Vulnerability {
	var result struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	err := json.Unmarshal([]byte(scan), &result)
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return nil
	}

	var vulns []Vulnerability
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			vulns = append(vulns, Vulnerability{
				ID:       vuln.VulnerabilityID,
				Severity: strings.ToLower(vuln.Severity),
			})
		}
	}

	return vulns
}

func incrementSeverityCount(counts *SeverityCounts, severity string) {
	switch severity {
	case "low":
		counts.Low++
	case "medium":
		counts.Medium++
	case "high":
		counts.High++
	case "critical":
		counts.Critical++
	}
}

func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, v := range b {
		bMap[v] = true
	}

	var diff []string
	for _, v := range a {
		if !bMap[v] {
			diff = append(diff, v)
		}
	}
	return diff
}

func CheckTrivyInstallation() error {
	// Check if Trivy is installed
	_, err := exec.LookPath("trivy")
	if err != nil {
		return fmt.Errorf("Trivy is not installed. Please install Trivy and ensure it's in your PATH")
	}

	// Check Trivy version
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed to get Trivy version: %v", err)
	}

	version := strings.TrimSpace(strings.TrimPrefix(string(output), "Version: "))
	fmt.Printf("Trivy version %s is installed.\n", version)

	return nil
}

func calculateDifference(before, after map[string][]string) map[string][]Vulnerability {
	diff := make(map[string][]Vulnerability)

	for severity, vulns := range before {
		for _, vuln := range vulns {
			if !contains(after[severity], vuln) {
				diff[severity] = append(diff[severity], Vulnerability{
					ID:       vuln,
					Severity: severity,
				})
			}
		}
	}

	return diff
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func GenerateReport(comparison *ImageComparisonReport) string {
	var sb strings.Builder

	sb.WriteString("## Image Comparison Report\n")
	sb.WriteString(fmt.Sprintf("### Comparing images: %s and %s\n\n",
		comparison.Image1.Image, comparison.Image2.Image))

	// CVE by Severity section
	headers := []string{"Severity", "Count", "Prev Count", "Difference"}
	rows := generateSeverityRows(comparison) // helper function to generate rows
	sb.WriteString(reports.FormatSection("CVE by Severity",
		reports.FormatMarkdownTable(headers, rows)))

	// Unchanged CVEs section
	sb.WriteString("### Unchanged CVEs\n\n")
	if len(comparison.UnchangedCVEs) == 0 {
		sb.WriteString("No unchanged vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.UnchangedCVEs))
	}

	// Added CVEs section
	sb.WriteString("### Added CVEs\n\n")
	if len(comparison.AddedCVEs) == 0 {
		sb.WriteString("No new vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.AddedCVEs))
	}

	// Removed CVEs section
	sb.WriteString("### Removed CVEs\n\n")
	if len(comparison.RemovedCVEs) == 0 {
		sb.WriteString("No removed vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.RemovedCVEs))
	}

	return sb.String()
}

func formatVulnerabilitySection(vulns map[string][]Vulnerability) string {
	var sb strings.Builder

	if len(vulns) == 0 {
		return "No vulnerabilities found.\n\n"
	}

	// Sort severities
	severities := make([]string, 0, len(vulns))
	for severity := range vulns {
		severities = append(severities, severity)
	}
	sort.Slice(severities, func(i, j int) bool {
		return reports.SeverityValue(severities[i]) > reports.SeverityValue(severities[j])
	})

	for _, severity := range severities {
		if len(vulns[severity]) > 0 {
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(severity)))
			sb.WriteString("| CVE ID | Severity |\n")
			sb.WriteString("|---------|----------|\n")

			// Sort vulnerabilities by ID
			sort.Slice(vulns[severity], func(i, j int) bool {
				return vulns[severity][i].ID < vulns[severity][j].ID
			})

			for _, vuln := range vulns[severity] {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", vuln.ID, vuln.Severity))
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func generateSeverityRows(comparison *ImageComparisonReport) [][]string {
	severities := []string{"critical", "high", "medium", "low"}
	var rows [][]string

	// Count current and previous vulnerabilities by severity
	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	// Count previous vulnerabilities
	for _, vuln := range comparison.Image1.VulnList {
		prevCounts[vuln.Severity]++
	}

	// Count current vulnerabilities
	for _, vuln := range comparison.Image2.VulnList {
		currentCounts[vuln.Severity]++
	}

	// Generate table rows
	for _, severity := range severities {
		count := currentCounts[severity]
		prevCount := prevCounts[severity]
		difference := count - prevCount
		differenceStr := fmt.Sprintf("%+d", difference) // Use %+d to always show the sign

		rows = append(rows, []string{
			severity,
			fmt.Sprintf("%d", count),
			fmt.Sprintf("%d", prevCount),
			differenceStr,
		})
	}

	return rows
}
