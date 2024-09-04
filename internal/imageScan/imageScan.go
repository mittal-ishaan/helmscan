package imageScan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
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

func ScanImage(imageName string) (ScanResult, error) {
	if strings.Contains(imageName, "alpine") {
		return ScanResult{}, nil
	}

	// Create a safe filename from the image name
	safeFileName := createSafeFileName(imageName)
	outputFile := fmt.Sprintf("working-files/%s_trivy_output.json", safeFileName)

	cmd := exec.Command("trivy", "image",
		"-f", "json",
		"-o", outputFile,
		"--severity", "HIGH,MEDIUM,LOW,CRITICAL",
		"--vuln-type", "os,library",
		"--scanners", "vuln,secret,config",
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

func createSafeFileName(imageName string) string {
	unsafe := []string{"/", ":", "-", ".", " ", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")"}
	safeFileName := imageName
	for _, char := range unsafe {
		safeFileName = strings.ReplaceAll(safeFileName, char, "_")
	}
	return safeFileName
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

func CompareScans(firstScan, secondScan ScanResult) *VulnerabilityReport {
	report := &VulnerabilityReport{
		Image1Name:      firstScan.Image,
		Image2Name:      secondScan.Image,
		TotalCVEsImage1: firstScan.Vulnerabilities,
		TotalCVEsImage2: secondScan.Vulnerabilities,
		RemovedByLevel:  make(map[string][]string),
		AddedByLevel:    make(map[string][]string),
	}

	// Calculate removed and added vulnerabilities
	report.RemovedCVEs, report.RemovedByLevel = calculateDifference(firstScan.VulnsByLevel, secondScan.VulnsByLevel)
	report.AddedCVEs, report.AddedByLevel = calculateDifference(secondScan.VulnsByLevel, firstScan.VulnsByLevel)

	return report
}

type VulnerabilityReport struct {
	Image1Name      string
	Image2Name      string
	TotalCVEsImage1 SeverityCounts
	TotalCVEsImage2 SeverityCounts
	RemovedCVEs     SeverityCounts
	AddedCVEs       SeverityCounts
	RemovedByLevel  map[string][]string
	AddedByLevel    map[string][]string
}

type Vulnerability struct {
	ID       string
	Severity string
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

func containsVulnerability(vulns []Vulnerability, vuln Vulnerability) bool {
	for _, v := range vulns {
		if v.ID == vuln.ID {
			return true
		}
	}
	return false
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

type SeverityCounts struct {
	Low      int
	Medium   int
	High     int
	Critical int
}

func calculateDifference(before, after map[string][]string) (SeverityCounts, map[string][]string) {
	diff := make(map[string][]string)
	counts := SeverityCounts{}

	for severity, vulns := range before {
		for _, vuln := range vulns {
			if !contains(after[severity], vuln) {
				diff[severity] = append(diff[severity], vuln)
				incrementSeverityCount(&counts, severity)
			}
		}
	}

	return counts, diff
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func PrintComparisonReport(report *VulnerabilityReport, saveReport bool) error {
	// Create a report
	var sb strings.Builder
	sb.WriteString("## Vulnerability Comparison Report\n")
	sb.WriteString(fmt.Sprintf("### Comparing images: %s and %s\n", report.Image1Name, report.Image2Name))

	// Image 1 summary
	sb.WriteString(fmt.Sprintf("#### Image 1: %s\n", report.Image1Name))
	sb.WriteString(fmt.Sprintf("#### Total vulnerabilities: %d\n\n",
		report.TotalCVEsImage1.Critical+report.TotalCVEsImage1.High+
			report.TotalCVEsImage1.Medium+report.TotalCVEsImage1.Low))
	sb.WriteString(formatVulnerabilityCountsTable(report.TotalCVEsImage1))
	sb.WriteString("\n")

	// Image 2 summary
	sb.WriteString(fmt.Sprintf("#### Image 2: %s\n", report.Image2Name))
	sb.WriteString(fmt.Sprintf("#### Total vulnerabilities: %d\n\n",
		report.TotalCVEsImage2.Critical+report.TotalCVEsImage2.High+
			report.TotalCVEsImage2.Medium+report.TotalCVEsImage2.Low))
	sb.WriteString(formatVulnerabilityCountsTable(report.TotalCVEsImage2))
	sb.WriteString("\n")

	// Generate and print the report for added vulnerabilities
	sb.WriteString("### Added vulnerabilities:\n")
	sb.WriteString(printVulnerabilityReport(report.AddedByLevel))

	// Generate and print the report for removed vulnerabilities
	sb.WriteString("### Removed vulnerabilities:\n")
	sb.WriteString(printVulnerabilityReport(report.RemovedByLevel))

	if saveReport {
		filename := generateFilename(report.Image1Name, report.Image2Name)
		err := saveReportToFile(sb.String(), filename)
		if err != nil {
			errReturn := fmt.Errorf("error saving report to file: %v", err)
			return errReturn
		}
	}

	fmt.Println(sb.String())
	return nil
}

func formatVulnerabilityCountsTable(counts SeverityCounts) string {
	return fmt.Sprintf(`| Severity | Count |
|----------|-------|
| Critical | %d    |
| High     | %d    |
| Medium   | %d    |
| Low      | %d    |
`, counts.Critical, counts.High, counts.Medium, counts.Low)
}

func printVulnerabilityReport(vulnerabilities map[string][]string) string {
	var sb strings.Builder
	for severity, vulnIDs := range vulnerabilities {
		sb.WriteString(fmt.Sprintf("#### %s\n", severity))
		sb.WriteString("| VulnerabilityID |\n")
		sb.WriteString("| --------------- |\n")
		for _, id := range vulnIDs {
			sb.WriteString(fmt.Sprintf("| %s |\n", id))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func generateFilename(ref1, ref2 string) string {
	// Extract image names and tags
	getName := func(ref string) (string, string) {
		parts := strings.Split(ref, ":")
		name := strings.Split(parts[0], "/")
		tag := "latest"
		if len(parts) > 1 {
			tag = parts[1]
		}
		return name[len(name)-1], tag
	}

	name1, tag1 := getName(ref1)
	name2, tag2 := getName(ref2)

	// Create a sanitized filename
	filename := fmt.Sprintf("working-files/%s-%s_%s-%s", name1, tag1, name2, tag2)
	filename = sanitizeFilename(filename)
	filename = fmt.Sprintf("%s.md", filename)

	return filename
}

func sanitizeFilename(filename string) string {
	// Replace any character that isn't alphanumeric, underscore, or hyphen with an underscore
	reg := regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
	return reg.ReplaceAllString(filename, "_")
}

func saveReportToFile(content, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}
