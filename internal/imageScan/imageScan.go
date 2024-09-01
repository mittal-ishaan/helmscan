package imageScan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

const (
	trivyInstallURL = "https://aquasecurity.github.io/trivy/v0.54/getting-started/installation/"
)

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

type ScanResult struct {
	Image           string
	Vulnerabilities SeverityCounts
	VulnsByLevel    map[string][]string
}

func ScanImage(imageName string) (ScanResult, error) {
	// Create a safe filename from the image name
	safeFileName := strings.ReplaceAll(imageName, "/", "_")
	safeFileName = strings.ReplaceAll(safeFileName, ":", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "-", "_")
	safeFileName = strings.ReplaceAll(safeFileName, ".", "_")
	safeFileName = strings.ReplaceAll(safeFileName, " ", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "!", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "@", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "#", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "$", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "%", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "^", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "&", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "*", "_")
	safeFileName = strings.ReplaceAll(safeFileName, "(", "_")
	safeFileName = strings.ReplaceAll(safeFileName, ")", "_")
	outputFile := fmt.Sprintf("working-files/%s_trivy_output.json", safeFileName)

	//fmt.Printf("\noutputFile: %s\n\n", outputFile)

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

	fmt.Printf("Extracted vulnerabilities:\n%v\n\n", vulns)
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
		return fmt.Errorf("Trivy is not installed. Please install Trivy from: %s", trivyInstallURL)
	}

	// Get the latest Trivy version from GitHub
	latestVersion, err := getLatestTrivyVersion()
	if err != nil {
		return fmt.Errorf("Failed to get latest Trivy version: %v", err)
	}

	// Check Trivy version
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed to get Trivy version: %v", err)
	}

	version := strings.TrimSpace(strings.TrimPrefix(string(output), "Version: "))
	if compareVersions(version, latestVersion) < 0 {
		return fmt.Errorf("Trivy version %s is outdated. Please update to version %s or later from: %s", version, latestVersion, trivyInstallURL)
	}

	return nil
}

func getLatestTrivyVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/aquasecurity/trivy/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	return strings.TrimPrefix(release.TagName, "v"), nil
}

func compareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		if v1Parts[i] > v2Parts[i] {
			return 1
		}
		if v1Parts[i] < v2Parts[i] {
			return -1
		}
	}

	if len(v1Parts) > len(v2Parts) {
		return 1
	}
	if len(v1Parts) < len(v2Parts) {
		return -1
	}

	return 0
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
