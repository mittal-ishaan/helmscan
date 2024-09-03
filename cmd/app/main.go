package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/helmscan"
	"github.com/cliffcolvin/image-comparison/internal/imageScan"

	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	zapLogger, _ := zap.NewProduction()
	defer zapLogger.Sync()
	logger = zapLogger.Sugar()

	if err := imageScan.CheckTrivyInstallation(); err != nil {
		logger.Fatalf("Trivy installation check failed: %v", err)
	}
}

func main() {
	// Ensure the working-files directory exists
	if err := ensureWorkingFilesDir(); err != nil {
		logger.Fatalf("Failed to create working-files directory: %v", err)
	}

	compareFlag := flag.Bool("compare", false, "Compare two images or Helm charts")
	reportFlag := flag.Bool("report", false, "Save the report to a file")
	flag.Parse()
	args := flag.Args()

	if *compareFlag {
		if len(args) != 2 {
			logger.Fatalf("For comparison, please provide exactly two image URLs or Helm chart references. Got: %v", args)
		}
		compareArtifacts(args[0], args[1], *reportFlag)
	} else if len(args) == 1 {
		scanSingleArtifact(args[0])
	} else if len(args) == 0 {
		runInteractiveMenu()
	} else {
		logger.Fatal("Invalid number of arguments. Please provide one artifact reference for scanning or use --compare with two references")
	}
}

func runInteractiveMenu() {
	for {
		printMenu()
		choice := getUserInput()

		switch choice {
		case "1":
			scanArtifact()
		case "2":
			compareArtifacts("", "", true)
		case "3":
			logger.Info("Exiting the program. Goodbye!")
			return
		default:
			logger.Warn("Invalid option. Please try again.")
		}
	}
}

func printMenu() {
	fmt.Println("\n--- Artifact Security Scanner Menu ---")
	fmt.Println("1. Scan a single image or Helm chart")
	fmt.Println("2. Compare two images or Helm charts")
	fmt.Println("3. Exit")
	fmt.Print("Enter your choice (1-3): ")
}

func getUserInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func scanSingleArtifact(artifactRef string) {
	if isHelmChart(artifactRef) {
		scanSingleHelmChart(artifactRef)
	} else {
		scanSingleImage(artifactRef)
	}
}

func scanArtifact() {
	fmt.Print("Enter the image URL or Helm chart reference to scan: ")
	artifactRef := getUserInput()
	scanSingleArtifact(artifactRef)
}

func compareArtifacts(ref1, ref2 string, saveReport bool) {
	if ref1 == "" || ref2 == "" {
		fmt.Print("Enter the first image URL or Helm chart reference: ")
		ref1 = getUserInput()
		fmt.Print("Enter the second image URL or Helm chart reference: ")
		ref2 = getUserInput()
	}

	logger.Infof("Comparing artifacts: %s and %s", ref1, ref2)

	if isHelmChart(ref1) && isHelmChart(ref2) {
		compareHelmCharts(ref1, ref2, saveReport)
	} else if !isHelmChart(ref1) && !isHelmChart(ref2) {
		compareImages(ref1, ref2, saveReport)
	} else {
		logger.Fatal("Cannot compare a Helm chart with a Docker image. Please provide two Helm charts or two Docker images.")
	}
}

func isHelmChart(ref string) bool {
	// This is a simple heuristic. You might want to improve this logic.
	return strings.Contains(ref, "/") && strings.Contains(ref, "@")
}

func scanSingleImage(imageURL string) {
	logger.Infof("Scanning image: %s", imageURL)
	_, err := imageScan.ScanImage(imageURL)
	if err != nil {
		logger.Errorf("Error scanning image: %v", err)
		return
	}
	//fmt.Println(result)
}

func scanSingleHelmChart(chartRef string) {
	logger.Infof("Scanning Helm chart: %s", chartRef)
	parts := strings.Split(chartRef, "@")
	if len(parts) != 2 {
		logger.Fatalf("Invalid Helm chart reference. Expected format: repo/chart@version")
	}
	_, err := helmscan.Scan(chartRef)
	if err != nil {
		logger.Errorf("Error scanning Helm chart: %v", err)
		return
	}
	//fmt.Println(helmscan.GenerateHelmComparisonReport(result))
}

func compareHelmCharts(chartRef1, chartRef2 string, saveReport bool) {
	parts1 := strings.Split(chartRef1, "@")
	parts2 := strings.Split(chartRef2, "@")
	if len(parts1) != 2 || len(parts2) != 2 {
		logger.Fatalf("Invalid Helm chart reference(s). Expected format: repo/chart@version")
	}

	logger.Infof("Comparing Helm charts: %s and %s", chartRef1, chartRef2)

	// Scan each chart
	scannedChart1, err := helmscan.Scan(chartRef1)
	if err != nil {
		logger.Errorf("Error scanning first Helm chart: %v", err)
		return
	}

	scannedChart2, err := helmscan.Scan(chartRef2)
	if err != nil {
		logger.Errorf("Error scanning second Helm chart: %v", err)
		return
	}

	// For now, just log the scanned charts
	logger.Infof("Scanned chart 1:\n%s", scannedChart1)
	logger.Infof("Scanned chart 2:\n%s", scannedChart2)

	// TODO: Implement comparison logic using scannedChart1 and scannedChart2

	// The rest of the function (report generation, saving, etc.) remains unchanged
	// ...
}

func compareImages(imageURL1, imageURL2 string, saveReport bool) {
	if imageURL1 == "" || imageURL2 == "" {
		fmt.Print("Enter the first image URL: ")
		imageURL1 = getUserInput()
		fmt.Print("Enter the second image URL: ")
		imageURL2 = getUserInput()
	}
	var sb strings.Builder
	sb.WriteString("## Vulnerability Comparison Report\n")
	sb.WriteString(fmt.Sprintf("### Comparing images: %s and %s\n", imageURL1, imageURL2))

	// Scan both images
	scan1, err := imageScan.ScanImage(imageURL1)
	if err != nil {
		logger.Errorf("Error scanning first image: %v", err)
		return
	}

	scan2, err := imageScan.ScanImage(imageURL2)
	if err != nil {
		logger.Errorf("Error scanning second image: %v", err)
		return
	}

	// Compare the scans
	report := imageScan.CompareScans(scan1, scan2)

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
		filename := generateFilename(imageURL1, imageURL2)
		err := saveReportToFile(sb.String(), filename)
		if err != nil {
			logger.Errorf("Error saving report to file: %v", err)
		}
	}

	fmt.Println(sb.String())
}

func formatVulnerabilityCountsTable(counts imageScan.SeverityCounts) string {
	return fmt.Sprintf(`| Severity | Count |
|----------|-------|
| Critical | %d    |
| High     | %d    |
| Medium   | %d    |
| Low      | %d    |
`, counts.Critical, counts.High, counts.Medium, counts.Low)
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
	filename := fmt.Sprintf("%s-%s_%s-%s", name1, tag1, name2, tag2)
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

func ensureWorkingFilesDir() error {
	return os.MkdirAll("working-files", os.ModePerm)
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
