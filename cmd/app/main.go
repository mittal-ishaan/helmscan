package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	chart := helmscan.HelmChart{Name: parts[0], Version: parts[1]}
	_, err := helmscan.CompareHelmCharts(chart, chart)
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

	chart1 := helmscan.HelmChart{Name: parts1[0], Version: parts1[1]}
	chart2 := helmscan.HelmChart{Name: parts2[0], Version: parts2[1]}

	logger.Infof("Comparing Helm charts: %s and %s", chartRef1, chartRef2)
	result, err := helmscan.CompareHelmCharts(chart1, chart2)
	if err != nil {
		logger.Errorf("Error comparing Helm charts: %v", err)
		fmt.Printf("Detailed error: %+v\n", err)
		return
	}

	// Generate the report
	report := helmscan.GenerateHelmComparisonReport(result)

	// Print the report
	//fmt.Println(report)

	// Save the report if requested
	if saveReport {
		filename := generateFilename(chartRef1, chartRef2)
		filepath := filepath.Join("working-files", filename)
		err := saveReportToFile(report, filepath)
		if err != nil {
			logger.Errorf("Failed to save report: %v", err)
		} else {
			logger.Infof("Report saved to %s", filepath)
		}
	}
}

func compareImages(imageURL1, imageURL2 string, saveReport bool) {
	if imageURL1 == "" || imageURL2 == "" {
		fmt.Print("Enter the first image URL: ")
		imageURL1 = getUserInput()
		fmt.Print("Enter the second image URL: ")
		imageURL2 = getUserInput()
	}

	logger.Infof("Comparing images: %s and %s", imageURL1, imageURL2)

	// Scan both images
	scan1, err := imageScan.ScanImage(imageURL1)
	if err != nil {
		logger.Errorf("Error scanning first image: %v", err)
		return
	}
	logger.Infof("Scan 1 completed")

	scan2, err := imageScan.ScanImage(imageURL2)
	if err != nil {
		logger.Errorf("Error scanning second image: %v", err)
		return
	}
	logger.Infof("Scan 2 completed")

	// Compare the scans
	result := imageScan.CompareScans(scan1, scan2)
	logger.Infof("Comparison completed")

	// Generate the report
	report := generateReport(result)

	// Print the report
	fmt.Println(report)

	// Save the report if requested
	if saveReport {
		filename := generateFilename(imageURL1, imageURL2)
		filepath := filepath.Join("working-files", filename)
		err := saveReportToFile(report, filepath)
		if err != nil {
			logger.Errorf("Failed to save report: %v", err)
		} else {
			logger.Infof("Report saved to %s", filepath)
		}
	}
}

func generateReport(report *imageScan.VulnerabilityReport) string {
	var builder strings.Builder

	builder.WriteString("Results:\n")
	builder.WriteString("-----------\n")

	builder.WriteString(fmt.Sprintf("Total CVEs:\n"))
	builder.WriteString(fmt.Sprintf("Image: %s (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		report.Image1Name,
		report.TotalCVEsImage1.Critical, report.TotalCVEsImage1.High, report.TotalCVEsImage1.Medium, report.TotalCVEsImage1.Low))
	builder.WriteString(fmt.Sprintf("Image: %s (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		report.Image2Name,
		report.TotalCVEsImage2.Critical, report.TotalCVEsImage2.High, report.TotalCVEsImage2.Medium, report.TotalCVEsImage2.Low))

	builder.WriteString(fmt.Sprintf("Removed CVEs: Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.RemovedCVEs.Critical, report.RemovedCVEs.High, report.RemovedCVEs.Medium, report.RemovedCVEs.Low))

	builder.WriteString(fmt.Sprintf("Added CVEs: Critical: %d, High: %d, Medium: %d, Low: %d\n\n",
		report.AddedCVEs.Critical, report.AddedCVEs.High, report.AddedCVEs.Medium, report.AddedCVEs.Low))

	builder.WriteString("Removed Vulnerabilities:\n")
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if vulns, ok := report.RemovedByLevel[severity]; ok && len(vulns) > 0 {
			builder.WriteString(fmt.Sprintf("  %s:\n", strings.Title(severity)))
			for _, vuln := range vulns {
				builder.WriteString(fmt.Sprintf("    %s\n", vuln))
			}
		}
	}

	builder.WriteString("\nAdded Vulnerabilities:\n")
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if vulns, ok := report.AddedByLevel[severity]; ok && len(vulns) > 0 {
			builder.WriteString(fmt.Sprintf("  %s:\n", strings.Title(severity)))
			for _, vuln := range vulns {
				builder.WriteString(fmt.Sprintf("    %s\n", vuln))
			}
		}
	}

	return builder.String()
}

func generateFilename(ref1, ref2 string) string {
	// Extract chart names and versions
	parts1 := strings.Split(ref1, "@")
	parts2 := strings.Split(ref2, "@")

	chartName1 := filepath.Base(parts1[0])
	version1 := parts1[1]
	chartName2 := filepath.Base(parts2[0])
	version2 := parts2[1]

	// Create a sanitized filename
	filename := fmt.Sprintf("%s@%s-%s@%s", chartName1, version1, chartName2, version2)
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, ".", "_")
	filename = strings.ReplaceAll(filename, " ", "_")
	filename = strings.ReplaceAll(filename, "(", "_")
	filename = strings.ReplaceAll(filename, ")", "_")
	filename = strings.ReplaceAll(filename, "-", "_")
	filename = fmt.Sprintf("%s.md", filename)

	return filename
}

func saveReportToFile(report, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(report)
	return err
}

func ensureWorkingFilesDir() error {
	return os.MkdirAll("working-files", os.ModePerm)
}
