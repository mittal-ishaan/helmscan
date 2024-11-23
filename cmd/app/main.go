package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/helmscan"
	"github.com/cliffcolvin/image-comparison/internal/imageScan"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

func init() {
	// Ensure the logs directory exists
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		panic("Failed to create log directory: " + err.Error())
	}

	// Create the log file
	logFile, err := os.OpenFile(filepath.Join(logDir, "helmscan.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("Failed to open log file: " + err.Error())
	}

	// Create a custom encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Create a custom core that writes to the file
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(logFile),
		zap.InfoLevel,
	)

	// Create a logger with the custom core
	zapLogger := zap.New(core)
	defer zapLogger.Sync()

	// Create a sugared logger
	logger = zapLogger.Sugar()

	logger.Info("Application started")

	// Check Trivy installation
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

	comparison := helmscan.CompareHelmCharts(scannedChart1, scannedChart2)
	report := helmscan.GenerateReport(comparison)

	// Print to console
	//fmt.Println(report)

	// Save to file
	err = helmscan.SaveReportToFile(report, "working-files/helm_comparison_report.md")
	if err != nil {
		log.Fatalf("Error saving report: %v", err)
	}

}

func compareImages(imageURL1, imageURL2 string, saveReport bool) {
	if imageURL1 == "" || imageURL2 == "" {
		fmt.Print("Enter the first image URL: ")
		imageURL1 = getUserInput()
		fmt.Print("Enter the second image URL: ")
		imageURL2 = getUserInput()
	}

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
	err = imageScan.PrintComparisonReport(report, saveReport)
	if err != nil {
		logger.Errorf("Error printing comparison report: %v", err)
		return
	}

}

func ensureWorkingFilesDir() error {
	return os.MkdirAll("working-files", os.ModePerm)
}
