package helmscan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/imageScan"
	"gopkg.in/yaml.v3"
)

// HelmChart represents a Helm chart with its version
type HelmChart struct {
	Name    string
	Version string
}

// ComparisonResult represents the comparison between two Helm chart versions
type ComparisonResult struct {
	Before          HelmChart
	After           HelmChart
	AddedImages     []ImageReport
	RemovedImages   []ImageReport
	ChangedImages   []ImageComparison
	UnchangedImages []ImageReport // New field for unchanged images
}

// ImageReport represents a summary of vulnerabilities for a single image
type ImageReport struct {
	Image           string
	Vulnerabilities imageScan.SeverityCounts
	VulnsByLevel    map[string][]string
}

// ImageComparison represents the comparison of a single image between versions
type ImageComparison struct {
	Image        string
	BeforeReport ImageReport
	AfterReport  ImageReport
	Diff         imageScan.VulnerabilityReport
}

// CompareHelmCharts compares two versions of a Helm chart and returns the comparison results
func CompareHelmCharts(before, after HelmChart) (ComparisonResult, error) {
	fmt.Printf("Comparing Helm charts: %s@%s vs %s@%s\n", before.Name, before.Version, after.Name, after.Version)

	beforeImages, err := extractImagesFromChart(before)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error extracting images from 'before' chart: %w", err)
	}

	afterImages, err := extractImagesFromChart(after)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error extracting images from 'after' chart: %w", err)
	}

	fmt.Printf("Extracted images. Before: %d, After: %d\n", len(beforeImages), len(afterImages))

	added, removed, common := compareImageLists(beforeImages, afterImages)

	addedReports, err := generateImageReports(added)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error generating reports for added images: %w", err)
	}

	removedReports, err := generateImageReports(removed)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error generating reports for removed images: %w", err)
	}

	changedImages, unchangedImages, err := compareCommonImages(common)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error comparing common images: %w", err)
	}

	return ComparisonResult{
		Before:          before,
		After:           after,
		AddedImages:     addedReports,
		RemovedImages:   removedReports,
		ChangedImages:   changedImages,
		UnchangedImages: unchangedImages, // Include unchanged images in the result
	}, nil
}

// generateImageReports generates a list of ImageReport for a given list of images
func generateImageReports(images []string) ([]ImageReport, error) {
	var reports []ImageReport
	for _, image := range images {
		scanResult, err := imageScan.ScanImage(image)
		if err != nil {
			return nil, err
		}
		report := parseImageScanResult(scanResult)
		reports = append(reports, report)
	}
	return reports, nil
}

// parseImageScanResult parses the image scan result and returns an ImageReport
func parseImageScanResult(scanResult imageScan.ScanResult) ImageReport {
	return ImageReport{
		Image: scanResult.Image,
		Vulnerabilities: imageScan.SeverityCounts{
			Low:      scanResult.Vulnerabilities.Low,
			Medium:   scanResult.Vulnerabilities.Medium,
			High:     scanResult.Vulnerabilities.High,
			Critical: scanResult.Vulnerabilities.Critical,
		},
		VulnsByLevel: scanResult.VulnsByLevel,
	}
}

// compareCommonImages compares common images between versions and returns changed and unchanged images
func compareCommonImages(images []string) ([]ImageComparison, []ImageReport, error) {
	var comparisons []ImageComparison
	var unchangedReports []ImageReport

	for _, image := range images {
		beforeScan, err := imageScan.ScanImage(image)
		if err != nil {
			return nil, nil, err
		}

		afterScan, err := imageScan.ScanImage(image)
		if err != nil {
			return nil, nil, err
		}

		beforeReport := parseImageScanResult(beforeScan)
		afterReport := parseImageScanResult(afterScan)

		diff := imageScan.CompareScans(beforeScan, afterScan)

		// Check if the diff is empty by comparing vulnerability counts
		if diff.RemovedCVEs.Low == 0 && diff.RemovedCVEs.Medium == 0 && diff.RemovedCVEs.High == 0 && diff.RemovedCVEs.Critical == 0 &&
			diff.AddedCVEs.Low == 0 && diff.AddedCVEs.Medium == 0 && diff.AddedCVEs.High == 0 && diff.AddedCVEs.Critical == 0 {
			// If there are no differences, add to unchanged reports
			unchangedReports = append(unchangedReports, afterReport)
		} else {
			// If there are differences, add to changed images
			comparisons = append(comparisons, ImageComparison{
				Image:        image,
				BeforeReport: beforeReport,
				AfterReport:  afterReport,
				Diff:         *diff,
			})
		}
	}
	return comparisons, unchangedReports, nil
}

// extractImagesFromChart extracts unique images from a Helm chart
func extractImagesFromChart(chart HelmChart) ([]string, error) {
	fmt.Printf("Extracting images from chart: %s@%s\n", chart.Name, chart.Version)

	// Run helm repo update
	cmd := exec.Command("helm", "repo", "update")
	fmt.Printf("Running command: %s\n", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running helm repo update: %v\n", err)
		fmt.Printf("Command output:\n%s\n", string(output))
		return nil, fmt.Errorf("error running helm repo update: %w", err)
	}
	fmt.Printf("Helm repo update output:\n%s\n", string(output))

	// Run helm template
	cmd = exec.Command("helm", "template", chart.Name, "--version", chart.Version)
	fmt.Printf("Running command: %s\n", cmd.String())
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running helm command: %v\n", err)
		fmt.Printf("Command output:\n%s\n", string(output))
		return nil, fmt.Errorf("error running helm template: %w", err)
	}

	fmt.Printf("Helm command output length: %d bytes\n", len(output))

	// Write output to a file for debugging
	filename := fmt.Sprintf("%s_%s_helm_output.yaml", strings.ReplaceAll(chart.Name, "/", "_"), chart.Version)
	currentDir, _ := os.Getwd()
	absFilename := filepath.Join(currentDir, filename)
	fmt.Printf("Attempting to write output to file: %s\n", absFilename)
	err = os.WriteFile(absFilename, output, 0644)
	if err != nil {
		fmt.Printf("Error writing output to file: %v\n", err)
	} else {
		fmt.Printf("Helm template output written to %s\n", absFilename)
		fileInfo, _ := os.Stat(absFilename)
		if fileInfo != nil {
			fmt.Printf("File size: %d bytes\n", fileInfo.Size())
		}
	}

	var images []string
	docs := strings.Split(string(output), "---")
	for _, doc := range docs {
		var node yaml.Node
		err := yaml.Unmarshal([]byte(doc), &node)
		if err != nil {
			fmt.Printf("Error parsing YAML: %v\n", err)
			continue
		}
		extractImagesFromNode(&node, &images)
	}

	fmt.Printf("Extracted images: %v\n", images)
	fmt.Printf("Number of unique images found: %d\n", len(uniqueStrings(images)))

	return uniqueStrings(images), nil
}

func extractImagesFromNode(node *yaml.Node, images *[]string) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if key.Value == "image" && value.Kind == yaml.ScalarNode {
				*images = append(*images, value.Value)
			} else {
				extractImagesFromNode(value, images)
			}
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			extractImagesFromNode(item, images)
		}
	case yaml.DocumentNode:
		for _, item := range node.Content {
			extractImagesFromNode(item, images)
		}
	}
}

// uniqueStrings returns a slice of unique strings
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// compareImageLists compares two lists of images and returns added, removed, and common images
func compareImageLists(before, after []string) (added, removed, common []string) {
	beforeMap := make(map[string]bool)
	afterMap := make(map[string]bool)

	for _, img := range before {
		beforeMap[img] = true
	}

	for _, img := range after {
		afterMap[img] = true
		if !beforeMap[img] {
			added = append(added, img)
		} else {
			common = append(common, img)
		}
	}

	for _, img := range before {
		if !afterMap[img] {
			removed = append(removed, img)
		}
	}

	return
}

// generateHelmComparisonReport generates a report for the comparison of two Helm chart versions
func generateHelmComparisonReport(result ComparisonResult) string {
	var report strings.Builder

	report.WriteString(fmt.Sprintf("Helm Chart Comparison Report\n"))
	report.WriteString(fmt.Sprintf("Before: %s@%s\n", result.Before.Name, result.Before.Version))
	report.WriteString(fmt.Sprintf("After: %s@%s\n", result.After.Name, result.After.Version))

	// Calculate overall summary
	totalImages := len(result.AddedImages) + len(result.RemovedImages) + len(result.ChangedImages) + len(result.UnchangedImages)
	totalLow, totalMedium, totalHigh, totalCritical := 0, 0, 0, 0

	for _, imageReport := range append(result.AddedImages, result.RemovedImages...) {
		totalLow += imageReport.Vulnerabilities.Low
		totalMedium += imageReport.Vulnerabilities.Medium
		totalHigh += imageReport.Vulnerabilities.High
		totalCritical += imageReport.Vulnerabilities.Critical
	}

	for _, imageComparison := range result.ChangedImages {
		totalLow += imageComparison.AfterReport.Vulnerabilities.Low
		totalMedium += imageComparison.AfterReport.Vulnerabilities.Medium
		totalHigh += imageComparison.AfterReport.Vulnerabilities.High
		totalCritical += imageComparison.AfterReport.Vulnerabilities.Critical
	}

	for _, imageReport := range result.UnchangedImages {
		totalLow += imageReport.Vulnerabilities.Low
		totalMedium += imageReport.Vulnerabilities.Medium
		totalHigh += imageReport.Vulnerabilities.High
		totalCritical += imageReport.Vulnerabilities.Critical
	}

	// Add overall summary to the report
	report.WriteString(fmt.Sprintf("\nOverall Summary:\n"))
	report.WriteString(fmt.Sprintf("Images: %d\n", totalImages))
	report.WriteString(fmt.Sprintf("Low: %d\n", totalLow))
	report.WriteString(fmt.Sprintf("Medium: %d\n", totalMedium))
	report.WriteString(fmt.Sprintf("High: %d\n", totalHigh))
	report.WriteString(fmt.Sprintf("Critical: %d\n", totalCritical))

	report.WriteString("\nAdded Images:\n")
	for _, image := range result.AddedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\nRemoved Images:\n")
	for _, image := range result.RemovedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\nChanged Images:\n")
	for _, image := range result.ChangedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\nUnchanged Images:\n")
	for _, image := range result.UnchangedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	return report.String()
}

// ... (additional helper functions as needed)
