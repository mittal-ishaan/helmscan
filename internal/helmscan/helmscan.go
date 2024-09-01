package helmscan

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/imageScan"
	"gopkg.in/yaml.v3"
)

type HelmComparison struct {
	Before          HelmChart
	After           HelmChart
	AddedImages     []*ContainerImage
	RemovedImages   []*ContainerImage
	ChangedImages   []*ContainerImage
	UnchangedImages []*ContainerImage
	RemovedCVEs     []imageScan.Vulnerability
	AddedCVEs       []imageScan.Vulnerability
}

// HelmChart represents a Helm chart with its version
type HelmChart struct {
	Name           string
	Version        string
	HelmRepo       string
	ContainsImages []*ContainerImage
}

type ContainerImage struct {
	Repository                    string
	Tag                           string
	ImageName                     string
	ScanResult                    imageScan.ScanResult
	VulnerabilityCountsBySeverity imageScan.SeverityCounts
	Vulnerabilities               []imageScan.Vulnerability
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
	//fmt.Printf("Comparing Helm charts: %s@%s vs %s@%s\n", before.Name, before.Version, after.Name, after.Version)

	beforeImages, err := extractImagesFromChart(before)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error extracting images from 'before' chart: %w", err)
	}

	afterImages, err := extractImagesFromChart(after)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error extracting images from 'after' chart: %w", err)
	}

	fmt.Printf("Extracted images. Before: %d, After: %d\n", len(beforeImages), len(afterImages))

	added, removed, changed, common, changedMap, _, afterMap, repoBeforeMap, repoAfterMap := compareImageLists(beforeImages, afterImages)

	addedReports, err := generateImageReports(added)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error generating reports for added images: %w", err)
	}

	removedReports, err := generateImageReports(removed)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error generating reports for removed images: %w", err)
	}

	changedReports, unchangedReports, err := compareCommonImages(common)
	if err != nil {
		return ComparisonResult{}, fmt.Errorf("error comparing common images: %w", err)
	}

	// Generate reports for changed images
	for _, img := range changed {
		beforeImg := fmt.Sprintf("%s/%s:%s", repoBeforeMap[img], img, changedMap[img])
		afterImg := fmt.Sprintf("%s/%s:%s", repoAfterMap[img], img, afterMap[img])
		// this trim is a hack until i can figure out why ai screwed this up lol
		beforeScan, err := imageScan.ScanImage(strings.Trim(strings.Trim(strings.Trim(beforeImg, "/"), ":"), " "))
		if err != nil {
			return ComparisonResult{}, fmt.Errorf("error scanning before image: %w", err)
		}
		afterScan, err := imageScan.ScanImage(strings.Trim(strings.Trim(strings.Trim(afterImg, "/"), ":"), " "))
		if err != nil {
			return ComparisonResult{}, fmt.Errorf("error scanning after image: %w", err)
		}
		fmt.Printf("beforeScan: %v\n", beforeScan)
		fmt.Printf("afterScan: %v\n", afterScan)
		beforeReport := parseImageScanResult(beforeScan)
		afterReport := parseImageScanResult(afterScan)

		diff := imageScan.CompareScans(beforeScan, afterScan)
		changedReports = append(changedReports, ImageComparison{
			Image:        afterImg,
			BeforeReport: beforeReport,
			AfterReport:  afterReport,
			Diff:         *diff,
		})
	}

	return ComparisonResult{
		Before:          before,
		After:           after,
		AddedImages:     addedReports,
		RemovedImages:   removedReports,
		ChangedImages:   changedReports,
		UnchangedImages: unchangedReports,
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
			Critical: scanResult.Vulnerabilities.Critical,
			High:     scanResult.Vulnerabilities.High,
			Medium:   scanResult.Vulnerabilities.Medium,
			Low:      scanResult.Vulnerabilities.Low,
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
		if len(diff.RemovedByLevel) == 0 && len(diff.AddedByLevel) == 0 {
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
	//fmt.Printf("Helm repo update output:\n%s\n", string(output))

	// Run helm template
	cmd = exec.Command("helm", "template", chart.Name, "--version", chart.Version)
	fmt.Printf("Running command: %s\n", cmd.String())
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running helm command: %v\n", err)
		fmt.Printf("Command output:\n%s\n", string(output))
		return nil, fmt.Errorf("error running helm template: %w", err)
	}

	//fmt.Printf("Helm command output length: %d bytes\n", len(output))

	// Write output to a file in the working-files/ directory for debugging
	filename := fmt.Sprintf("working-files/%s_%s_helm_output.yaml", strings.ReplaceAll(chart.Name, "/", "_"), chart.Version)
	err = os.WriteFile(filename, output, 0644)
	if err != nil {
		fmt.Printf("Error writing output to file: %v\n", err)
	} else {
		fmt.Printf("Helm template output written to %s\n", filename)
		fileInfo, _ := os.Stat(filename)
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
func compareImageLists(before, after []string) (added, removed, changed, common []string, changedMap, beforeMap, afterMap, repoBeforeMap, repoAfterMap map[string]string) {
	beforeMap = make(map[string]string)
	afterMap = make(map[string]string)
	changedMap = make(map[string]string)
	repoBeforeMap = make(map[string]string)
	repoAfterMap = make(map[string]string)

	for _, img := range before {
		repository, base, tag := splitImageName(img)
		beforeMap[base] = tag
		repoBeforeMap[base] = repository
	}

	for _, img := range after {
		repository, base, tag := splitImageName(img)
		afterMap[base] = tag
		repoAfterMap[base] = repository
	}

	for imageName, afterTag := range afterMap {
		if _, exists := beforeMap[imageName]; !exists {
			added = append(added, fmt.Sprintf("%s/%s:%s", repoAfterMap[imageName], imageName, afterTag))
			continue
		}
		if beforeTag, exists := beforeMap[imageName]; exists && beforeTag != afterTag {
			changed = append(changed, fmt.Sprintf("%s/%s:%s", repoAfterMap[imageName], imageName, afterTag))
			changedMap[imageName] = beforeTag
		} else {
			common = append(common, fmt.Sprintf("%s/%s:%s", repoAfterMap[imageName], imageName, afterTag))
		}

	}

	for imageName, beforeTag := range beforeMap {
		if _, exists := afterMap[imageName]; !exists {
			removed = append(removed, fmt.Sprintf("%s/%s:%s", repoBeforeMap[imageName], imageName, beforeTag))
		}
	}

	return
}

func splitImageName(image string) (repository, base, tag string) {
	// Split the image string into repository/image and tag
	parts := strings.Split(image, ":")
	if len(parts) > 1 {
		tag = parts[1]
	} else {
		tag = "latest"
	}

	// Split the repository/image part into repository and base image
	repoParts := strings.Split(parts[0], "/")
	base = repoParts[len(repoParts)-1]
	if len(repoParts) > 1 {
		repository = strings.Join(repoParts[:len(repoParts)-1], "/")
	} else {
		repository = "docker.io"
	}

	return
}

// GenerateHelmComparisonReport generates a report for the comparison of two Helm chart versions
func GenerateHelmComparisonReport(result ComparisonResult) string {
	var report strings.Builder

	report.WriteString("# Helm Chart Comparison Report\n")
	report.WriteString(fmt.Sprintf("**Before:** %s@%s\n", result.Before.Name, result.Before.Version))
	report.WriteString(fmt.Sprintf("**After:** %s@%s\n", result.After.Name, result.After.Version))

	// Add summary for each Helm chart
	report.WriteString(fmt.Sprintf("\n## Summary for Before Helm Chart (%s@%s):\n", result.Before.Name, result.Before.Version))
	beforeLow, beforeMedium, beforeHigh, beforeCritical := 0, 0, 0, 0
	beforeImages := len(result.RemovedImages) + len(result.ChangedImages) + len(result.UnchangedImages)
	for _, imageReport := range result.RemovedImages {
		beforeLow += imageReport.Vulnerabilities.Low
		beforeMedium += imageReport.Vulnerabilities.Medium
		beforeHigh += imageReport.Vulnerabilities.High
		beforeCritical += imageReport.Vulnerabilities.Critical
	}
	report.WriteString(fmt.Sprintf("**Images:** %d\n", beforeImages))
	report.WriteString(fmt.Sprintf("**Critical:** %d\n", beforeCritical))
	report.WriteString(fmt.Sprintf("**High:** %d\n", beforeHigh))
	report.WriteString(fmt.Sprintf("**Medium:** %d\n", beforeMedium))
	report.WriteString(fmt.Sprintf("**Low:** %d\n", beforeLow))

	report.WriteString(fmt.Sprintf("\n## Summary for After Helm Chart (%s@%s):\n", result.After.Name, result.After.Version))
	afterLow, afterMedium, afterHigh, afterCritical := 0, 0, 0, 0
	afterImages := len(result.AddedImages) + len(result.ChangedImages) + len(result.UnchangedImages)
	for _, imageReport := range result.AddedImages {
		afterLow += imageReport.Vulnerabilities.Low
		afterMedium += imageReport.Vulnerabilities.Medium
		afterHigh += imageReport.Vulnerabilities.High
		afterCritical += imageReport.Vulnerabilities.Critical
	}
	report.WriteString(fmt.Sprintf("**Images:** %d\n", afterImages))
	report.WriteString(fmt.Sprintf("**Critical:** %d\n", afterCritical))
	report.WriteString(fmt.Sprintf("**High:** %d\n", afterHigh))
	report.WriteString(fmt.Sprintf("**Medium:** %d\n", afterMedium))
	report.WriteString(fmt.Sprintf("**Low:** %d\n", afterLow))

	// Add details for added, removed, changed, and unchanged images
	report.WriteString("\n## Added Images:\n")
	for _, image := range result.AddedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\n## Removed Images:\n")
	for _, image := range result.RemovedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\n## Changed Images:\n")
	for _, image := range result.ChangedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	report.WriteString("\n## Unchanged Images:\n")
	for _, image := range result.UnchangedImages {
		report.WriteString(fmt.Sprintf("- %s\n", image.Image))
	}

	fmt.Printf("\n\n")

	// List all CVEs by severity removed from the right that existed in the left
	report.WriteString("\n## Removed CVEs by Severity:\n")
	removedCVEs := make(map[string]map[string][]string)
	for _, imageComparison := range result.ChangedImages {
		fmt.Printf("Image: %s\n", imageComparison.Image)
		fmt.Printf("Diff: %v\n", imageComparison.Diff)
		for severity, cves := range imageComparison.Diff.RemovedByLevel {
			fmt.Printf("Severity: %s\n", severity)
			fmt.Printf("CVEs: %v\n", cves)
			if _, exists := removedCVEs[severity]; !exists {
				removedCVEs[severity] = make(map[string][]string)
			}
			for _, cve := range cves {
				removedCVEs[severity][cve] = append(removedCVEs[severity][cve], imageComparison.Image)
			}
		}
	}

	// Create a markdown table for removed CVEs
	report.WriteString("\n| CVE Name | Severity | Images |\n")
	report.WriteString("|----------|----------|--------|\n")
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if cves, ok := removedCVEs[severity]; ok {
			for cve, images := range cves {
				report.WriteString(fmt.Sprintf("| %s | %s | %s |\n", cve, strings.Title(severity), strings.Join(images, ", ")))
			}
		}
	}

	fmt.Printf("\n\n")

	return report.String()
}

// ... (additional helper functions as needed)
