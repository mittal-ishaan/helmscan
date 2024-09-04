package helmscan

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/imageScan"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
)

type HelmComparison struct {
	Before        HelmChart
	After         HelmChart
	AddedImages   map[string][]*ContainerImage
	RemovedImages map[string][]*ContainerImage
	ChangedImages map[string][]*ContainerImage
	RemovedCVEs   map[string]map[string]imageScan.Vulnerability
	AddedCVEs     map[string]map[string]imageScan.Vulnerability
}

type HelmChart struct {
	Name           string
	Version        string
	HelmRepo       string
	ContainsImages []*ContainerImage
}

func (hc HelmChart) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name: %s, Version: %s, HelmRepo: %s\n", hc.Name, hc.Version, hc.HelmRepo))
	sb.WriteString("ContainsImages:\n")
	for _, img := range hc.ContainsImages {
		sb.WriteString(fmt.Sprintf("  %s\n", img))
	}
	return sb.String()
}

type ContainerImage struct {
	Repository      string
	Tag             string
	ImageName       string
	ScanResult      imageScan.ScanResult
	Vulnerabilities map[string]imageScan.Vulnerability
}

func (ci ContainerImage) String() string {
	return fmt.Sprintf("Repository: %s\n, Tag: %s\n, ImageName: %s\n\n", ci.Repository, ci.Tag, ci.ImageName)
}

func Scan(chartRef string) (HelmChart, error) {
	// Add this at the beginning of the Scan function
	if err := os.MkdirAll("working-files", 0755); err != nil {
		return HelmChart{}, fmt.Errorf("error creating working-files directory: %w", err)
	}

	// Parse the chart reference
	repoName, chartName, version, err := parseChartReference(chartRef)
	if err != nil {
		return HelmChart{}, err
	}

	// Use local Helm to template the chart
	cmd := exec.Command("helm", "template", fmt.Sprintf("%s/%s", repoName, chartName), "--version", version)
	output, err := cmd.Output()
	if err != nil {
		return HelmChart{}, fmt.Errorf("error templating chart: %w", err)
	}

	// Save the output to a file
	outputFileName := fmt.Sprintf("working-files/%s_%s_%s_helm_output.yaml", repoName, chartName, version)
	err = os.WriteFile(outputFileName, output, 0644)
	if err != nil {
		return HelmChart{}, fmt.Errorf("error saving helm output to file: %w", err)
	}

	// Extract images using yq and jq
	images, err := extractImagesFromYAML(output)
	if err != nil {
		return HelmChart{}, fmt.Errorf("error extracting images: %w", err)
	}

	helmChart := HelmChart{
		Name:           chartName,
		Version:        version,
		HelmRepo:       repoName,
		ContainsImages: images,
	}

	if len(images) == 0 {
		fmt.Printf("Warning: No images found in chart %s\n", chartRef)
	} else {
		fmt.Printf("Found %d images in chart %s:\n", len(images), chartRef)
	}

	var scanErrors []string
	for _, img := range images {
		scanResult, err := imageScan.ScanImage(fmt.Sprintf("%s/%s:%s", img.Repository, img.ImageName, img.Tag))
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("error scanning image %s: %v", img.ImageName, err))
		} else {
			img.ScanResult = scanResult
		}
	}

	if len(scanErrors) > 0 {
		return helmChart, fmt.Errorf("errors occurred during image scanning:\n%s", strings.Join(scanErrors, "\n"))
	}

	return helmChart, nil
}

func CompareHelmCharts(before, after HelmChart) HelmComparison {
	comparison := HelmComparison{
		Before:        before,
		After:         after,
		AddedImages:   make(map[string][]*ContainerImage),
		RemovedImages: make(map[string][]*ContainerImage),
		ChangedImages: make(map[string][]*ContainerImage),
		RemovedCVEs:   make(map[string]map[string]imageScan.Vulnerability),
		AddedCVEs:     make(map[string]map[string]imageScan.Vulnerability),
	}

	beforeImages := make(map[string]*ContainerImage)
	afterImages := make(map[string]*ContainerImage)

	for _, img := range before.ContainsImages {
		beforeImages[img.ImageName] = img
	}

	for _, img := range after.ContainsImages {
		afterImages[img.ImageName] = img
	}

	for name, beforeImg := range beforeImages {
		if afterImg, exists := afterImages[name]; exists {
			if beforeImg.Tag != afterImg.Tag {
				comparison.ChangedImages[name] = []*ContainerImage{beforeImg, afterImg}
				compareImageVulnerabilities(beforeImg, afterImg, &comparison)
			}
		} else {
			for ID, vuln := range beforeImg.Vulnerabilities {
				if _, exists := comparison.RemovedCVEs[ID]; !exists {
					comparison.RemovedCVEs[ID] = make(map[string]imageScan.Vulnerability)
					comparison.RemovedCVEs[ID][name] = vuln
				} else {
					comparison.RemovedCVEs[ID][name] = vuln
				}
			}
		}
	}

	for name, afterImg := range afterImages {
		if _, exists := beforeImages[name]; !exists {
			for ID, vuln := range afterImg.Vulnerabilities {
				if _, exists := comparison.AddedCVEs[ID]; !exists {
					comparison.AddedCVEs[ID] = make(map[string]imageScan.Vulnerability)
					comparison.AddedCVEs[ID][name] = vuln
				} else {
					comparison.AddedCVEs[ID][name] = vuln
				}
			}
		}
	}

	return comparison
}

func compareImageVulnerabilities(before, after *ContainerImage, comparison *HelmComparison) {
	for id, vuln := range before.Vulnerabilities {
		if _, exists := after.Vulnerabilities[id]; !exists {
			if _, exists := comparison.RemovedCVEs[id]; !exists {
				comparison.RemovedCVEs[id] = make(map[string]imageScan.Vulnerability)
				comparison.RemovedCVEs[id][before.ImageName] = vuln
			} else {
				comparison.RemovedCVEs[id][before.ImageName] = vuln
			}
		}
	}

	for id, vuln := range after.Vulnerabilities {
		if _, exists := before.Vulnerabilities[id]; !exists {
			if _, exists := comparison.AddedCVEs[id]; !exists {
				comparison.AddedCVEs[id] = make(map[string]imageScan.Vulnerability)
				comparison.AddedCVEs[id][after.ImageName] = vuln
			} else {
				comparison.AddedCVEs[id][after.ImageName] = vuln
			}
		}
	}
}

func extractImagesFromYAML(yamlData []byte) ([]*ContainerImage, error) {
	// Use yq to convert YAML to JSON, then use jq to extract image values
	cmd := exec.Command("bash", "-c", `yq e -o json - | jq -r '.. | .image? | select(.)'`)
	cmd.Stdin = bytes.NewReader(yamlData)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error extracting images: %w", err)
	}

	// Split the output into lines
	imageStrings := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Create ContainerImage objects
	var images []*ContainerImage
	for _, imageString := range imageStrings {
		image := parseImageString(imageString)
		images = append(images, image)
	}

	return images, nil
}

func parseImageString(imageString string) *ContainerImage {
	parts := strings.Split(imageString, ":")
	var repository, imageName, tag string

	if len(parts) > 1 {
		tag = parts[len(parts)-1]
		repoAndImage := strings.Join(parts[:len(parts)-1], ":")
		repoParts := strings.Split(repoAndImage, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = repoAndImage
		}
	} else {
		repoParts := strings.Split(imageString, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = imageString
		}
		tag = "latest"
	}

	return &ContainerImage{
		Repository: repository,
		ImageName:  imageName,
		Tag:        tag,
	}
}

func parseChartReference(chartRef string) (string, string, string, error) {
	parts := strings.Split(chartRef, "/")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	repoAndChart := parts[1]
	repoParts := strings.Split(repoAndChart, "@")
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	return parts[0], repoParts[0], repoParts[1], nil
}

func downloadChart(repoName, chartName, version, destDir string) (string, error) {
	settings := cli.New()
	actionConfig := new(action.Configuration)
	client := action.NewInstall(actionConfig)
	client.DryRun = true
	client.ReleaseName = "test"
	client.Replace = true
	client.ClientOnly = true
	client.IncludeCRDs = false

	cp, err := client.ChartPathOptions.LocateChart(fmt.Sprintf("%s/%s", repoName, chartName), settings)
	if err != nil {
		return "", fmt.Errorf("error locating chart: %w", err)
	}

	chartPath := filepath.Join(destDir, filepath.Base(cp))
	err = os.Rename(cp, chartPath)
	if err != nil {
		return "", fmt.Errorf("error moving chart: %w", err)
	}

	return chartPath, nil
}

func GenerateReport(comparison HelmComparison) string {
	var sb strings.Builder

	sb.WriteString("# Helm Chart Comparison Report\n\n")

	// Images table
	sb.WriteString("## Images\n\n")
	sb.WriteString("| Image Name | Status | Before Repo | After Repo | Before Tag | After Tag |\n")
	sb.WriteString("|------------|--------|-------------|------------|------------|-----------|\n")

	var imageRows []string

	for name, images := range comparison.AddedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Added | - | %s | - | %s |", name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.RemovedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Removed | %s | - | %s | - |", name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.ChangedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Changed | %s | %s | %s | %s |", name, images[0].Repository, images[1].Repository, images[0].Tag, images[1].Tag))
	}

	sort.Strings(imageRows)
	sb.WriteString(strings.Join(imageRows, "\n"))
	sb.WriteString("\n\n")

	// Added CVEs table
	sb.WriteString("## Added CVEs\n\n")
	sb.WriteString("| CVE ID | Severity | Affected Images |\n")
	sb.WriteString("|--------|----------|------------------|\n")

	addedCVERows := generateCVERows(comparison.AddedCVEs)
	sb.WriteString(strings.Join(addedCVERows, "\n"))
	sb.WriteString("\n\n")

	// Removed CVEs table
	sb.WriteString("## Removed CVEs\n\n")
	sb.WriteString("| CVE ID | Severity | Affected Images |\n")
	sb.WriteString("|--------|----------|------------------|\n")

	removedCVERows := generateCVERows(comparison.RemovedCVEs)
	sb.WriteString(strings.Join(removedCVERows, "\n"))
	sb.WriteString("\n")

	return sb.String()
}

func generateCVERows(cves map[string]map[string]imageScan.Vulnerability) []string {
	var rows []string
	for cveID, imageVulns := range cves {
		var affectedImages []string
		var severity string

		for imageName, vuln := range imageVulns {
			affectedImages = append(affectedImages, imageName)
			severity = vuln.Severity // Assuming all instances of a CVE have the same severity
		}

		// Sort affected images for consistent output
		sort.Strings(affectedImages)

		// Join affected images with commas
		imagesStr := strings.Join(affectedImages, ", ")

		// Create the table row
		row := fmt.Sprintf("| %s | %s | %s |", cveID, severity, imagesStr)
		rows = append(rows, row)
	}

	// Sort rows by CVE ID for consistent output
	sort.Strings(rows)

	return rows
}

// Add this function to save the report to a file
func SaveReportToFile(report string, filename string) error {
	return os.WriteFile(filename, []byte(report), 0644)
}
