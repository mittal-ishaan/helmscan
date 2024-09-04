package helmscan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cliffcolvin/image-comparison/internal/imageScan"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	yaml "sigs.k8s.io/yaml" // This line replaces both yaml imports
)

type HelmComparison struct {
	Before        HelmChart
	After         HelmChart
	AddedImages   map[string][]*ContainerImage
	RemovedImages map[string][]*ContainerImage
	ChangedImages map[string][]*ContainerImage
	RemovedCVEs   map[string][]imageScan.Vulnerability
	AddedCVEs     map[string][]imageScan.Vulnerability
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
	return fmt.Sprintf("Repository: %s, Tag: %s, ImageName: %s", ci.Repository, ci.Tag, ci.ImageName)
}

func Scan(chartRef string) (HelmChart, error) {
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

	// Parse the templated output
	var templatedYaml map[string]interface{}
	err = yaml.Unmarshal(output, &templatedYaml)
	if err != nil {
		return HelmChart{}, fmt.Errorf("error parsing templated YAML: %w", err)
	}

	// Extract images
	images := extractImages(templatedYaml)

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
		for _, img := range images {
			fmt.Printf("  - %s\n", img)
		}
	}

	var scanErrors []string

	// Scan each image
	for _, image := range images {
		fmt.Printf("Debug: Image details - Repository: '%s', ImageName: '%s', Tag: '%s'\n", image.Repository, image.ImageName, image.Tag)

		var fullImageName string
		if image.Repository != "" {
			fullImageName = fmt.Sprintf("%s/%s:%s", image.Repository, image.ImageName, image.Tag)
		} else {
			fullImageName = fmt.Sprintf("%s:%s", image.ImageName, image.Tag)
		}
		fmt.Printf("Debug: Full image name: '%s'\n", fullImageName)

		scanResult, err := imageScan.ScanImage(fullImageName)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("error scanning image %s: %v", fullImageName, err))
			continue
		}

		image.ScanResult = scanResult
		image.Vulnerabilities = make(map[string]imageScan.Vulnerability)
		for _, vuln := range scanResult.VulnList {
			image.Vulnerabilities[vuln.ID] = vuln
		}
		fmt.Printf("Image %s has %d vulnerabilities\n", fullImageName, len(image.Vulnerabilities))
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
		RemovedCVEs:   make(map[string][]imageScan.Vulnerability),
		AddedCVEs:     make(map[string][]imageScan.Vulnerability),
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
			comparison.RemovedImages[name] = []*ContainerImage{beforeImg}
			for _, vuln := range beforeImg.Vulnerabilities {
				comparison.RemovedCVEs[name] = append(comparison.RemovedCVEs[name], vuln)
			}
		}
	}

	for name, afterImg := range afterImages {
		if _, exists := beforeImages[name]; !exists {
			comparison.AddedImages[name] = []*ContainerImage{afterImg}
			for _, vuln := range afterImg.Vulnerabilities {
				comparison.AddedCVEs[name] = append(comparison.AddedCVEs[name], vuln)
			}
		}
	}

	return comparison
}

func compareImageVulnerabilities(before, after *ContainerImage, comparison *HelmComparison) {
	for id, vuln := range before.Vulnerabilities {
		if _, exists := after.Vulnerabilities[id]; !exists {
			comparison.RemovedCVEs[before.ImageName] = append(comparison.RemovedCVEs[before.ImageName], vuln)
		}
	}

	for id, vuln := range after.Vulnerabilities {
		if _, exists := before.Vulnerabilities[id]; !exists {
			comparison.AddedCVEs[after.ImageName] = append(comparison.AddedCVEs[after.ImageName], vuln)
		}
	}
}

func extractImages(data interface{}) []*ContainerImage {
	var images []*ContainerImage

	switch v := data.(type) {
	case map[string]interface{}:
		if img, ok := v["image"].(string); ok {
			images = append(images, parseImageString(img))
		}
		for _, value := range v {
			images = append(images, extractImages(value)...)
		}
	case []interface{}:
		for _, item := range v {
			images = append(images, extractImages(item)...)
		}
	}

	return images
}

func parseImageString(imageString string) *ContainerImage {
	parts := strings.Split(imageString, ":")
	var repository, imageName, tag string

	if len(parts) > 1 {
		tag = strings.Join(parts[1:], ":") // Join all parts after the first colon
		imageNameParts := strings.Split(parts[0], "/")
		if len(imageNameParts) > 1 {
			repository = strings.Join(imageNameParts[:len(imageNameParts)-1], "/")
			imageName = imageNameParts[len(imageNameParts)-1]
		} else {
			imageName = parts[0]
		}
	} else {
		imageNameParts := strings.Split(imageString, "/")
		if len(imageNameParts) > 1 {
			repository = strings.Join(imageNameParts[:len(imageNameParts)-1], "/")
			imageName = imageNameParts[len(imageNameParts)-1]
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
