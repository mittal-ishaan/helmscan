# helmscan
Docker Image and Helm Chart CVE comparison tool

This tool allows you to scan and compare Docker images or Helm charts and analyze their CVE (Common Vulnerabilities and Exposures) reports.

## Usage

There are three main ways to use this tool:

1. Command-line arguments
2. Interactive menu system
3. Single artifact scanning

### 1. Command-line arguments

You can run the tool with command-line arguments to compare two artifacts:

```
./image-comparison --compare [--report] [--json] <artifact1> <artifact2>
```

Flags:
- `--compare`: Enable comparison mode
- `--report`: Generate a Markdown report file (optional)
- `--json`: Generate a JSON report file (optional)
- `<artifact1>`: The URL of the "before" image or Helm chart reference
- `<artifact2>`: The URL of the "after" image or Helm chart reference

Examples:
```
# Compare Docker images and generate both JSON and Markdown reports
./image-comparison --compare --report --json docker.io/library/ubuntu:20.04 docker.io/library/ubuntu:22.04

# Compare Helm charts with only JSON output
./image-comparison --compare --json myrepo/mychart@1.0.0 myrepo/mychart@2.0.0
```

### 2. Interactive menu system

To use the interactive menu system, simply run the executable without any arguments:

```
./image-comparison
```

Follow the on-screen prompts to:
1. Scan a single image or Helm chart
2. Compare two images or Helm charts
3. Exit

### 3. Single artifact scanning

To scan a single artifact, provide its reference as an argument:

```
./image-comparison <artifact_reference>
```

Example:
```
# Scan a Docker image
./image-comparison docker.io/library/ubuntu:22.04

# Scan a Helm chart
./image-comparison myrepo/mychart@1.0.0
```

## Output

The tool will provide information about:

- CVE severity levels and counts
- Added CVEs: New vulnerabilities in the second artifact
- Removed CVEs: Vulnerabilities that were present in the first artifact but addressed in the second
- Unchanged CVEs: Vulnerabilities present in both artifacts

When using the `--report` flag, the output will be saved to the `working-files` directory.

## Note

- Make sure you have the necessary permissions to pull the Docker images or access the Helm charts you want to analyze
- For Helm charts, use the format `repo/chart@version`
- The tool requires Trivy to be installed and accessible in your PATH
