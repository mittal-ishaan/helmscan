# image-comparison
Docker Image CVE comparison tool

This tool allows you to compare two Docker images and analyze the differences in their CVE (Common Vulnerabilities and Exposures) reports.

## Usage

There are two ways to use this tool:

1. Command-line arguments
2. Interactive menu system

### 1. Command-line arguments

You can run the tool directly with command-line arguments:

```
./image-comparison <image1_url> <image2_url>
```

- `<image1_url>`: The URL of the "before" image (Image 1)
- `<image2_url>`: The URL of the "after" image (Image 2)

Example:
```
./image-comparison docker.io/library/ubuntu:20.04 docker.io/library/ubuntu:22.04
```

### 2. Interactive menu system

To use the interactive menu system, simply run the executable without any arguments:

```
./image-comparison
```

Follow the on-screen prompts to enter the URLs for Image 1 (before) and Image 2 (after).

## Output

The tool will compare the two images and provide information about:

- Removed CVEs: Vulnerabilities that were present in Image 1 but have been addressed in Image 2
- CVE severity levels
- Overall security improvement

## Note

Make sure you have the necessary permissions to pull the Docker images you want to compare. The tool focuses on identifying resolved vulnerabilities between the two image versions.
