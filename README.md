# README for SoftwareBuster 💥

## Overview

**SoftwareBuster** is a Python tool designed to scan websites for outdated JavaScript libraries. It resolves domain names, checks software versions, and identifies potential security vulnerabilities using Snyk's vulnerability database. The tool can process single URLs or a batch of URLs, providing detailed reports in markdown or color-coded formats.

## Features

- **Domain Resolution**: Resolves domains to their respective IP addresses.
- **JavaScript Library Detection**: Scans websites for known JavaScript libraries and checks their versions.
- **Vulnerability Detection**: Retrieves the latest version of npm packages and checks for associated CVEs (Common Vulnerabilities and Exposures) using Snyk.
- **Threaded Scanning**: Supports multithreading for faster results.
- **Formatted Output**: Provides results in a markdown table or a color-coded terminal table.

## Installation

### Prerequisites

- Python 3.x
- This tool was designed to be run on a **Mac**
- May need **GeckoDriver**: SoftwareBuster uses Selenium with Firefox. Download the latest version of [GeckoDriver](https://github.com/mozilla/geckodriver/releases) and ensure it's in your PATH.

### Setup

SoftwareBuster includes a setup script (`setup`) to automate the installation of dependencies and configuration. 

1. Clone the repository or download the script.
```bash
git clone https://github.com/JackMason1/SoftwareBuster
```
3. Run the setup script:

```bash
cd SoftwareBuster
chmod +x setup
./setup
```

This script will:
- Upgrade `pip`.
- Install required Python packages from `requirements.txt`.
- Move the `SoftwareBuster` executable to `/usr/local/bin` and make it executable.

### Manual Installation

Alternatively, you can manually install dependencies and configure the script:

```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Move SoftwareBuster to /usr/local/bin and make it executable
cp SoftwareBuster /usr/local/bin/
chmod +x /usr/local/bin/SoftwareBuster
```

## Usage

After installation, you can run SoftwareBuster directly from the terminal.

### Syntax

```bash
SoftwareBuster [OPTIONS]
```

### Options

- `--url` `<URL>`: Scan a single URL.
- `--file` `<filename>`: Provide a file containing a list of URLs to scan.
- `--timeout` `<seconds>`: Set the timeout for each request (default: 10 seconds).
- `--threads` `<num_threads>`: Set the number of threads for concurrent scanning (default: 4).
- `--delay` `<milliseconds>`: Set the delay between requests (default: 100 ms).
- `--cookie` `<cookie_string>`: Add a session cookie (optional).

### Example Commands

1. **Scan a Single URL**:
   ```bash
   SoftwareBuster --url https://example.com
   ```

2. **Scan Multiple URLs from a File**:
   ```bash
   SoftwareBuster --file urls.txt
   ```

3. **Scan with Session Cookie**:
   ```bash
   SoftwareBuster --url https://example.com --cookie "sessionid=abcd1234"
   ```

## Output

SoftwareBuster generates two types of outputs:

1. **Markdown Table**: A table in markdown format listing outdated software and their associated CVEs.
2. **Color-Coded Terminal Output**: A color-coded table showing software versions and severity of CVEs.

### Sample Markdown Table

```
| Host      | Port | Software Discovered | Version Found | Latest Version | CVE     |
|-----------|------|---------------------|---------------|----------------|---------|
| example.com | 443  | Lodash              | 4.17.15       | 4.17.21        | CVE-2020-1234 |
```

### Color-Coded Table Output
The terminal output will be color-coded, showing outdated libraries in red and displaying severity levels for CVEs using different colors.

## Uninstallation

To remove SoftwareBuster from your system, run the following commands:

```bash
rm /usr/local/bin/SoftwareBuster
pip3 uninstall -r requirements.txt
```

## Author

- **Jack Mason**

---

This README explains the basic usage and up of SoftwareBuster. For more detailed information on how the tool works, refer to the comments in the source code.
