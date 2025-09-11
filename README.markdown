# Web Vulnerability Scanner

*By elryan7*

A Python-based tool for scanning web applications for SQL Injection and Cross-Site Scripting (XSS) vulnerabilities. This tool supports mass scanning of multiple URLs, multithreading for efficiency, and generates both JSON and HTML reports for scan results.

## Features

- **SQL Injection Scanning**: Utilizes `sqlmap` to perform in-depth SQL injection testing with configurable risk and level settings.
- **XSS Testing**: Tests for XSS vulnerabilities using a predefined list of common payloads.
- **Multithreading**: Processes multiple URLs and parameters concurrently to improve performance.
- **Automated Parameter Extraction**: Optionally extracts form parameters from web pages using BeautifulSoup.
- **Configurable Settings**: Supports cookies, proxies, and thread counts via a JSON configuration file.
- **Reporting**: Generates JSON and HTML reports for easy analysis of vulnerabilities.
- **Logging**: Logs errors and scan activities to a `scan.log` file.

## Prerequisites

- Python 3.6 or higher
- `sqlmap` installed and accessible in your system's PATH
- Required Python libraries:
  - `requests`
  - `beautifulsoup4`
  - `argparse` (included in Python standard library)
  - `threading` (included in Python standard library)
  - `queue` (included in Python standard library)
  - `json` (included in Python standard library)
  - `logging` (included in Python standard library)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/elryan7/web-vulnerability-scanner.git
   cd web-vulnerability-scanner
   ```

2. Install the required Python libraries:

   ```bash
   pip install requests beautifulsoup4
   ```

3. Install `sqlmap`:

   - Follow the instructions at sqlmap GitHub to install `sqlmap`.
   - Ensure `sqlmap` is in your system's PATH.

4. Create a `config.json` file (see Configuration for details).

## Usage

Run the scanner with a file containing URLs to scan:

```bash
python3 scanner.py urls.txt --config config.json --report report.json --html-report report.html
```

### Arguments

- `input_file`: A text file containing URLs to scan (one per line).
- `--config`: Path to the JSON configuration file (default: `config.json`).
- `--report`: Output file for JSON report (optional).
- `--html-report`: Output file for HTML report (optional).

### Example

```bash
python3 scanner.py urls.txt --config config.json --report results.json --html-report results.html
```

### Input File Format (`urls.txt`)

```
http://example.com/login
http://example.com/register
```

## Configuration

Create a `config.json` file in the project directory with the following structure:

```json
{
  "cookies": "session=abc123; user=admin",
  "proxy": "http://proxy:8080",
  "auto_params": true,
  "threads": 5
}
```

- `cookies`: Optional HTTP cookies for authenticated scanning.
- `proxy`: Optional proxy server for requests.
- `auto_params`: Set to `true` to automatically extract form parameters from URLs, or `false` to manually input parameters.
- `threads`: Number of concurrent threads (default: 5).

## Output

- **Log File**: Scan activities and errors are logged to `scan.log`.
- **JSON Report**: Detailed scan results in JSON format (if `--report` is specified).
- **HTML Report**: A formatted table of scan results in HTML (if `--html-report` is specified).

## Example Output

### JSON Report (`results.json`)

```json
[
  {
    "url": "http://example.com/login",
    "parameter": "username",
    "type": "XSS",
    "payload": "<script>alert('XSS')</script>",
    "status": "Vulnerable"
  },
  {
    "url": "http://example.com/login",
    "parameter": "username",
    "type": "SQL Injection",
    "output": "...",
    "error": ""
  }
]
```

### HTML Report (`results.html`)

A table displaying the URL, parameter, vulnerability type, status, output, and errors.

## Notes

- **Ethical Use**: This tool is intended for authorized penetration testing and security research only. Do not use it on systems without explicit permission.
- **Dependencies**: Ensure `sqlmap` is configured correctly, as it is used for SQL injection testing.
- **Performance**: Adjust the `threads` setting in `config.json` based on your system's capabilities to avoid overloading.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.