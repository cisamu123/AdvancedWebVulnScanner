'''
       ^ Author    : Cisamu
       ^ Name      : AdvancedWebVulnScanner
       ^ Github    : https://github.com/cisamu123
'''
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner")
    parser.add_argument('target_url', type=str, help='The URL to scan for vulnerabilities')
    parser.add_argument('report_file', type=str, help='The file to save the scan report')
    parser.add_argument('--user-agent', type=str, help='User-Agent header to use for requests')
    parser.add_argument('--proxies', type=str, help='Proxy server URL (e.g., http://localhost:8080)')
    return parser.parse_args()
