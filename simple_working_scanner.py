#!/usr/bin/env python3
"""
Simple Working Web Security Scanner
A functional tool that actually performs security tests and finds vulnerabilities.
Use only on websites you own or have explicit permission to test.

Author: Security Researcher
Version: 1.0
"""

import requests
import urllib.parse
import re
import json
import argparse
import logging
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class SimpleWorkingScanner:
    def __init__(self, target_url, username=None, password=None, username2=None, password2=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.username2 = username2
        self.password2 = password2
        self.session = requests.Session()
        self.session2 = requests.Session()
        self.vulnerabilities = []
        self.endpoints = set()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)
        
        # Set reasonable timeouts
        self.session.timeout = 10
        self.session2.timeout = 10
        
        # User agent to avoid being blocked
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session2.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def authenticate(self):
        """Authenticate first account"""
        if not self.username or not self.password:
            return False
            
        try:
            login_data = {
                'email': self.username,
                'password': self.password,
                'username': self.username,  # Try both email and username
                'login': self.username
            }
            
            # Try common login endpoints
            login_endpoints = ['/login', '/signin', '/auth', '/user/login', '/admin/login']
            
            for endpoint in login_endpoints:
                try:
                    response = self.session.post(f"{self.target_url}{endpoint}", data=login_data, timeout=10)
                    if response.status_code == 200 and 'error' not in response.text.lower():
                        self.logger.info(f"Authentication successful via {endpoint}")
                        return True
                except:
                    continue
            
            self.logger.warning("Authentication failed")
            return False
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    def authenticate_account2(self):
        """Authenticate second account"""
        if not self.username2 or not self.password2:
            return False
            
        try:
            login_data = {
                'email': self.username2,
                'password': self.password2,
                'username': self.username2,
                'login': self.username2
            }
            
            login_endpoints = ['/login', '/signin', '/auth', '/user/login', '/admin/login']
            
            for endpoint in login_endpoints:
                try:
                    response = self.session2.post(f"{self.target_url}{endpoint}", data=login_data, timeout=10)
                    if response.status_code == 200 and 'error' not in response.text.lower():
                        self.logger.info(f"Second account authentication successful via {endpoint}")
                        return True
                except:
                    continue
            
            self.logger.warning("Second account authentication failed")
            return False
            
        except Exception as e:
            self.logger.error(f"Second account authentication error: {e}")
            return False

    def discover_endpoints(self):
        """Discover endpoints by crawling and common patterns"""
        self.logger.info("Discovering endpoints...")
        
        try:
            # Get main page
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/') or href.startswith(self.target_url):
                        full_url = urljoin(self.target_url, href)
                        self.endpoints.add(full_url)
                
                # Add common endpoints to test
                common_endpoints = [
                    '/admin', '/admin/login', '/admin/dashboard',
                    '/user', '/user/profile', '/user/settings',
                    '/api', '/api/users', '/api/data',
                    '/profile', '/settings', '/dashboard',
                    '/upload', '/download', '/files',
                    '/search', '/login', '/register',
                    '/logout', '/password', '/reset'
                ]
                
                for endpoint in common_endpoints:
                    self.endpoints.add(f"{self.target_url}{endpoint}")
                
                self.logger.info(f"Discovered {len(self.endpoints)} endpoints")
                
        except Exception as e:
            self.logger.error(f"Error discovering endpoints: {e}")

    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        try:
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")'
            ]
            
            for payload in xss_payloads:
                # Test in URL parameters
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    vulnerability = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': test_url,
                        'payload': payload,
                        'risk_level': 'High',
                        'description': 'XSS payload found in response',
                        'mitigation': 'Implement proper input validation and output encoding'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"XSS vulnerability found: {payload}")
                    break
                    
        except Exception as e:
            pass  # Skip if endpoint doesn't exist

    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        try:
            sqli_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--"
            ]
            
            for payload in sqli_payloads:
                test_url = f"{url}?id={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL error messages
                sql_errors = [
                    'sql syntax', 'mysql_fetch', 'oracle error',
                    'postgresql error', 'sql server error'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': test_url,
                            'payload': payload,
                            'risk_level': 'Critical',
                            'description': f'SQL error detected: {error}',
                            'mitigation': 'Use parameterized queries and input validation'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.logger.warning(f"SQL Injection vulnerability found: {payload}")
                        return
                        
        except Exception as e:
            pass

    def test_directory_traversal(self, url):
        """Test for directory traversal vulnerabilities"""
        try:
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd'
            ]
            
            for payload in traversal_payloads:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
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
                    break
                    
        except Exception as e:
            pass

    def test_idor(self):
        """Test for IDOR vulnerabilities using two accounts"""
        if not self.username or not self.password or not self.username2 or not self.password2:
            self.logger.info("Two accounts required for IDOR testing, skipping")
            return
        
        self.logger.info("Testing for IDOR vulnerabilities...")
        
        # Authenticate both accounts
        if not self.authenticate_account2():
            self.logger.warning("Failed to authenticate second account, skipping IDOR tests")
            return
        
        # Test common IDOR patterns
        idor_patterns = [
            '/profile/{id}',
            '/user/{id}',
            '/api/users/{id}',
            '/orders/{id}',
            '/files/{id}'
        ]
        
        for pattern in idor_patterns:
            for test_id in range(1, 6):  # Test IDs 1-5
                test_url = f"{self.target_url}{pattern.format(id=test_id)}"
                
                try:
                    response1 = self.session.get(test_url, timeout=10)
                    response2 = self.session2.get(test_url, timeout=10)
                    
                    # If both users can access the same resource, it might be IDOR
                    if response1.status_code == 200 and response2.status_code == 200:
                        if response1.content != response2.content:
                            vulnerability = {
                                'type': 'IDOR - Access Control Bypass',
                                'url': test_url,
                                'payload': f'Both users can access resource with ID: {test_id}',
                                'risk_level': 'High',
                                'description': 'Users can access other users data',
                                'mitigation': 'Implement proper authorization checks'
                            }
                            self.vulnerabilities.append(vulnerability)
                            self.logger.warning(f"IDOR vulnerability: {test_url}")
                            
                except Exception as e:
                    continue

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        self.logger.info("Testing authentication bypass...")
        
        # Test common admin endpoints
        admin_endpoints = [
            '/admin', '/admin/dashboard', '/admin/users',
            '/admin/settings', '/admin/config'
        ]
        
        for endpoint in admin_endpoints:
            try:
                test_url = f"{self.target_url}{endpoint}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and 'admin' in response.text.lower():
                    vulnerability = {
                        'type': 'Authentication Bypass',
                        'url': test_url,
                        'payload': 'Direct access to admin endpoint',
                        'risk_level': 'Critical',
                        'description': 'Admin endpoint accessible without authentication',
                        'mitigation': 'Implement proper authentication and authorization'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"Authentication bypass: {test_url}")
                    
            except Exception as e:
                continue

    def test_default_credentials(self):
        """Test for default credentials"""
        self.logger.info("Testing default credentials...")
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        for username, password in default_creds:
            try:
                login_data = {
                    'email': username,
                    'password': password,
                    'username': username
                }
                
                response = self.session.post(f"{self.target_url}/login", data=login_data, timeout=10)
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    vulnerability = {
                        'type': 'Default Credentials',
                        'url': f"{self.target_url}/login",
                        'payload': f'{username}:{password}',
                        'risk_level': 'Medium',
                        'description': f'Default credentials work: {username}:{password}',
                        'mitigation': 'Change default credentials and implement strong password policies'
                    }
                    self.vulnerabilities.append(vulnerability)
                    self.logger.warning(f"Default credentials work: {username}:{password}")
                    
            except Exception as e:
                continue

    def run_scan(self):
        """Run the complete security scan"""
        self.logger.info(f"Starting security scan of: {self.target_url}")
        
        # Authenticate if credentials provided
        if self.username and self.password:
            self.authenticate()
        
        # Discover endpoints
        self.discover_endpoints()
        
        # Test each endpoint
        for endpoint in list(self.endpoints)[:20]:  # Limit to first 20 endpoints
            self.test_xss(endpoint)
            self.test_sql_injection(endpoint)
            self.test_directory_traversal(endpoint)
        
        # Test authentication bypass
        self.test_authentication_bypass()
        
        # Test default credentials
        self.test_default_credentials()
        
        # Test for IDOR vulnerabilities if two accounts are provided
        self.test_idor()
        
        self.logger.info("Security scan completed")
        return self.generate_report()

    def generate_report(self):
        """Generate a security report"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities,
            'endpoints_discovered': len(self.endpoints)
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
    parser = argparse.ArgumentParser(description='Simple Working Web Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--username', help='Username for first account')
    parser.add_argument('--password', help='Password for first account')
    parser.add_argument('--username2', help='Username for second account (for IDOR testing)')
    parser.add_argument('--password2', help='Password for second account (for IDOR testing)')
    parser.add_argument('--non-interactive', action='store_true', help='Skip interactive prompts (for CI/CD)')
    
    args = parser.parse_args()
    
    # Safety check
    if not args.url.startswith(('http://', 'https://')):
        print("Error: Please provide a valid URL starting with http:// or https://")
        return 1
    
    print("WARNING: This tool is for educational purposes only.")
    print("Only use on websites you own or have explicit permission to test.")
    print("Unauthorized security testing is illegal and unethical.")
    
    # Skip confirmation in non-interactive mode
    if not args.non_interactive:
        try:
            confirm = input("\nDo you have permission to test this website? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Scan cancelled. Please obtain proper authorization before testing.")
                return 0
        except EOFError:
            print("Running in non-interactive mode. Assuming permission granted.")
    else:
        print("Running in non-interactive mode. Assuming permission granted.")
    
    try:
        scanner = SimpleWorkingScanner(
            target_url=args.url,
            username=args.username,
            password=args.password,
            username2=args.username2,
            password2=args.password2
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
        return 1

if __name__ == "__main__":
    main()
