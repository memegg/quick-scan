#!/usr/bin/env python3
import requests
import json
import argparse
from datetime import datetime

class WorkingScanner:
    def __init__(self, target_url, username=None, password=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Set headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        print("Testing XSS...")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>'
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{self.target_url}?test={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': test_url,
                        'risk': 'High',
                        'description': 'XSS payload found in response'
                    })
                    print(f"✅ XSS found: {payload}")
                    break
            except:
                continue
    
    def test_sql_injection(self):
        """Test for SQL injection"""
        print("Testing SQL Injection...")
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--"
        ]
        
        for payload in sqli_payloads:
            try:
                test_url = f"{self.target_url}?id={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if 'sql' in response.text.lower() or 'mysql' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': test_url,
                        'risk': 'Critical',
                        'description': 'SQL error detected'
                    })
                    print(f"✅ SQL Injection found: {payload}")
                    break
            except:
                continue
    
    def test_directory_traversal(self):
        """Test for directory traversal"""
        print("Testing Directory Traversal...")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{self.target_url}?file={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if 'root:' in response.text or 'Administrator' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'risk': 'High',
                        'description': 'Directory traversal successful'
                    })
                    print(f"✅ Directory Traversal found: {payload}")
                    break
            except:
                continue
    
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        print("Testing Authentication Bypass...")
        
        admin_endpoints = ['/admin', '/admin/dashboard', '/admin/users']
        
        for endpoint in admin_endpoints:
            try:
                test_url = f"{self.target_url}{endpoint}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and 'admin' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'url': test_url,
                        'risk': 'Critical',
                        'description': 'Admin endpoint accessible without auth'
                    })
                    print(f"✅ Authentication Bypass found: {endpoint}")
                    break
            except:
                continue
    
    def run_scan(self):
        """Run all tests"""
        print(f"🔍 Starting scan of: {self.target_url}")
        
        self.test_xss()
        self.test_sql_injection()
        self.test_directory_traversal()
        self.test_authentication_bypass()
        
        print(f"\n📊 Scan completed! Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Working Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--non-interactive', action='store_true', help='Skip prompts')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: Please provide a valid URL")
        return 1
    
    print("⚠️  WARNING: Only test websites you own or have permission to test!")
    
    if not args.non_interactive:
        try:
            confirm = input("Do you have permission? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Scan cancelled.")
                return 0
        except:
            print("Running in non-interactive mode")
    
    try:
        scanner = WorkingScanner(args.url, args.username, args.password)
        vulnerabilities = scanner.run_scan()
        
        if vulnerabilities:
            print("\n🚨 VULNERABILITIES FOUND:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']}")
                print(f"   Risk: {vuln['risk']}")
                print(f"   URL: {vuln['url']}")
                print(f"   Description: {vuln['description']}")
        
        # Save report
        report = {
            'target_url': args.url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities
        }
        
        filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report saved to: {filename}")
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    main()
