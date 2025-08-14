#!/usr/bin/env python3
"""
Simple test script for GitHub Actions workflow
"""

import sys
import os

def test_basic_imports():
    """Test basic imports"""
    try:
        import requests
        print("✅ requests imported")
    except ImportError as e:
        print(f"❌ requests import failed: {e}")
        return False
    
    try:
        from bs4 import BeautifulSoup
        print("✅ BeautifulSoup imported")
    except ImportError as e:
        print(f"❌ BeautifulSoup import failed: {e}")
        return False
    
    try:
        import yaml
        print("✅ yaml imported")
    except ImportError as e:
        print(f"❌ yaml import failed: {e}")
        return False
    
    return True

def test_scanner_imports():
    """Test scanner imports"""
    try:
        from web_security_scanner import WebSecurityScanner
        print("✅ WebSecurityScanner imported")
    except ImportError as e:
        print(f"❌ WebSecurityScanner import failed: {e}")
        return False
    
    try:
        from advanced_scanner import AdvancedSecurityScanner
        print("✅ AdvancedSecurityScanner imported")
    except ImportError as e:
        print(f"❌ AdvancedSecurityScanner import failed: {e}")
        return False
    
    return True

def test_scanner_creation():
    """Test scanner creation (without running scan)"""
    try:
        from web_security_scanner import WebSecurityScanner
        scanner = WebSecurityScanner("https://example.com")
        print("✅ WebSecurityScanner created successfully")
    except Exception as e:
        print(f"❌ WebSecurityScanner creation failed: {e}")
        return False
    
    try:
        from advanced_scanner import AdvancedSecurityScanner
        scanner = AdvancedSecurityScanner("https://example.com")
        print("✅ AdvancedSecurityScanner created successfully")
    except Exception as e:
        print(f"❌ AdvancedSecurityScanner creation failed: {e}")
        return False
    
    return True

def main():
    print("🧪 Testing scanner setup for GitHub Actions...")
    print("=" * 50)
    
    # Test basic imports
    if not test_basic_imports():
        print("❌ Basic imports failed")
        sys.exit(1)
    
    # Test scanner imports
    if not test_scanner_imports():
        print("❌ Scanner imports failed")
        sys.exit(1)
    
    # Test scanner creation
    if not test_scanner_creation():
        print("❌ Scanner creation failed")
        sys.exit(1)
    
    print("=" * 50)
    print("✅ All tests passed! Scanners are ready for GitHub Actions.")
    return True

if __name__ == "__main__":
    main()
