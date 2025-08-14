#!/usr/bin/env python3
"""
Test script to verify scanner functionality
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    try:
        import requests
        print("✅ requests imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import requests: {e}")
        return False
    
    try:
        from bs4 import BeautifulSoup
        print("✅ BeautifulSoup imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import BeautifulSoup: {e}")
        return False
    
    try:
        import yaml
        print("✅ yaml imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import yaml: {e}")
        return False
    
    return True

def test_scanner_imports():
    """Test if scanner modules can be imported"""
    try:
        from web_security_scanner import WebSecurityScanner
        print("✅ WebSecurityScanner imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import WebSecurityScanner: {e}")
        return False
    
    try:
        from advanced_scanner import AdvancedSecurityScanner
        print("✅ AdvancedSecurityScanner imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import AdvancedSecurityScanner: {e}")
        return False
    
    return True

def test_scanner_instantiation():
    """Test if scanner classes can be instantiated"""
    try:
        from web_security_scanner import WebSecurityScanner
        scanner = WebSecurityScanner("https://example.com")
        print("✅ WebSecurityScanner instantiated successfully")
    except Exception as e:
        print(f"❌ Failed to instantiate WebSecurityScanner: {e}")
        return False
    
    try:
        from advanced_scanner import AdvancedSecurityScanner
        scanner = AdvancedSecurityScanner("https://example.com")
        print("✅ AdvancedSecurityScanner instantiated successfully")
    except Exception as e:
        print(f"❌ Failed to instantiate AdvancedSecurityScanner: {e}")
        return False
    
    return True

def main():
    print("Testing scanner functionality...")
    print("=" * 50)
    
    # Test basic imports
    if not test_imports():
        print("❌ Basic imports failed")
        sys.exit(1)
    
    # Test scanner imports
    if not test_scanner_imports():
        print("❌ Scanner imports failed")
        sys.exit(1)
    
    # Test scanner instantiation
    if not test_scanner_instantiation():
        print("❌ Scanner instantiation failed")
        sys.exit(1)
    
    print("=" * 50)
    print("✅ All tests passed! Scanners are ready to use.")
    return True

if __name__ == "__main__":
    main()
