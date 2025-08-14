# 🚀 Web Security Scanner - GitHub Actions

This repository includes GitHub Actions workflows that allow you to run web security scans without installing Python locally. The scanner runs in GitHub's cloud environment and provides detailed reports.

## ⚠️ **IMPORTANT: Ethical Usage Only**

**This tool is for EDUCATIONAL PURPOSES ONLY and should ONLY be used on:**
- Websites you own
- Websites you have explicit written permission to test
- Your own test environments
- Authorized penetration testing engagements

**Unauthorized security testing is ILLEGAL and UNETHICAL.**

## 🎯 **Available Workflows**

### 1. **Full Security Scan** (`.github/workflows/security-scan.yml`)
Comprehensive vulnerability testing with both basic and advanced scanners.

**Features:**
- XSS (Cross-Site Scripting) detection
- SQL Injection testing
- CSRF vulnerability assessment
- File upload security testing
- Authentication flaws detection
- Directory traversal testing
- Advanced: Open Redirect, SSRF, XXE, Command Injection
- Security headers analysis

### 2. **Quick Security Scan** (`.github/workflows/quick-scan.yml`)
Fast, focused scanning for specific vulnerability types.

**Features:**
- Security headers check
- Basic XSS assessment
- SQL injection pattern detection
- Form input analysis
- Quick results in under 2 minutes

## 🚀 **How to Use**

### **Method 1: GitHub Web Interface (Recommended)**

1. **Go to your repository** on GitHub
2. **Click on "Actions" tab**
3. **Select the workflow** you want to run:
   - `Web Security Scanner` (full scan)
   - `Quick Security Scan` (quick scan)
4. **Click "Run workflow"**
5. **Fill in the required information:**
   - **Target URL**: The website you want to scan (must be yours or authorized)
   - **Scanner Type**: Choose basic/advanced or scan type
   - **Username/Password**: If authentication is needed
6. **Click "Run workflow"**

### **Method 2: GitHub CLI**

```bash
# Install GitHub CLI first
# Then run:

# Full security scan
gh workflow run "Web Security Scanner" \
  --field target_url="https://your-website.com" \
  --field scanner_type="basic" \
  --field username="your_username" \
  --field password="your_password"

# Quick scan
gh workflow run "Quick Security Scan" \
  --field target_url="https://your-website.com" \
  --field scan_type="all"
```

### **Method 3: API Trigger**

```bash
curl -X POST \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/YOUR_USERNAME/YOUR_REPO/dispatches \
  -d '{
    "event_type": "security-scan",
    "client_payload": {
      "target_url": "https://your-website.com",
      "scanner_type": "basic"
    }
  }'
```

## 📊 **Understanding Results**

### **Workflow Summary**
After each run, GitHub Actions provides:
- **Step-by-step execution log**
- **Summary of findings**
- **Downloadable artifacts** (reports, logs)

### **Generated Reports**
- **JSON reports**: Machine-readable data
- **HTML reports**: Professional presentations
- **CSV reports**: Spreadsheet analysis
- **Log files**: Detailed execution logs

### **Risk Levels**
- **Critical**: Immediate action required
- **High**: Fix as soon as possible
- **Medium**: Address in next release
- **Low**: Consider for future updates
- **Info**: Informational findings

## 🔧 **Configuration Options**

### **Full Scanner Options**
```yaml
target_url: "https://example.com"          # Required
username: "admin"                          # Optional
password: "password123"                    # Optional
scanner_type: "basic" | "advanced"         # Required
config_file: "config.yaml"                 # Optional (advanced only)
```

### **Quick Scanner Options**
```yaml
target_url: "https://example.com"          # Required
scan_type: "all" | "xss-only" | "sql-injection-only" | "headers-only"  # Required
```

## 📋 **Example Use Cases**

### **1. Pre-Deployment Security Check**
```yaml
# Run before deploying to production
target_url: "https://staging.yourcompany.com"
scanner_type: "advanced"
```

### **2. Regular Security Audit**
```yaml
# Monthly security check
target_url: "https://yourcompany.com"
scanner_type: "basic"
```

### **3. Quick Header Check**
```yaml
# Fast security headers validation
target_url: "https://yourcompany.com"
scan_type: "headers-only"
```

### **4. Form Security Assessment**
```yaml
# Check for XSS vulnerabilities
target_url: "https://yourcompany.com"
scan_type: "xss-only"
```

## 🛡️ **Security Best Practices**

### **Before Running**
1. **Verify ownership** of target website
2. **Get written permission** if testing others' sites
3. **Schedule scans** during low-traffic periods
4. **Monitor target systems** during scanning

### **During Scanning**
1. **Watch for errors** in the workflow logs
2. **Check target website** performance
3. **Stop immediately** if issues arise

### **After Scanning**
1. **Download all artifacts** before they expire
2. **Review findings** carefully
3. **Prioritize fixes** by risk level
4. **Implement mitigations** promptly

## 🐛 **Troubleshooting**

### **Common Issues**

#### **Workflow Fails to Start**
- Check repository permissions
- Verify workflow file syntax
- Ensure GitHub Actions is enabled

#### **Scan Times Out**
- Target website is slow
- Network connectivity issues
- Increase timeout in configuration

#### **Authentication Fails**
- Verify credentials
- Check login endpoint
- Ensure account is active

#### **No Vulnerabilities Found**
- Website is well-secured
- Scanner needs configuration
- Check scan type selection

### **Debug Mode**
Enable debug logging by modifying the workflow:
```yaml
- name: Debug mode
  run: |
    export PYTHONVERBOSE=1
    python -u your_scanner.py
```

## 📚 **Learning Resources**

- **OWASP Top 10**: Common web vulnerabilities
- **Security Headers**: HTTP security best practices
- **XSS Prevention**: Cross-site scripting defense
- **SQL Injection**: Database security
- **CSRF Protection**: Cross-site request forgery

## 🔒 **Legal and Ethical Considerations**

### **What You Can Do**
- Test your own websites
- Test with explicit permission
- Use for educational purposes
- Contribute to security research

### **What You Cannot Do**
- Test unauthorized websites
- Perform malicious attacks
- Violate terms of service
- Cause service disruption

### **Responsible Disclosure**
If you find vulnerabilities:
1. **Document thoroughly**
2. **Contact website owner**
3. **Give reasonable time** to fix
4. **Follow responsible disclosure** guidelines

## 📞 **Support and Community**

### **Getting Help**
- Check workflow logs for errors
- Review GitHub Actions documentation
- Consult security community forums
- Report issues in repository

### **Contributing**
- Improve workflow efficiency
- Add new vulnerability tests
- Enhance reporting capabilities
- Share security research

---

## 🎉 **Ready to Start?**

1. **Fork this repository** to your GitHub account
2. **Go to Actions tab**
3. **Select a workflow**
4. **Click "Run workflow"**
5. **Enter your target URL**
6. **Review results and artifacts**

**Remember: With great power comes great responsibility. Use this tool wisely and ethically.**

---

**Last Updated: January 2024**
**Version: GitHub Actions 1.0**
