# Web Application Security Scanner

A comprehensive, automated web application security testing framework designed for ethical hacking and penetration testing. This tool helps security professionals identify common web vulnerabilities in a controlled and responsible manner.

## ⚠️ IMPORTANT SECURITY WARNING

**This tool is for EDUCATIONAL PURPOSES ONLY and should ONLY be used on:**

- Websites you own
- Websites you have explicit written permission to test
- Your own test environments
- Authorized penetration testing engagements

**Unauthorized security testing is:**
- ILLEGAL in most jurisdictions
- A violation of computer fraud laws
- Potentially a criminal offense
- Unethical and harmful

**By using this tool, you agree that you:**
- Have proper authorization to test the target website
- Will not use it for malicious purposes
- Understand the legal implications
- Will follow responsible disclosure practices

## 🚀 Features

### Core Vulnerability Testing
- **Cross-Site Scripting (XSS)** - Reflected and Stored XSS detection
- **SQL Injection** - Multiple database engine support
- **Cross-Site Request Forgery (CSRF)** - Token validation testing
- **File Upload Vulnerabilities** - Malicious file type testing
- **Authentication Flaws** - Default credentials, weak auth testing
- **Directory Traversal** - Path traversal vulnerability detection

### Advanced Testing Capabilities
- **Open Redirect** - URL redirection vulnerability testing
- **Server-Side Request Forgery (SSRF)** - Internal network access testing
- **XML External Entity (XXE)** - XML parsing vulnerability detection
- **Command Injection** - OS command execution testing
- **Security Headers** - Missing security header detection

### Technical Features
- **Multi-threaded scanning** for improved performance
- **Rate limiting** to avoid overwhelming target servers
- **Comprehensive logging** of all activities
- **Multiple report formats** (JSON, HTML, CSV)
- **Configurable payloads** via YAML configuration
- **Session management** for authenticated testing
- **Error handling** and retry mechanisms

## 📋 Requirements

- Python 3.7+
- Internet connection
- Proper authorization for target websites

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd web-security-scanner
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python web_security_scanner.py --help
```

## 📖 Usage

### Basic Usage

#### Simple Scan
```bash
python web_security_scanner.py https://example.com
```

#### Scan with Authentication
```bash
python web_security_scanner.py https://example.com --username admin --password password123
```

#### Advanced Scanner
```bash
python advanced_scanner.py https://example.com --username admin --password password123
```

### Command Line Options

#### Basic Scanner
```bash
python web_security_scanner.py [URL] [OPTIONS]

Options:
  --username USERNAME    Username for authentication
  --password PASSWORD    Password for authentication
  --threads THREADS      Maximum number of threads (default: 5)
```

#### Advanced Scanner
```bash
python advanced_scanner.py [URL] [OPTIONS]

Options:
  --username USERNAME    Username for authentication
  --password PASSWORD    Password for authentication
  --config CONFIG        Configuration file path (default: config.yaml)
```

### Configuration

The scanner uses a YAML configuration file (`config.yaml`) for customizable settings:

```yaml
scanner:
  max_threads: 5
  request_delay: 1.0
  timeout: 30

payloads:
  xss:
    - '<script>alert("XSS")</script>'
  sql_injection:
    - "' OR '1'='1"
```

## 📊 Output and Reports

### Console Output
The scanner provides real-time feedback during execution:
```
Starting security scan of: https://example.com
Testing XSS on: https://example.com/login
Testing SQL Injection on: https://example.com/search
XSS vulnerability found: <script>alert("XSS")</script>
```

### Generated Reports

#### JSON Report
Comprehensive vulnerability data in machine-readable format:
```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "scan_date": "2024-01-15T10:30:00",
    "total_vulnerabilities": 3
  },
  "vulnerabilities": [...]
}
```

#### HTML Report
Professional, formatted report for stakeholders:
- Color-coded risk levels
- Detailed vulnerability descriptions
- Mitigation recommendations
- Executive summary

#### CSV Report
Spreadsheet-friendly format for analysis:
- Vulnerability type
- Risk level
- Affected URL
- Description
- Mitigation steps

### Log Files
- Detailed execution logs
- Error tracking
- Performance metrics
- Timestamped activities

## 🔧 Customization

### Adding Custom Payloads

Edit `config.yaml` to add your own testing payloads:

```yaml
payloads:
  custom_test:
    - "your_custom_payload_here"
    - "another_test_case"
```

### Modifying Test Parameters

Adjust scanning behavior in the configuration:

```yaml
scanner:
  max_threads: 10        # Increase for faster scanning
  request_delay: 0.5     # Reduce for aggressive testing
  timeout: 60            # Increase for slow servers
```

### Extending Functionality

The modular design allows easy addition of new test types:

```python
def test_custom_vulnerability(self, url, form_data=None):
    """Test for custom vulnerability type"""
    # Your custom testing logic here
    pass
```

## 🚨 Responsible Usage Guidelines

### Before Scanning
1. **Obtain Written Permission** from website owner
2. **Define Scope** of testing activities
3. **Set Expectations** for testing schedule
4. **Establish Communication** channels

### During Scanning
1. **Monitor Performance** of target systems
2. **Respect Rate Limits** to avoid disruption
3. **Document All Activities** for reporting
4. **Stop Immediately** if issues arise

### After Scanning
1. **Generate Comprehensive Report** with findings
2. **Prioritize Vulnerabilities** by risk level
3. **Provide Clear Mitigation** recommendations
4. **Follow Up** on critical issues

## 📚 Common Use Cases

### Penetration Testing
- Pre-deployment security assessment
- Regular security audits
- Compliance testing (OWASP, NIST)
- Vulnerability management

### Security Research
- Learning web application security
- Testing security tools and techniques
- Academic research projects
- Security conference presentations

### Bug Bounty Programs
- Authorized vulnerability hunting
- Responsible disclosure programs
- Security community contributions
- Professional development

## ⚡ Performance Tips

### Optimizing Scan Speed
- Increase thread count (with caution)
- Reduce request delays
- Focus on high-risk endpoints
- Use targeted scanning

### Reducing Resource Usage
- Limit concurrent connections
- Implement proper delays
- Monitor memory usage
- Clean up temporary files

### Network Considerations
- Use stable internet connection
- Consider bandwidth limitations
- Monitor for rate limiting
- Respect server capabilities

## 🐛 Troubleshooting

### Common Issues

#### Connection Errors
```bash
Error: Connection timeout
Solution: Check network connectivity and increase timeout values
```

#### Authentication Failures
```bash
Warning: Authentication failed
Solution: Verify credentials and login endpoint
```

#### Rate Limiting
```bash
Error: 429 Too Many Requests
Solution: Increase delays between requests
```

### Debug Mode
Enable verbose logging for troubleshooting:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 🔒 Security Best Practices

### For Testers
- Always obtain proper authorization
- Use dedicated testing accounts
- Document all activities
- Follow responsible disclosure

### For Website Owners
- Implement proper access controls
- Monitor for unauthorized testing
- Have incident response plans
- Regular security assessments

## 📞 Support and Community

### Getting Help
- Review error logs for specific issues
- Check configuration file syntax
- Verify Python dependencies
- Consult security community forums

### Contributing
- Report bugs and issues
- Suggest new features
- Improve documentation
- Share security research

### Learning Resources
- OWASP Web Security Testing Guide
- Web Application Security Consortium
- Security conference materials
- Online security courses

## 📄 License and Legal

This tool is provided for educational purposes only. Users are responsible for:

- Obtaining proper authorization
- Following applicable laws
- Respecting website terms of service
- Using the tool responsibly

## 🙏 Acknowledgments

- OWASP community for security guidance
- Security researchers for vulnerability research
- Open source contributors
- Ethical hacking community

---

**Remember: With great power comes great responsibility. Use this tool wisely and ethically.**

## 📝 Changelog

### Version 2.0 (Advanced Scanner)
- Added advanced vulnerability testing modules
- Enhanced reporting capabilities
- Improved configuration management
- Better error handling and retry logic

### Version 1.0 (Basic Scanner)
- Core vulnerability testing framework
- Basic reporting functionality
- Multi-threaded scanning
- Session management

---

**Last Updated: January 2024**
**Version: 2.0**
**Author: Security Researcher**
