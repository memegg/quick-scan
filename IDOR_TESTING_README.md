# 🔐 IDOR Testing with Dual Account Security Scanner

## Overview

The enhanced security scanner now includes comprehensive **IDOR (Insecure Direct Object Reference)** testing capabilities using **two separate user accounts**. This allows the scanner to detect authorization bypasses where users can access other users' data.

## 🚀 New Features

### **Dual Account Authentication**
- **Account 1**: Primary account for basic scanning
- **Account 2**: Secondary account for IDOR vulnerability detection
- Both accounts maintain separate sessions for accurate testing

### **Comprehensive IDOR Testing**

#### **1. Profile Access Testing**
- Tests access to user profiles with different IDs
- Detects if User1 can access User2's profile
- Common endpoints: `/profile/{id}`, `/user/{id}`, `/account/{id}`

#### **2. File Access Testing**
- Tests file download endpoints with different IDs
- Detects unauthorized file access across users
- Common endpoints: `/files/{id}`, `/download/{id}`, `/documents/{id}`

#### **3. API Endpoint Testing**
- Tests REST API endpoints for authorization bypasses
- Detects if users can access other users' data via API
- Common endpoints: `/api/users/{id}`, `/api/orders/{id}`, `/api/posts/{id}`

#### **4. Order/Transaction Testing**
- Tests access to orders, purchases, and transactions
- Detects financial data exposure vulnerabilities
- Common endpoints: `/orders/{id}`, `/purchases/{id}`, `/invoices/{id}`

#### **5. Message/Communication Testing**
- Tests access to private messages and communications
- Detects privacy violations and data leaks
- Common endpoints: `/messages/{id}`, `/chats/{id}`, `/emails/{id}`

## 🛠️ Usage

### **Command Line Usage**

#### **Basic Scanner with IDOR Testing**
```bash
python web_security_scanner.py "https://target.com" \
  --username "user1@example.com" \
  --password "password1" \
  --username2 "user2@example.com" \
  --password2 "password2" \
  --non-interactive
```

#### **Advanced Scanner with IDOR Testing**
```bash
python advanced_scanner.py "https://target.com" \
  --username "user1@example.com" \
  --password "password1" \
  --username2 "user2@example.com" \
  --password2 "password2" \
  --config "config.yaml" \
  --non-interactive
```

### **GitHub Actions Usage**

When running the workflow, you can now provide:

- **Target URL**: The website to scan
- **Username**: First account username
- **Password**: First account password
- **Username2**: Second account username (for IDOR testing)
- **Password2**: Second account password (for IDOR testing)
- **Scanner Type**: Choose `basic` or `advanced`

## 🔍 How IDOR Testing Works

### **1. Authentication Phase**
```
User1 Login → Session1 Created
User2 Login → Session2 Created
```

### **2. Testing Phase**
```
For each endpoint pattern:
  - Test with User1 session
  - Test with User2 session
  - Compare responses
  - Detect if both users can access same resource
```

### **3. Vulnerability Detection**
```
If User1 can access User2's data:
  → IDOR Vulnerability Found
  → Risk Level: High
  → Detailed Report Generated
```

## 📊 Test Coverage

### **Basic Scanner IDOR Tests**
- **Profile Access**: 5 common patterns
- **File Access**: 5 common patterns
- **API Access**: 5 common patterns
- **Order Access**: 4 common patterns
- **Total Test Cases**: 95+ combinations

### **Advanced Scanner IDOR Tests**
- **Profile Access**: 10 common patterns
- **File Access**: 8 common patterns
- **API Access**: 8 common patterns
- **Order Access**: 7 common patterns
- **Message Access**: 5 common patterns
- **Total Test Cases**: 300+ combinations

## 🎯 What Gets Tested

### **Common IDOR Patterns**
```
/profile/{id}          → User profile access
/user/{id}             → User account access
/files/{id}            → File download access
/api/users/{id}        → API user data access
/orders/{id}           → Order information access
/messages/{id}         → Private message access
```

### **ID Range Testing**
- **Basic Scanner**: Tests IDs 1-10
- **Advanced Scanner**: Tests IDs 1-15 (some endpoints)
- **Smart Detection**: Automatically detects valid ID ranges

## 🚨 Vulnerability Types Detected

### **High Risk**
- **Profile Access Bypass**: Users can view other users' profiles
- **API Data Exposure**: Users can access other users' data via API
- **Order Information Leak**: Users can view other users' orders
- **Message Privacy Violation**: Users can read other users' messages

### **Medium Risk**
- **File Access Control**: Insufficient file access restrictions
- **Resource Enumeration**: Users can enumerate other users' resources

## 📋 Sample Report Output

```json
{
  "type": "IDOR - Profile Access",
  "url": "https://target.com/profile/123",
  "payload": "User1 accessing User2 profile with ID: 123",
  "risk_level": "High",
  "description": "User can access other users profile information",
  "mitigation": "Implement proper authorization checks and validate user ownership"
}
```

## 🔧 Configuration

### **Custom IDOR Patterns**
You can add custom IDOR patterns in `config.yaml`:

```yaml
idor_patterns:
  custom_endpoints:
    - "/custom/{id}"
    - "/special/{id}"
  test_ids:
    start: 1
    end: 20
```

### **Rate Limiting**
```yaml
scanner:
  request_delay: 1.0  # Delay between requests
  max_threads: 3      # Concurrent testing threads
```

## ⚠️ Important Notes

### **Ethical Usage**
- **ONLY test websites you own or have explicit permission to test**
- **IDOR testing involves accessing real user data**
- **Ensure you have proper authorization before testing**

### **Account Requirements**
- **Two separate, valid user accounts required**
- **Accounts should have different permission levels if possible**
- **Accounts should contain different data for accurate testing**

### **Performance Considerations**
- **IDOR testing increases scan time significantly**
- **More comprehensive testing = longer scan duration**
- **Use appropriate rate limiting to avoid overwhelming target**

## 🚀 Getting Started

1. **Prepare Two Test Accounts**
   - Create two separate user accounts on target website
   - Ensure accounts have different data/permissions
   - Note down usernames and passwords

2. **Run Basic IDOR Scan**
   ```bash
   python web_security_scanner.py "https://your-site.com" \
     --username "account1@site.com" \
     --password "pass1" \
     --username2 "account2@site.com" \
     --password2 "pass2" \
     --non-interactive
   ```

3. **Run Advanced IDOR Scan**
   ```bash
   python advanced_scanner.py "https://your-site.com" \
     --username "account1@site.com" \
     --password "pass1" \
     --username2 "account2@site.com" \
     --password2 "pass2" \
     --non-interactive
   ```

4. **Review Results**
   - Check generated reports for IDOR vulnerabilities
   - Prioritize fixes based on risk levels
   - Implement proper authorization controls

## 🔒 Security Best Practices

### **Prevention**
- **Always validate user ownership** before allowing access
- **Implement proper authorization** at every endpoint
- **Use session-based validation** for user-specific resources
- **Test with multiple accounts** during development

### **Detection**
- **Regular security scans** with dual account testing
- **Automated IDOR testing** in CI/CD pipelines
- **Manual verification** of critical endpoints
- **User permission audits** on regular basis

## 📞 Support

For questions about IDOR testing:
- Check the generated logs for detailed information
- Review the vulnerability reports for specific findings
- Ensure both accounts are properly authenticated
- Verify target website allows security testing

---

**Remember: With great power comes great responsibility. Use this tool ethically and only on authorized targets.**
