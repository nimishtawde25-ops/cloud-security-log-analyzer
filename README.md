# Cloud Security Log Analyzer

A Python and Flask-based security monitoring application that analyzes security logs, detects suspicious activity, calculates risk, and presents security events through a web dashboard.

---

## Features

### 🔐 Authentication
- Login system
- Logout functionality
- Session-based authentication
- HTTP-only session cookies
- SameSite cookie protection

### 📊 Security Dashboard
- Total security events
- Critical events
- High-severity events
- Medium-severity events
- Low-severity events
- Alert history
- Risk scores
- Risk levels
- IP addresses
- Usernames
- Event timestamps

### 🔎 Log Analysis
The analyzer can identify security-related events such as:

- Failed login attempts
- Unauthorized access
- Permission denied
- Successful login
- Suspicious activity
- Repeated authentication failures

### 🚨 Threat Detection
The project includes:

- Brute-force detection
- Suspicious IP analysis
- Attack-pattern detection
- Incident classification
- Threat correlation
- Advanced threat detection
- Risk scoring
- Threat severity classification

### 📈 Risk Analysis

Threats are assigned:

- Risk score
- Risk level
- Severity
- Priority
- Confidence
- Incident type
- Attack stage

### 📁 Log Upload

Supported log files:

- `.log`
- `.txt`

Maximum upload size:

```text
5 MB
