# A01:2021 - Broken Access Control

## 1. What is the Vulnerability?

Broken Access Control occurs when users can act outside of their intended permissions. This allows attackers to access unauthorized functionality or data, such as accessing other users' accounts, viewing sensitive files, modifying other users' data, or changing access rights.

**Key Characteristics:**

- Users can access resources they shouldn't have permission to
- Horizontal privilege escalation (accessing another user's data)
- Vertical privilege escalation (accessing admin functions as regular user)
- Missing or inadequate authorization checks

## 2. Root Cause Analysis

**Primary Causes:**

- **Missing Authorization Checks**: Functions that don't verify if the user should have access
- **Insecure Direct Object References (IDOR)**: Direct access to objects without proper authorization
- **Elevation of Privilege**: Users can act as admins without proper checks
- **Metadata Manipulation**: Tampering with JWT tokens, cookies, or hidden fields
- **CORS Misconfiguration**: Allowing unauthorized cross-origin requests
- **Force Browsing**: Accessing pages/functions by guessing URLs

**Technical Root Causes:**

- Lack of centralized access control mechanism
- Inconsistent authorization implementation
- Client-side enforcement only
- Default configurations that are too permissive

## 3. Real World Cases

### Case Study 1: Facebook Privacy Bug (2018)

- **Impact**: 14 million users' private posts became public
- **Cause**: A code change caused the audience selector to default to "public" instead of user's preference
- **Lesson**: Default configurations must be secure, not convenient

## 4. Manual Testing Methodology

### 4.1 Horizontal Privilege Escalation Testing

```bash
# Test accessing other users' data
# Original request
GET /user/profile?id=123

# Modified request (try different user IDs)
GET /user/profile?id=124
GET /user/profile?id=125
```

### 4.2 Vertical Privilege Escalation Testing

```bash
# Test accessing admin functions as regular user
# Try admin endpoints with regular user session
GET /admin/users
POST /admin/delete-user
GET /admin/system-config
```

### 4.3 Direct Object Reference Testing

```bash
# Test direct access to objects
GET /documents/confidential-report-123.pdf
GET /api/user/456/sensitive-data
GET /files/financial-data-2023.xlsx
```

### 4.4 Session Management Testing

- Test session timeout
- Try session fixation attacks
- Test concurrent session handling
- Verify session invalidation on logout

### 4.5 URL Manipulation Testing

- Try accessing admin URLs directly
- Test forced browsing to restricted pages
- Manipulate parameters in URLs
- Test for information disclosure in error messages

## 5. Remediation to Prevent and Fix

### 5.1 Implement Proper Authorization

```java
// Example: Proper authorization check
@PreAuthorize("hasRole('ADMIN') or @userService.isOwner(#userId, principal.name)")
public User getUserData(@PathVariable Long userId) {
    return userService.findById(userId);
}
```

### 5.2 Use Centralized Access Control

```python
# Example: Centralized authorization service
class AuthorizationService:
    def can_access_resource(self, user, resource, action):
        # Check user permissions against resource and action
        user_roles = self.get_user_roles(user)
        required_permissions = self.get_required_permissions(resource, action)
        return self.has_permissions(user_roles, required_permissions)
```

### 5.3 Server-Side Enforcement

- Never rely on client-side access controls
- Validate all server-side operations
- Implement proper session management
- Use secure defaults (deny by default)

## 6. Prevention Best Practices

### 6.1 Design Principles

- **Principle of Least Privilege**: Users should have minimum necessary access
- **Fail Securely**: When access control fails, deny access by default
- **Complete Mediation**: Check permissions for every access request
- **Defense in Depth**: Multiple layers of access control

### 6.2 Implementation Guidelines

- Use proven access control frameworks
- Implement centralized authorization mechanisms
- Log all access control failures
- Regularly review and test access controls
- Implement proper CORS policies
- Use indirect object references when possible

### 6.3 Monitoring and Detection

- Monitor for unusual access patterns
- Alert on privilege escalation attempts
- Log all administrative actions
- Implement behavioral analysis
- Regular access control audits

## 7. Testing Tools and Techniques

### 7.1 Automated Tools

- **Burp Suite Professional**: Comprehensive web application security testing
- **OWASP ZAP**: Free security testing proxy
- **Postman**: API testing with authorization scenarios
- **Custom Scripts**: Automated IDOR and privilege escalation testing

### 7.2 Manual Testing Checklist

- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation
- [ ] Verify proper session management
- [ ] Test direct object references
- [ ] Check admin function access controls
- [ ] Verify proper logout functionality
- [ ] Test concurrent session handling
- [ ] Check for metadata manipulation vulnerabilities

## 8. Compliance and Standards

### 8.1 Regulatory Requirements

- **PCI DSS**: Requirement 7 - Restrict access to cardholder data by business need-to-know
- **HIPAA**: Administrative safeguards for access control
- **SOX**: Access controls for financial systems
- **GDPR**: Access controls for personal data processing

### 8.2 Industry Standards

- **ISO 27001**: Access control management
- **NIST Cybersecurity Framework**: Identity and Access Management
- **CIS Controls**: Account and Access Control Management

## 9. Code Examples and Fixes

### 9.1 Vulnerable Code Example

```php
// VULNERABLE: No authorization check
<?php
$user_id = $_GET['user_id'];
$user_data = get_user_data($user_id);
echo json_encode($user_data);
?>
```

### 9.2 Secure Code Example

```php
// SECURE: Proper authorization check
<?php
session_start();
$requested_user_id = $_GET['user_id'];
$current_user_id = $_SESSION['user_id'];
$current_user_role = $_SESSION['user_role'];

// Check if user can access this data
if ($current_user_role === 'admin' || $current_user_id === $requested_user_id) {
    $user_data = get_user_data($requested_user_id);
    echo json_encode($user_data);
} else {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized access']);
}
?>
```

## 10. References and Further Reading

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [NIST SP 800-162: Guide to Attribute Based Access Control](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)
