# Web Application Security Assessment
## OWASP Top 10 Focused Report

**Target:** PortSwigger Academy - SQL injection vulnerability in WHERE clause  
**Lab URL:** `https://0a8b00f2049c8b5e82e4c7a5009300b2.web-security-academy.net/`  
**Date:** December 15, 2024  
**Tester:** Security Analyst  
**Duration:** 45 minutes

---

## Executive Summary

**Vulnerabilities Found:** 1 Total  
**Risk Breakdown:** 1 Critical | 0 High | 0 Medium | 0 Low

**Key Issues:**
- SQL injection in product category filter allows unauthorized data access

**Overall Risk:** 🔴 HIGH

---

## Scope and Methodology

### Test Scope
**In-Scope Targets:**
- Primary Lab URL: `https://0a8b00f2049c8b5e82e4c7a5009300b2.web-security-academy.net/`
- All web application endpoints and parameters
- Product filtering functionality

**Out-of-Scope:**
- Other PortSwigger Academy labs
- Infrastructure/network level testing
- Social engineering attacks
- Denial of Service testing

### Testing Methodology
**Standards and Frameworks:**
- OWASP Testing Guide v4.2
- OWASP Top 10 2021 categories
- Manual penetration testing approach

**Testing Phases:**
1. **Reconnaissance** - Application mapping and parameter identification
2. **Vulnerability Discovery** - SQL injection testing on identified parameters
3. **Exploitation** - Proof-of-concept development
4. **Impact Assessment** - Business and technical impact evaluation
5. **Documentation** - Finding documentation and remediation guidance

**Tools and Techniques:**
- Burp Suite Community Edition (request interception)
- Browser Developer Tools (response analysis)
- Manual payload crafting and testing
- Comparative analysis of application responses

---

## Findings Summary

### Vulnerability Statistics
**Total Findings:** 1  
**Risk Distribution:**
- 🔴 Critical: 1 finding (100%)
- 🟠 High: 0 findings (0%)
- 🟡 Medium: 0 findings (0%)
- 🔵 Low: 0 findings (0%)

### Finding Categories
| Category | Finding Type | Count |
|----------|--------------|-------|
| Input Validation | SQL Injection | 1 |
| Access Control | None identified | 0 |
| Authentication | None tested | 0 |
| Session Management | None tested | 0 |

### Business Impact Summary
The identified SQL injection vulnerability poses a **critical risk** to the application's data security and business logic integrity. Successful exploitation allows unauthorized access to hidden product information, potentially exposing sensitive business data and circumventing access controls.

---

## OWASP Top 10 Results

| Category | Finding | Risk | Status |
|----------|---------|------|---------|
| A01: Broken Access Control | Not tested | - | ❌ |
| A02: Cryptographic Failures | Not tested | - | ❌ |
| A03: Injection | SQL Injection in WHERE clause | 🔴 | ✅ |
| A04: Insecure Design | Not tested | - | ❌ |
| A05: Security Misconfiguration | Not tested | - | ❌ |
| A06: Vulnerable Components | Not tested | - | ❌ |
| A07: Authentication Failures | Not tested | - | ❌ |
| A08: Software/Data Integrity | Not tested | - | ❌ |
| A09: Logging/Monitoring | Not tested | - | ❌ |
| A10: SSRF | Not tested | - | ❌ |

---

## Detailed Findings

### 🔴 CRITICAL: SQL Injection in Product Filter
**OWASP Category:** A03 - Injection  
**CVSS Score:** 9.1 (Critical)  
**Location:** `https://[LAB-ID].web-security-academy.net/filter?category=Gifts`

**Description:**
The application's product category filter is vulnerable to SQL injection. The `category` parameter in the WHERE clause is not properly sanitized, allowing attackers to manipulate the SQL query structure. This enables retrieval of hidden products and potentially sensitive database information.

**Proof of Concept:**

**Original Request (Normal):**
```http
GET /filter?category=Gifts HTTP/2
Host: 0a8b00f2049c8b5e82e4c7a5009300b2.web-security-academy.net
Cookie: session=XqBq7bF2kM2hF8v3L9mN1pR5sT8uY4zA

```

**Malicious Request (SQL Injection):**
```http
GET /filter?category=Gifts'+OR+1=1-- HTTP/2
Host: 0a8b00f2049c8b5e82e4c7a5009300b2.web-security-academy.net
Cookie: session=XqBq7bF2kM2hF8v3L9mN1pR5sT8uY4zA

```

**Payload Analysis:**
- `Gifts'` - Closes the original string parameter
- `OR 1=1` - Always true condition that bypasses the WHERE filter  
- `--` - SQL comment to ignore remaining query

**Expected SQL Query Behavior:**
```sql
-- Original query (secure)
SELECT * FROM products WHERE category = 'Gifts' AND released = 1

-- Injected query (vulnerable)  
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
-- Everything after -- is commented out
```

**Impact:**
- **Data Exposure:** Access to unreleased/hidden products that should not be visible
- **Business Logic Bypass:** Circumvention of application access controls
- **Information Disclosure:** Potential access to sensitive product data, pricing, or inventory information

**Fix:**
- **Immediate:** Implement parameterized queries/prepared statements
- **Code Example (Secure):**
```java
// Vulnerable code
String query = "SELECT * FROM products WHERE category = '" + userInput + "' AND released = 1";

// Secure code  
String query = "SELECT * FROM products WHERE category = ? AND released = 1";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userInput);
```

**Evidence:**
*Normal category filter shows only 3 products*
![Normal Filter](evidence_normal.png)

*SQL injection payload reveals 4 products including hidden ones*
![SQL Injection Result](evidence_sqli.png)

---

## Quick Remediation Guide

### 🚨 Fix Immediately (Critical)
1. **SQL Injection in Category Filter** → Replace string concatenation with parameterized queries

### ⚠️ Fix This Week (High)
*No high-risk findings identified*

### 📋 Fix This Month (Medium/Low)
*No medium/low-risk findings identified*

---

## Security Testing Checklist

### ✅ Completed Tests
- [x] SQL Injection (A03) - WHERE clause manipulation
- [x] Boolean-based SQL injection
- [x] Comment-based payload testing
- [ ] XSS Testing (A03) - *Not applicable for this lab*
- [ ] Access Control (A01) - *Not tested in this lab*
- [ ] Authentication Bypass (A07) - *No auth in this lab*
- [ ] IDOR Testing (A01) - *Not applicable*
- [ ] Security Headers (A05) - *Not focused area*
- [ ] File Upload (A08) - *Not applicable*
- [ ] SSRF Testing (A10) - *Not applicable*

### 🔍 Testing Notes
**Tools Used:** Browser, Burp Suite Community, Manual Testing  
**Test Approach:** Black Box Testing  
**Key Techniques:** 
- Manual payload injection
- Boolean-based SQL injection
- SQL comment injection
- Response comparison analysis

**Testing Steps Performed:**
1. Identified parameter injection point (`category`)
2. Tested basic SQL metacharacters (`'` quote)  
3. Confirmed SQL injection with `OR 1=1` payload
4. Used `--` comment to ignore remaining query
5. Verified increased product count in response

---

## Lab Learning Summary

**Skills Practiced:**
- Manual SQL injection identification and exploitation
- WHERE clause manipulation techniques  
- Boolean-based SQL injection testing
- SQL comment injection (`--`) for query termination

**Key Takeaways:**
- Always test input parameters with SQL metacharacters first (`'`, `"`, `;`)
- The `OR 1=1` condition is effective for bypassing WHERE filters
- SQL comments (`--`, `/* */`) are crucial for ignoring unwanted query parts
- Comparing response differences helps confirm successful injection
- Even simple SQL injection can lead to significant data exposure

**Technical Learning:**
- Understanding how user input flows into SQL WHERE clauses
- Recognizing the difference between filtered and unfiltered results
- Importance of parameterized queries for prevention

**Next Steps:**
- Practice UNION-based SQL injection for data extraction
- Learn about time-based blind SQL injection techniques  
- Explore error-based SQL injection methods
- Study different database-specific injection techniques

**Difficulty Rating:** ⭐⭐☆☆☆ (Beginner)
**Time to Complete:** 15 minutes (after understanding concept)
**Lab Status:** ✅ SOLVED

---

## Conclusion

### Assessment Summary
This penetration test successfully identified a **critical SQL injection vulnerability** in the PortSwigger Academy lab application's product filtering functionality. The vulnerability allows unauthorized access to hidden product data through manipulation of the `category` parameter in the WHERE clause of the underlying SQL query.

### Key Findings Recap
- **Single Critical Finding:** SQL injection in product category filter
- **Attack Vector:** URL parameter manipulation (`category` parameter)
- **Impact Level:** HIGH - Unauthorized data access and business logic bypass
- **Exploitability:** HIGH - Simple payload, no authentication required
- **Lab Objective:** ✅ Successfully completed - Hidden products revealed

### Security Posture Assessment
The application demonstrates **poor input validation practices** typical of vulnerable web applications designed for educational purposes. The lack of parameterized queries and insufficient input sanitization creates a direct pathway for SQL injection attacks.

### Learning Outcomes Achieved
1. **Technical Skills Developed:**
   - Manual SQL injection identification and exploitation
   - Boolean-based SQL injection technique mastery
   - HTTP request manipulation and analysis
   - Comparative response analysis for vulnerability confirmation

2. **Security Concepts Reinforced:**
   - Understanding the relationship between user input and database queries
   - Recognition of SQL injection impact on business logic
   - Importance of secure coding practices (parameterized queries)
   - Risk assessment and business impact evaluation

### Laboratory Success Metrics
- ✅ **Vulnerability Identified:** SQL injection successfully discovered
- ✅ **Exploitation Achieved:** Hidden products successfully revealed
- ✅ **Impact Demonstrated:** Business logic bypass confirmed
- ✅ **Remediation Understood:** Secure coding solutions identified
- ✅ **Documentation Completed:** Professional report generated

### Professional Development Value
This exercise demonstrates proficiency in:
- **Manual Testing Techniques:** Hand-crafted payload development
- **Vulnerability Analysis:** Root cause identification and impact assessment  
- **Professional Reporting:** Industry-standard documentation practices
- **Risk Communication:** Technical findings translated to business impact

### Next Steps for Continued Learning
1. **Advanced SQL Injection Techniques:**
   - UNION-based data extraction
   - Blind SQL injection (time-based and boolean-based)
   - Error-based information disclosure

2. **Defense Techniques:**
   - Web Application Firewall (WAF) bypass methods
   - Secure coding review practices
   - Database security hardening

3. **Tool Proficiency:**
   - SQLMap automation tool usage
   - Advanced Burp Suite techniques
   - Custom script development for injection testing

### Compliance and Standards Alignment
This assessment aligns with:
- **OWASP Top 10 2021** - A03: Injection category
- **NIST Cybersecurity Framework** - Identify and Protect functions
- **ISO 27001** - Information security management practices
- **Industry Best Practices** - Secure software development lifecycle

**Lab Completion Status:** ✅ **SOLVED**  
**Skill Level Demonstrated:** Beginner to Intermediate  
**Time Investment:** 45 minutes (including documentation)  
**Knowledge Transfer:** Ready for practical application

---

*Assessment completed as part of OWASP Top 10 security training program*