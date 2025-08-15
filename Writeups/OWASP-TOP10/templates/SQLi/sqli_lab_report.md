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
PreparedStatement stmt = connection.prepareStatemen t(query);
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

*Report generated for OWASP Top 10 practice lab - SQL Injection module*