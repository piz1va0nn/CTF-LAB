# A02:2021 - Cryptographic Failures

## 1. What is the Vulnerability?

Cryptographic Failures occur when applications fail to properly protect data through cryptography. This includes scenarios where data is transmitted or stored without encryption, weak cryptographic algorithms are used, or cryptographic functions are implemented incorrectly.

**Key Characteristics:**

- Sensitive data transmitted in clear text
- Use of weak or broken cryptographic algorithms
- Improper key management
- Missing encryption for sensitive data at rest
- Weak random number generation
- Certificate and TLS configuration issues

## 2. Root Cause Analysis

**Primary Causes:**

- **Missing Encryption**: No encryption for sensitive data in transit or at rest
- **Weak Algorithms**: Use of deprecated or weak cryptographic algorithms (MD5, SHA1, DES)
- **Poor Key Management**: Hardcoded keys, weak keys, or improper key storage
- **Implementation Flaws**: Incorrect use of cryptographic libraries
- **Configuration Issues**: Weak TLS configurations, accepting weak ciphers
- **Insufficient Entropy**: Poor random number generation for keys and tokens

**Technical Root Causes:**

- Lack of understanding of cryptographic best practices
- Using default configurations
- Legacy system constraints
- Performance concerns overriding security
- Inadequate threat modeling

## 3. Real World Cases

### Case Study 1: Adobe Password Breach (2013)

- **Impact**: 153 million user accounts compromised
- **Cause**: Passwords were encrypted with 3DES in ECB mode with same key, and password hints stored in plaintext
- **Lesson**: Proper password hashing (not encryption) and unique salts are essential

### Case Study 2: Heartbleed OpenSSL Bug (2014)

- **Impact**: Millions of websites vulnerable to memory disclosure
- **Cause**: Buffer over-read in OpenSSL TLS heartbeat extension
- **Lesson**: Cryptographic library vulnerabilities can have massive impact

## 4. Manual Testing Methodology

### 4.1 Traffic Analysis

```bash
# Capture network traffic
tcpdump -i any -w capture.pcap

# Analyze for unencrypted sensitive data
wireshark capture.pcap
# Look for: passwords, credit cards, PII in plaintext
```

### 4.2 TLS Configuration Testing

```bash
# Test SSL/TLS configuration
nmap --script ssl-enum-ciphers -p 443 target.com
openssl s_client -connect target.com:443 -cipher 'EXPORT'

# Test for weak protocols
openssl s_client -connect target.com:443 -ssl2
openssl s_client -connect target.com:443 -ssl3
```

These tests are used to evaluate the security of a server’s TLS/SSL configuration. The `nmap --script ssl-enum-ciphers` command lists which protocol versions and encryption ciphers the server supports, allowing you to identify weak or outdated options (such as TLS 1.0 or 40-bit ciphers). The `openssl s_client` commands then try to connect using very weak ciphers (`EXPORT`) and obsolete protocols (`SSLv2`, `SSLv3`) to check whether the server still accepts them.

If any of those connections are allowed, it means the server is misconfigured and supports insecure protocols/ciphers that attackers could exploit (e.g., downgrade attacks). A secure server should reject SSLv2/SSLv3 and export-grade ciphers, and only allow modern TLS versions (TLS 1.2 or above) with strong encryption.

### 4.3 Certificate Validation Testing

```bash
# Check certificate details
openssl s_client -connect target.com:443 -showcerts

# Test certificate validation
curl --insecure https://target.com  # Should fail with proper validation
curl https://expired.badssl.com/    # Test expired certificates
```

Thsse test is used to verify the correctness and trustworthiness of SSL/TLS certificates. it help identify issues like expired, self-signed, or improperly chained certificates, which could allow attackers to perform man-in-the-middle attacks if not properly validated.

### 4.4 Encryption Implementation Testing

- Test password storage mechanisms
- Analyze database encryption
- Check for hardcoded cryptographic keys
- Test random number generation quality
- Verify proper initialization vector usage

### 4.5 API Security Testing

```bash
# Test for encrypted API communications
curl -v https://api.example.com/sensitive-data
curl -v http://api.example.com/sensitive-data  # Should not work

# Test JWT token security
# Decode JWT tokens and check for sensitive information
echo "JWT_TOKEN" | base64 -d
```

- The first command connects via HTTPS to check that API data is encrypted in transit.
  
    The second command tries HTTP (unencrypted); if it works, the API is exposing sensitive data in plain text, which is insecure.

    This test ensures that all API traffic uses TLS/HTTPS.

- JWT (JSON Web Token) often contains Base64-encoded payloads.

    Decoding the token lets you inspect what information is inside, like user IDs, roles, or sensitive data.

    This test helps identify if tokens leak sensitive information that should not be exposed client-side.

## 5. Remediation to Prevent and Fix

### 5.1 Implement Strong Encryption

```python
# Example: Proper password hashing with bcrypt
import bcrypt

def hash_password(password):
    # Generate salt and hash password
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

This test demonstrates secure password hashing and verification using bcrypt, a widely used password hashing algorithm

### 5.2 Secure TLS Configuration

```nginx
# Example: Secure Nginx TLS configuration
server {
    listen 443 ssl http2;
    
    # Use strong protocols only
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Strong cipher suites
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Strong key exchange
    ssl_ecdh_curve secp384r1;
    ssl_dhparam /path/to/dhparam.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
}
```

### 5.3 Key Management

```python
# Example: Proper key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def derive_key(password: bytes, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Adjust based on performance requirements
    )
    
    return kdf.derive(password)
```

## 6. Prevention Best Practices

### 6.1 Cryptographic Standards

- Use proven cryptographic libraries (don't roll your own)
- Implement current standards (AES-256, RSA-2048+, SHA-256+)
- Regular cryptographic reviews and updates
- Follow NIST, OWASP, and industry guidelines

### 6.2 Key Management

- Never hardcode cryptographic keys
- Use proper key derivation functions
- Implement key rotation policies
- Secure key storage (HSM, key management services)
- Separate keys from encrypted data

### 6.3 Implementation Guidelines

- Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Implement proper random number generation
- Validate all cryptographic inputs
- Handle cryptographic errors securely
- Regular security assessments

## 7. Testing Tools and Techniques

### 7.1 Network Analysis Tools

- **Wireshark**: Network protocol analyzer
- **tcpdump**: Command-line packet analyzer  
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Security scanning proxy

### 7.2 TLS/SSL Testing Tools

- **SSL Labs SSL Test**: Online SSL configuration analyzer
- **testssl.sh**: Command-line SSL/TLS tester
- **SSLyze**: SSL configuration scanner
- **nmap**: Network discovery and security auditing

### 7.3 Cryptographic Analysis

- **hashcat**: Advanced password recovery
- **John the Ripper**: Password cracking tool
- **OpenSSL**: Cryptographic library and toolkit
- **Custom scripts**: For specific cryptographic testing

## 8. Compliance and Standards

### 8.1 Regulatory Requirements

- **PCI DSS**: Strong cryptography for cardholder data
- **HIPAA**: Encryption for PHI in transit and at rest
- **GDPR**: Appropriate technical measures including encryption
- **SOX**: Encryption for financial data integrity

### 8.2 Cryptographic Standards

- **FIPS 140-2**: US government cryptographic module standards
- **Common Criteria**: International security evaluation standards
- **NIST SP 800-57**: Key management guidelines
- **RFC 7525**: TLS implementation guidelines

## 9. Code Examples and Fixes

### 9.1 Vulnerable Code Examples

```php
// VULNERABLE: MD5 password hashing
$password_hash = md5($password);

// VULNERABLE: Hardcoded encryption key
$key = "mysecretkey12345";
$encrypted = openssl_encrypt($data, 'AES-128-CBC', $key);

// VULNERABLE: Weak random generation
$token = substr(str_shuffle("0123456789abcdef"), 0, 16);
```

### 9.2 Secure Code Examples

```php
// SECURE: Proper password hashing
$password_hash = password_hash($password, PASSWORD_ARGON2ID);

// SECURE: Proper key management and AES-GCM
$key = random_bytes(32); // Store securely, don't hardcode
$iv = random_bytes(12);
$encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

// SECURE: Cryptographically secure random generation
$token = bin2hex(random_bytes(16));
```

## 10. Monitoring and Detection

### 10.1 Security Monitoring

- Monitor for weak cipher usage
- Detect unencrypted sensitive data transmission
- Alert on certificate expiration and validation failures
- Track cryptographic library vulnerabilities

### 10.2 Automated Scanning

- Regular TLS/SSL configuration scans
- Database encryption verification
- Code analysis for cryptographic weaknesses
- Certificate lifecycle management

## 11. References and Further Reading

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST SP 800-175B: Guideline for Using Cryptographic Standards](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf)
- [RFC 7525: Recommendations for Secure Use of TLS](https://tools.ietf.org/html/rfc7525)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
  