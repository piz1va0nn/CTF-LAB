# A05:2021 - Security Misconfiguration

## 1. What is the Vulnerability?

Security Misconfiguration occurs when security settings are not properly defined, implemented, or maintained, leaving applications and systems vulnerable to attacks. This includes missing security hardening, default configurations, incomplete setups, open cloud storage, verbose error messages, and missing security headers.

**Key Characteristics:**

- Default passwords and configurations still in use
- Missing security patches and updates
- Unnecessary features, services, or privileges enabled
- Error messages revealing sensitive information
- Missing or improper security headers
- Outdated or vulnerable software components
- Misconfigured cloud storage and services

## 2. Root Cause Analysis

**Primary Causes:**

- **Default Configurations**: Using default settings without security hardening
- **Missing Updates**: Failure to apply security patches and updates
- **Overprivileged Services**: Running services with unnecessary permissions
- **Information Disclosure**: Verbose error messages and directory listings
- **Missing Security Headers**: Lack of protective HTTP headers
- **Incomplete Installation**: Partially configured security controls
- **Poor Documentation**: Inadequate security configuration guides

**Technical Root Causes:**

- Lack of configuration management processes
- No security baseline or standards
- Insufficient security testing of configurations
- Manual configuration processes prone to errors
- Lack of configuration monitoring and validation
- Inadequate security training for system administrators

## 3. Real World Cases

### Case Study 1: Capital One Breach (2019)

- **Impact**: 100+ million customer records exposed
- **Cause**: Misconfigured Web Application Firewall (WAF) allowed SSRF attacks
- **Root Cause**: Overprivileged IAM roles and misconfigured security groups
- **Lesson**: Cloud configurations require careful security review and least privilege principles

### Case Study 2: MongoDB Exposures (2017-2019)

- **Impact**: Millions of databases exposed publicly
- **Cause**: Default MongoDB installations without authentication enabled
- **Root Cause**: Default "open" configuration and lack of security awareness
- **Lesson**: Default configurations should be secure, not convenient

### Case Study 3: Elasticsearch Data Leaks

- **Impact**: Billions of records exposed across multiple incidents
- **Cause**: Elasticsearch clusters configured without authentication
- **Root Cause**: Default open configuration and missing access controls
- **Lesson**: All services should require authentication by default

## 4. Manual Testing Methodology

### 4.1 Default Credentials Testing

```bash
# Test common default credentials
# Web applications
admin:admin
admin:password
admin:
root:root
user:user

# Databases
mysql: root:(blank)
postgres: postgres:postgres
mongodb: (no auth by default)

# Network devices
admin:admin
admin:cisco
admin:password123
```

### 4.2 Information Disclosure Testing

```bash
# Test for information disclosure
curl -I https://target.com/
# Look for Server headers revealing versions

# Test error messages
curl https://target.com/nonexistent-page
curl https://target.com/admin/
curl -X POST https://target.com/login -d "invalid=data"

# Test directory listings
curl https://target.com/uploads/
curl https://target.com/backup/
curl https://target.com/logs/
```

### 4.3 Security Headers Testing

```bash
# Test for missing security headers
curl -I https://target.com/

# Check for:
# - Content-Security-Policy
# - X-Frame-Options
# - X-Content-Type-Options
# - Strict-Transport-Security
# - Referrer-Policy
# - Permissions-Policy

# Online tools
# https://securityheaders.com/
# https://observatory.mozilla.org/
```

### 4.4 Configuration File Testing

```bash
# Common configuration files to test
/.env
/config.php
/web.config
/app.config
/.git/config
/WEB-INF/web.xml
/META-INF/MANIFEST.MF

# Test access to configuration files
curl https://target.com/.env
curl https://target.com/config/database.yml
curl https://target.com/.git/config
```

### 4.5 Service Enumeration

```bash
# Port scanning for unnecessary services
nmap -sV -sC target.com

# Common ports to check:
# 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP)
# 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP)
# 443 (HTTPS), 993 (IMAPS), 995 (POP3S)
# 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
```

## 5. Remediation to Prevent and Fix

### 5.1 Secure Configuration Baseline

```yaml
# Example: Secure nginx configuration
server {
    listen 443 ssl http2;
    server_name example.com;

    # SSL Configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Hide server version
    server_tokens off;

    # Disable unnecessary HTTP methods
    if ($request_method !~ ^(GET|HEAD|POST)$ ) {
        return 405;
    }

    # File upload restrictions
    client_max_body_size 10M;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 5.2 Database Security Configuration

```sql
-- MySQL secure configuration
-- Remove default accounts
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Create application-specific user
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_random_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'app_user'@'localhost';

-- Remove test database
DROP DATABASE IF EXISTS test;

-- Secure configuration options in my.cnf
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
skip-show-database
sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
```

### 5.3 Application Security Configuration

```python
# Example: Flask secure configuration
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Secure session configuration
app.config.update(
    SECRET_KEY='your-secret-key-here',  # Use strong random key
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# Security headers with Talisman
Talisman(app, {
    'force_https': True,
    'strict_transport_security': True,
    'strict_transport_security_max_age': 31536000,
    'content_security_policy': {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'"
    }
})

# Disable debug mode in production
if not app.debug:
    app.config['TESTING'] = False
    app.config['DEBUG'] = False
```

### 5.4 Cloud Security Configuration

```yaml
# Example: AWS Security Group (restrictive)
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 0.0.0.0/0
    Description: "HTTPS from anywhere"
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/8  # Only from internal network
    Description: "SSH from internal network only"

# S3 Bucket Policy (deny public access)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::your-bucket/*",
        "arn:aws:s3:::your-bucket"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalServiceName": [
            "cloudfront.amazonaws.com"
          ]
        }
      }
    }
  ]
}
```

### 5.5 Container Security Configuration

```dockerfile
# Secure Dockerfile practices
FROM node:16-alpine AS builder

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .

# Build application
RUN npm run build

# Production stage
FROM node:16-alpine AS runner

# Security updates
RUN apk update && apk upgrade

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app ./

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js

CMD ["npm", "start"]
```

## 6. Prevention Best Practices

### 6.1 Configuration Management

- **Infrastructure as Code**: Use tools like Terraform, Ansible, or CloudFormation
- **Configuration Baselines**: Establish and maintain security baselines
- **Automated Deployment**: Minimize manual configuration steps
- **Configuration Testing**: Test configurations in staging environments
- **Version Control**: Track all configuration changes
- **Regular Audits**: Periodic review of configurations

### 6.2 Security Hardening Process

```bash
#!/bin/bash
# Example: Linux server hardening script

# Update system packages
apt update && apt upgrade -y

# Remove unnecessary packages
apt autoremove -y
apt autoclean

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp
ufw --force enable

# Secure SSH configuration
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
systemctl reload ssh

# Set proper file permissions
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow

# Configure automatic updates
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
systemctl enable unattended-upgrades

# Install and configure fail2ban
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban
```

### 6.3 Monitoring and Compliance

- **Configuration Monitoring**: Detect configuration drift
- **Compliance Scanning**: Regular compliance checks
- **Change Management**: Formal process for configuration changes
- **Documentation**: Maintain configuration documentation
- **Training**: Security training for administrators
- **Incident Response**: Process for configuration-related incidents

## 7. Testing Tools and Techniques

### 7.1 Configuration Assessment Tools

```bash
# Nmap for service discovery
nmap -sV -sC -O target.com

# Nikto for web server scanning
nikto -h https://target.com

# SSLyze for SSL/TLS configuration
sslyze target.com

# Nessus/OpenVAS for vulnerability scanning
# Commercial/open-source vulnerability scanners
```

### 7.2 Cloud Security Tools

```bash
# AWS Security Tools
# Scout Suite - Multi-cloud security auditing
python scout.py aws

# Prowler - AWS security assessment
./prowler -c check_all

# CloudSploit - Cloud security monitoring
node index.js

# Azure Security Tools
# Azure Security Center
# Azure Policy compliance assessment
```

### 7.3 Container Security Tools

```bash
# Docker security scanning
docker scan image-name

# Trivy vulnerability scanner
trivy image image-name

# Anchore security analysis
anchore-cli image add image-name
anchore-cli image wait image-name
anchore-cli image vuln image-name all
```

### 7.4 Manual Testing Checklist

- [ ] Check for default credentials
- [ ] Verify security headers are present
- [ ] Test for information disclosure in errors
- [ ] Verify unnecessary services are disabled
- [ ] Check file and directory permissions
- [ ] Test SSL/TLS configuration
- [ ] Verify database security settings
- [ ] Check for exposed configuration files
- [ ] Test access controls and authentication
- [ ] Verify logging and monitoring configuration

## 8. Specific Technology Configurations

### 8.1 Apache HTTP Server Security

```apache
# Secure Apache configuration
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'"

# Hide Apache version
LoadModule headers_module modules/mod_headers.so
Header unset Server
Header set Server "Web Server"

# Disable unnecessary modules
# LoadModule autoindex_module modules/mod_autoindex.so  # Commented out
# LoadModule status_module modules/mod_status.so        # Commented out

# Directory security
<Directory />
    Options -Indexes -Includes -ExecCGI
    AllowOverride None
    Require all denied
</Directory>

# File access restrictions
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$">
    Require all denied
</FilesMatch>
```

### 8.2 IIS Security Configuration

```xml
<!-- Web.config security settings -->
<configuration>
  <system.web>
    <!-- Remove version headers -->
    <httpRuntime enableVersionHeader="false" />

    <!-- Custom errors -->
    <customErrors mode="RemoteOnly" defaultRedirect="~/Error/GenericError" />

    <!-- Session security -->
    <httpCookies httpOnlyCookies="true" requireSSL="true" lockItem="true" />

    <!-- Request validation -->
    <pages validateRequest="true" />
  </system.web>

  <system.webServer>
    <!-- Remove server header -->
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>

    <!-- Security headers -->
    <httpProtocol>
      <customHeaders>
        <add name="X-Frame-Options" value="DENY" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-XSS-Protection" value="1; mode=block" />
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
        <remove name="Server" />
      </customHeaders>
    </httpProtocol>

    <!-- HTTPS redirect -->
    <rewrite>
      <rules>
        <rule name="HTTPS Redirect" stopProcessing="true">
          <match url="." />
          <conditions>
            <add input="{HTTPS}" pattern="off" ignoreCase="true" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:0}"
                  redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
```

### 8.3 Docker Security Configuration

```yaml
# Docker Compose security configuration
version: '3.8'
services:
  web:
    image: nginx:alpine
    container_name: secure-web

    # Run as non-root user
    user: '1001:1001'

    # Read-only root filesystem
    read_only: true

    # No new privileges
    security_opt:
      - no-new-privileges:true

    # Drop all capabilities
    cap_drop:
      - ALL

    # Add only necessary capabilities
    cap_add:
      - CHOWN
      - SETGID
      - SETUID

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

    # Temporary filesystems for writable directories
    tmpfs:
      - /tmp
      - /var/cache/nginx
      - /var/run

    # Port mapping (avoid privileged ports)
    ports:
      - '8080:8080'

    # Environment variables (use secrets for sensitive data)
    environment:
      - NODE_ENV=production

    # Health check
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:8080/health']
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

## 9. Compliance and Standards

### 9.1 Regulatory Requirements

- **PCI DSS**: Requirement 2 - Do not use vendor-supplied defaults for system passwords and other security parameters
- **HIPAA**: Administrative safeguards for workstation and media controls
- **SOX**: IT general controls for system configuration
- **ISO 27001**: A.12.6 - Management of technical vulnerabilities
- **NIST**: Configuration management controls (CM family)

### 9.2 Security Benchmarks

- **CIS Benchmarks**: Configuration standards for various technologies
- **NIST SP 800-70**: Security configuration checklists
- **OWASP Secure Configuration Guide**: Web application security configurations
- **SANS Securing Web Application Technologies**: Web security configurations

## 10. Automated Configuration Management

### 10.1 Infrastructure as Code Example

```terraform
# Terraform AWS security configuration
resource "aws_security_group" "web" {
  name_prefix = "web-sg"
  vpc_id      = var.vpc_id

  # HTTPS only
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH from management network only
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-security-group"
  }
}

# S3 bucket with security configuration
resource "aws_s3_bucket" "app_data" {
  bucket = var.bucket_name

  tags = {
    Name        = "App Data Bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### 10.2 Ansible Configuration Management

```yaml
# Ansible playbook for secure configuration
---
- name: Secure Web Server Configuration
  hosts: webservers
  become: yes
  tasks:
    - name: Update all packages
      apt:
        upgrade: dist
        update_cache: yes

    - name: Install security packages
      apt:
        name:
          - fail2ban
          - ufw
          - unattended-upgrades
        state: present

    - name: Configure firewall
      ufw:
        rule: '{{ item.rule }}'
        port: '{{ item.port }}'
        proto: '{{ item.proto }}'
        state: enabled
      loop:
        - { rule: 'allow', port: '22', proto: 'tcp' }
        - { rule: 'allow', port: '443', proto: 'tcp' }
        - { rule: 'deny', port: '80', proto: 'tcp' }

    - name: Secure SSH configuration
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '{{ item.regexp }}'
        line: '{{ item.line }}'
        backup: yes
      loop:
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
        - {
            regexp: '^PasswordAuthentication',
            line: 'PasswordAuthentication no',
          }
        - { regexp: '^X11Forwarding', line: 'X11Forwarding no' }
      notify: restart ssh

    - name: Set file permissions
      file:
        path: '{{ item.path }}'
        mode: '{{ item.mode }}'
      loop:
        - { path: '/etc/ssh/sshd_config', mode: '0600' }
        - { path: '/etc/shadow', mode: '0640' }

  handlers:
    - name: restart ssh
      service:
        name: ssh
        state: restarted
```

## 11. Monitoring and Detection

### 11.1 Configuration Drift Detection

```python
# Example: Configuration monitoring script
import hashlib
import json
import smtplib
from email.mime.text import MimeText

class ConfigurationMonitor:
    def __init__(self, config_files):
        self.config_files = config_files
        self.baseline_hashes = {}

    def create_baseline(self):
        """Create baseline hashes for configuration files"""
        for file_path in self.config_files:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    file_hash = hashlib.sha256(content).hexdigest()
                    self.baseline_hashes[file_path] = file_hash
            except FileNotFoundError:
                print(f"Warning: {file_path} not found")

    def check_drift(self):
        """Check for configuration drift"""
        changes_detected = []

        for file_path in self.config_files:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    current_hash = hashlib.sha256(content).hexdigest()

                if current_hash != self.baseline_hashes.get(file_path):
                    changes_detected.append(file_path)

            except FileNotFoundError:
                changes_detected.append(f"{file_path} (deleted)")

        if changes_detected:
            self.alert_changes(changes_detected)

        return changes_detected

    def alert_changes(self, changed_files):
        """Send alert for configuration changes"""
        message = f"Configuration drift detected in: {', '.join(changed_files)}"
        print(f"ALERT: {message}")
        # Add email notification logic here
```

### 11.2 Automated Security Scanning

```bash
#!/bin/bash
# Automated security configuration scan

# Function to check SSL configuration
check_ssl() {
    echo "Checking SSL configuration..."
    testssl.sh --quiet --jsonfile-pretty ssl_results.json $1

    # Check for weak ciphers
    if grep -q "WEAK" ssl_results.json; then
        echo "WARNING: Weak SSL ciphers detected"
    fi
}

# Function to check security headers
check_headers() {
    echo "Checking security headers..."
    curl -I -s $1 | grep -E "(X-Frame-Options|Content-Security-Policy|X-Content-Type-Options)" || \
        echo "WARNING: Missing security headers"
}

# Function to check for default credentials
check_defaults() {
    echo "Checking for default credentials..."

    # Check common default login pages
    for path in "/admin" "/administrator" "/login" "/wp-admin"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" $1$path)
        if [ $response -eq 200 ]; then
            echo "WARNING: Admin interface accessible at $path"
        fi
    done
}

# Main execution
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

target=$1
echo "Security configuration scan for: $target"

check_ssl $target
check_headers $target
check_defaults $target

echo "Scan completed. Check results above for any warnings."
```
