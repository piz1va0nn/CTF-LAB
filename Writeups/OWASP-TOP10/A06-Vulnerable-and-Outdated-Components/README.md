# A06:2021 - Vulnerable and Outdated Components

## 1. What is the Vulnerability?

Vulnerable and Outdated Components occur when applications use components (libraries, frameworks, modules) that have known security vulnerabilities. This includes both client-side and server-side components such as operating systems, web servers, database management systems, applications, APIs, runtime environments, and libraries.

**Key Characteristics:**

- Using components with known vulnerabilities (CVEs)
- Running outdated versions of software components
- Not regularly updating or patching components
- Using components from untrusted sources
- Not monitoring component security advisories
- Lack of inventory of components and their versions
- Using unnecessary or unused components

## 2. Root Cause Analysis

**Primary Causes:**

- **Lack of Inventory**: No comprehensive list of components and versions
- **Missing Updates**: Failure to apply security patches promptly
- **Legacy Dependencies**: Old components that are no longer maintained
- **Supply Chain Issues**: Compromised or malicious components
- **Resource Constraints**: Limited time/resources for maintenance
- **Complex Dependencies**: Deep dependency trees making updates difficult
- **Risk Assessment Gaps**: Not evaluating component security risks

**Technical Root Causes:**

- Manual dependency management processes
- No automated vulnerability scanning
- Insufficient testing of updates
- Fear of breaking changes when updating
- Lack of component security policies
- No Software Bill of Materials (SBOM)

## 3. Real World Cases

### Case Study 1: Log4Shell (2021)

- **Impact**: Millions of applications worldwide affected
- **Cause**: Remote code execution in Apache Log4j library (CVE-2021-44228)
- **Root Cause**: Widely-used logging library with critical vulnerability
- **Lesson**: Even common utility libraries can have severe vulnerabilities

### Case Study 2: SolarWinds Supply Chain Attack (2020)

- **Impact**: 18,000+ organizations compromised
- **Cause**: Malicious code inserted into legitimate software updates
- **Root Cause**: Compromised build process in the software supply chain
- **Lesson**: Supply chain security is critical for component integrity

## 4. Manual Testing Methodology

### 4.1 Component Version Discovery

```bash
# Web server version detection
curl -I https://target.com | grep -i server
nmap -sV target.com

# CMS and framework detection
whatweb https://target.com
wappalyzer https://target.com

# JavaScript library detection
# View page source and check for:
# - jquery-1.8.3.min.js (outdated jQuery)
# - bootstrap-3.0.0.css (outdated Bootstrap)
# - angular-1.2.0.js (outdated AngularJS)

# Check common paths for version info
curl https://target.com/package.json
curl https://target.com/composer.json
curl https://target.com/pom.xml
```

### 4.2 Vulnerability Database Lookup

```bash
# Check CVE databases for discovered versions
# National Vulnerability Database: https://nvd.nist.gov/
# CVE Details: https://www.cvedetails.com/
# Snyk Vulnerability Database: https://snyk.io/vuln/

# Example searches:
# "Apache Struts 2.3.32 vulnerabilities"
# "jQuery 1.8.3 CVE"
# "WordPress 4.9.6 security"

# Automated CVE checking tools
cve-search.py --product "Apache Struts" --version "2.3.32"
```

### 4.3 Dependency Analysis

```bash
# Node.js dependency checking
npm audit
npm audit --audit-level moderate

# Python dependency checking
pip-audit
safety check

# Java dependency checking
mvn dependency:tree
mvn org.owasp:dependency-check-maven:check

# Ruby dependency checking
bundle-audit

# PHP dependency checking
composer audit
```

### 4.4 Client-Side Component Testing

```javascript
// Browser console checks for vulnerable components
// Check jQuery version
if (typeof jQuery !== 'undefined') {
  console.log('jQuery version:', jQuery.fn.jquery);
}

// Check Angular version
if (typeof angular !== 'undefined') {
  console.log('Angular version:', angular.version.full);
}

// Check React version
if (typeof React !== 'undefined') {
  console.log('React version:', React.version);
}

// Check for known vulnerable patterns
// Look for old CDN links in HTML source:
// https://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js
```

### 4.5 Infrastructure Component Testing

```bash
# Operating system version
cat /etc/os-release
uname -a

# Web server version
apache2 -v
nginx -v

# Database version
mysql --version
psql --version

# Runtime versions
php --version
python --version
node --version
java -version

# Check for EOL (End of Life) versions
# https://endoflife.date/
```

## 5. Remediation to Prevent and Fix

### 5.1 Component Inventory Management

```python
# Example: Software Bill of Materials (SBOM) generator
import json
import subprocess
import requests
from datetime import datetime

class ComponentInventory:
    def __init__(self):
        self.components = []
        self.vulnerability_db = "https://api.osv.dev/v1/query"

    def scan_npm_dependencies(self, package_path):
        """Scan Node.js dependencies"""
        try:
            result = subprocess.run(['npm', 'list', '--json'],
                                  capture_output=True, text=True, cwd=package_path)
            if result.returncode == 0:
                deps = json.loads(result.stdout)
                self._process_npm_deps(deps.get('dependencies', {}))
        except Exception as e:
            print(f"Error scanning npm dependencies: {e}")

    def scan_python_dependencies(self):
        """Scan Python dependencies"""
        try:
            result = subprocess.run(['pip', 'freeze'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '==' in line:
                        name, version = line.split('==')
                        self._add_component(name.strip(), version.strip(), 'python')
        except Exception as e:
            print(f"Error scanning Python dependencies: {e}")

    def _add_component(self, name, version, ecosystem):
        """Add component to inventory"""
        component = {
            'name': name,
            'version': version,
            'ecosystem': ecosystem,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self._check_vulnerabilities(name, version, ecosystem)
        }
        self.components.append(component)

    def _check_vulnerabilities(self, name, version, ecosystem):
        """Check for known vulnerabilities"""
        try:
            query = {
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version
            }
            response = requests.post(self.vulnerability_db, json=query)
            if response.status_code == 200:
                return response.json().get('vulns', [])
        except Exception as e:
            print(f"Error checking vulnerabilities for {name}: {e}")
        return []

    def generate_report(self):
        """Generate vulnerability report"""
        vulnerable_components = [c for c in self.components if c['vulnerabilities']]

        print(f"Total components: {len(self.components)}")
        print(f"Vulnerable components: {len(vulnerable_components)}")

        for component in vulnerable_components:
            print(f"\n{component['name']} {component['version']}:")
            for vuln in component['vulnerabilities']:
                print(f"  - {vuln.get('id', 'Unknown')}: {vuln.get('summary', 'No summary')}")
```

### 5.2 Automated Dependency Updates

```yaml
# GitHub Dependabot configuration (.github/dependabot.yml)
version: 2
updates:
  - package-ecosystem: 'npm'
    directory: '/'
    schedule:
      interval: 'weekly'
    open-pull-requests-limit: 10
    reviewers:
      - 'security-team'
    commit-message:
      prefix: 'security'
      prefix-development: 'dev'

  - package-ecosystem: 'pip'
    directory: '/'
    schedule:
      interval: 'weekly'

  - package-ecosystem: 'maven'
    directory: '/'
    schedule:
      interval: 'weekly'

  - package-ecosystem: 'docker'
    directory: '/'
    schedule:
      interval: 'weekly'
```

### 5.3 Vulnerability Scanning Pipeline

````yaml
# CI/CD Pipeline with vulnerability scanning
name: Security Scan
on: [push, pull_request]

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'

      - name: Install dependencies
        run: npm ci

      - name: Run npm audit
        run: npm audit --audit-level moderate

      - name: Run Snyk vulnerability scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

      - name: Run OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'test'
          path: '.'
          format: 'HTML'

      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: Dependency-Check-Report
### 5.4 Component Update Strategy
```bash
#!/bin/bash
# Safe component update strategy

# 1. Create backup
git checkout -b update-dependencies-$(date +%Y%m%d)

# 2. Update patch versions first (safest)
npm update  # Updates to latest patch versions

# 3. Check for security vulnerabilities
npm audit

# 4. Run automated tests
npm test

# 5. Manual testing in staging environment
echo "Deploy to staging and perform manual testing"

# 6. Update minor versions if tests pass
npm install package@^2.1.0  # Allow patch updates in 2.1.x

# 7. Update major versions with caution
# Read changelog first!
npm install package@3.0.0

# 8. Document changes
echo "Updated dependencies:" >> CHANGELOG.md
npm list --depth=0 >> CHANGELOG.md
````

### 5.5 Container Image Security

```dockerfile
# Secure base image practices
# Use specific versions, not 'latest'
FROM node:16.17.0-alpine3.16

# Update packages and remove package manager cache
RUN apk update && \
    apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies with security audit
RUN npm ci --only=production && \
    npm audit --audit-level moderate && \
    npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .

# Switch to non-root user
USER nextjs

# Use init system
ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "start"]
```

## 6. Prevention Best Practices

### 6.1 Component Lifecycle Management

- **Inventory Management**: Maintain comprehensive component inventory
- **Version Pinning**: Use specific versions rather than ranges
- **Regular Updates**: Establish update schedules and procedures
- **End-of-Life Monitoring**: Track EOL dates for components
- **Security Monitoring**: Subscribe to security advisories
- **Testing Strategy**: Comprehensive testing of updates

### 6.2 Supply Chain Security

```python
# Example: Package integrity verification
import hashlib
import requests
import json

class PackageVerifier:
    def __init__(self):
        self.known_hashes = {}  # Load from trusted source

    def verify_npm_package(self, package_name, version):
        """Verify npm package integrity"""
        # Download package metadata
        url = f"https://registry.npmjs.org/{package_name}/{version}"
        response = requests.get(url)

        if response.status_code == 200:
            metadata = response.json()

            # Check if package has known vulnerabilities
            if 'dist' in metadata and 'integrity' in metadata['dist']:
                return self._verify_integrity(metadata['dist']['integrity'])

        return False

    def _verify_integrity(self, integrity_hash):
        """Verify package integrity hash"""
        # Implement integrity verification logic
        # Compare against known good hashes
        return True  # Simplified example

    def check_package_reputation(self, package_name):
        """Check package reputation and maintainer info"""
        checks = {
            'active_maintenance': self._check_recent_updates(package_name),
            'download_count': self._check_popularity(package_name),
            'maintainer_reputation': self._check_maintainers(package_name),
            'security_history': self._check_vulnerability_history(package_name)
        }
        return checks
```

### 6.3 Automated Security Controls

- **Dependency Scanning**: Integrate into CI/CD pipelines
- **License Compliance**: Check for compatible licenses
- **Malware Detection**: Scan for malicious code
- **Policy Enforcement**: Block known vulnerable components
- **SBOM Generation**: Generate Software Bill of Materials
- **Continuous Monitoring**: Real-time vulnerability monitoring

## 7. Testing Tools and Techniques

### 7.1 Open Source Vulnerability Scanners

```bash
# OWASP Dependency Check
dependency-check.sh --project "MyApp" --scan /path/to/project

# Snyk CLI
snyk test
snyk monitor  # Continuous monitoring

# Safety (Python)
safety check
safety check --json

# Bundler Audit (Ruby)
bundle-audit check --update

# Retire.js (JavaScript)
retire --js --outputformat json

# OSV Scanner (Multi-language)
osv-scanner --lockfile package-lock.json
```

### 7.2 Commercial Security Tools

```yaml
# Integration examples
# Veracode SCA
- name: Veracode Upload and Scan
  uses: veracode/veracode-uploadandscan-action@v1
  with:
    appname: 'MyApp'
    createprofile: false
    filepath: 'target/myapp.jar'

# WhiteSource (Mend)
- name: WhiteSource Security Scan
  uses: whitesource/ws-action@v1
  with:
    apiKey: ${{ secrets.WS_API_KEY }}
    productName: 'MyProduct'

# Checkmarx SCA
- name: Checkmarx SCA Scan
  uses: checkmarx/sca-github-action@v1
  with:
    username: ${{ secrets.CX_USER }}
    password: ${{ secrets.CX_PASSWORD }}
```

### 7.3 Container Security Scanning

```bash
# Docker Scout
docker scout cves image-name:tag

# Trivy
trivy image image-name:tag
trivy fs /path/to/project

# Clair
clairctl analyze image-name:tag

# Anchore Engine
anchore-cli image add image-name:tag
anchore-cli image vuln image-name:tag all

# Grype
grype image-name:tag
```

### 7.4 Manual Testing Checklist

- [ ] Identify all components and their versions
- [ ] Check for known CVEs in identified versions
- [ ] Verify components are from trusted sources
- [ ] Check for end-of-life components
- [ ] Test component update procedures
- [ ] Verify component integrity (checksums, signatures)
- [ ] Check for unused or unnecessary components
- [ ] Review component licenses for compatibility
- [ ] Test application functionality after updates
- [ ] Verify security configurations of components

## 8. Vulnerability Management Process

### 8.1 Vulnerability Response Workflow

```python
# Example: Automated vulnerability response system
import json
import smtplib
from enum import Enum
from datetime import datetime, timedelta

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class VulnerabilityManager:
    def __init__(self):
        self.sla_times = {
            Severity.CRITICAL: timedelta(hours=24),
            Severity.HIGH: timedelta(days=7),
            Severity.MEDIUM: timedelta(days=30),
            Severity.LOW: timedelta(days=90)
        }

    def process_vulnerability(self, vuln_data):
        """Process newly discovered vulnerability"""
        vulnerability = {
            'cve_id': vuln_data.get('id'),
            'component': vuln_data.get('package'),
            'version': vuln_data.get('version'),
            'severity': Severity(vuln_data.get('severity', 'medium')),
            'description': vuln_data.get('summary'),
            'discovered_date': datetime.now(),
            'due_date': self._calculate_due_date(vuln_data.get('severity')),
            'status': 'open'
        }

        # Prioritize based on severity and exposure
        priority = self._calculate_priority(vulnerability)

        # Create tracking ticket
        ticket_id = self._create_ticket(vulnerability, priority)

        # Send notifications
        self._send_notifications(vulnerability, ticket_id)

        return ticket_id

    def _calculate_due_date(self, severity):
        """Calculate remediation due date based on severity"""
        sla_time = self.sla_times.get(Severity(severity), timedelta(days=30))
        return datetime.now() + sla_time

    def _calculate_priority(self, vulnerability):
        """Calculate priority based on multiple factors"""
        base_priority = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25
        }.get(vulnerability['severity'], 50)

        # Adjust based on exposure (internet-facing, etc.)
        if self._is_internet_facing(vulnerability['component']):
            base_priority += 25

        # Adjust based on exploit availability
        if self._has_public_exploit(vulnerability['cve_id']):
            base_priority += 20

        return min(base_priority, 100)
```

### 8.2 Patch Management Strategy

```bash
#!/bin/bash
# Patch management automation

ENVIRONMENT=$1
COMPONENT=$2
NEW_VERSION=$3

if [ $# -ne 3 ]; then
    echo "Usage: $0 <environment> <component> <new_version>"
    exit 1
fi

# Function to backup current state
backup_environment() {
    echo "Creating backup of $ENVIRONMENT environment..."
    # Implementation specific backup commands
    kubectl create backup $ENVIRONMENT-$(date +%Y%m%d-%H%M%S)
}

# Function to deploy update
deploy_update() {
    echo "Deploying $COMPONENT version $NEW_VERSION to $ENVIRONMENT..."

    case $ENVIRONMENT in
        "dev")
            # Direct deployment to dev
            update_component $COMPONENT $NEW_VERSION
            ;;
        "staging")
            # Canary deployment to staging
            deploy_canary $COMPONENT $NEW_VERSION 10%
            ;;
        "production")
            # Blue-green deployment to production
            deploy_blue_green $COMPONENT $NEW_VERSION
            ;;
    esac
}

# Function to run security tests
run_security_tests() {
    echo "Running security tests..."

    # Vulnerability scan
    trivy image app:$NEW_VERSION

    # Functional security tests
    ./security-tests.sh $ENVIRONMENT

    # Performance impact assessment
    ./performance-tests.sh $ENVIRONMENT
}

# Function to rollback if needed
rollback_if_needed() {
    if [ $? -ne 0 ]; then
        echo "Tests failed, rolling back..."
        rollback_deployment $COMPONENT
        exit 1
    fi
}

# Main execution
echo "Starting patch deployment process..."

backup_environment
deploy_update
sleep 60  # Allow time for deployment
run_security_tests
rollback_if_needed

echo "Patch deployment completed successfully"
```

## 9. Component Security Policies

### 9.1 Approved Component List

```json
{
  "approved_components": {
    "javascript": {
      "react": {
        "approved_versions": [">=17.0.0", "<19.0.0"],
        "security_notes": "Versions below 17.0.0 have known XSS vulnerabilities"
      },
      "lodash": {
        "approved_versions": [">=4.17.21"],
        "security_notes": "Versions below 4.17.21 have prototype pollution vulnerabilities"
      },
      "jquery": {
        "approved_versions": [">=3.5.0"],
        "security_notes": "Versions below 3.5.0 have multiple XSS vulnerabilities",
        "alternatives": ["vanilla-js", "modern-dom-apis"]
      }
    },
    "python": {
      "django": {
        "approved_versions": [">=3.2.0", "<5.0.0"],
        "security_notes": "LTS versions recommended for production"
      },
      "requests": {
        "approved_versions": [">=2.25.0"],
        "security_notes": "Earlier versions have SSL verification issues"
      }
    }
  },
  "banned_components": [
    {
      "name": "eval",
      "reason": "Dynamic code execution security risk"
    },
    {
      "name": "serialize-javascript",
      "versions": ["<3.1.0"],
      "reason": "XSS vulnerability in earlier versions"
    }
  ],
  "security_requirements": {
    "minimum_maintenance_activity": "6 months",
    "required_security_contact": true,
    "vulnerability_disclosure_process": true,
    "code_signing_required": false
  }
}
```

### 9.2 License Compliance Policy

```python
# Example: License compliance checker
import json
import requests
from typing import List, Dict

class LicenseChecker:
    def __init__(self):
        self.approved_licenses = [
            'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause',
            'ISC', 'MPL-2.0'
        ]
        self.copyleft_licenses = [
            'GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0',
            'AGPL-3.0'
        ]
        self.commercial_restricted = [
            'CC-BY-NC', 'SSPL-1.0'
        ]

    def check_package_licenses(self, package_file: str) -> Dict:
        """Check licenses for all packages"""
        results = {
            'approved': [],
            'copyleft': [],
            'commercial_restricted': [],
            'unknown': [],
            'violations': []
        }

        # Parse package file (npm, pip, etc.)
        packages = self._parse_package_file(package_file)

        for package in packages:
            license_info = self._get_license_info(package)
            self._categorize_license(license_info, results)

        return results

    def _get_license_info(self, package: Dict) -> Dict:
        """Get license information for a package"""
        # Implementation varies by package ecosystem
        if package['ecosystem'] == 'npm':
            return self._get_npm_license(package['name'])
        elif package['ecosystem'] == 'python':
            return self._get_python_license(package['name'])

        return {'license': 'Unknown'}

    def _categorize_license(self, license_info: Dict, results: Dict):
        """Categorize license based on policy"""
        license_name = license_info.get('license', 'Unknown')
        package_name = license_info.get('package', 'Unknown')

        if license_name in self.approved_licenses:
            results['approved'].append(license_info)
        elif license_name in self.copyleft_licenses:
            results['copyleft'].append(license_info)
            results['violations'].append(f"{package_name}: Copyleft license requires legal review")
        elif license_name in self.commercial_restricted:
            results['commercial_restricted'].append(license_info)
            results['violations'].append(f"{package_name}: Commercial use restricted")
        else:
            results['unknown'].append(license_info)
            results['violations'].append(f"{package_name}: Unknown license requires review")
```

## 10. Metrics and KPIs

### 10.1 Component Security Metrics

```python
# Example: Component security metrics dashboard
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

class ComponentMetrics:
    def __init__(self, vulnerability_data):
        self.vulnerability_data = vulnerability_data

    def calculate_metrics(self):
        """Calculate key security metrics"""
        metrics = {
            'total_components': self._count_total_components(),
            'vulnerable_components': self._count_vulnerable_components(),
            'critical_vulnerabilities': self._count_by_severity('critical'),
            'high_vulnerabilities': self._count_by_severity('high'),
            'mean_time_to_patch': self._calculate_mttp(),
            'outdated_components': self._count_outdated_components(),
            'eol_components': self._count_eol_components(),
            'patch_compliance_rate': self._calculate_patch_compliance()
        }

        return metrics

    def _calculate_mttp(self):
        """Calculate Mean Time To Patch"""
        patch_times = []

        for vuln in self.vulnerability_data:
            if vuln.get('patched_date') and vuln.get('discovered_date'):
                discovery = datetime.fromisoformat(vuln['discovered_date'])
                patch = datetime.fromisoformat(vuln['patched_date'])
                patch_time = (patch - discovery).total_seconds()
                patch_times.append(patch_time)

        if patch_times:
            return sum(patch_times) / len(patch_times) / 3600  # Convert to hours
        return 0

    def _calculate_patch_compliance(self):
        """Calculate patch compliance rate based on SLA"""
        total_vulns = len(self.vulnerability_data)
        if total_vulns == 0:
            return 100

        compliant_vulns = 0
        for vuln in self.vulnerability_data:
            if self._is_patched_within_sla(vuln):
                compliant_vulns += 1

        return (compliant_vulns / total_vulns) * 100

    def generate_report(self):
        """Generate security metrics report"""
        metrics = self.calculate_metrics()

        report = f"""
Component Security Metrics Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total Components: {metrics['total_components']}
Vulnerable Components: {metrics['vulnerable_components']}
Critical Vulnerabilities: {metrics['critical_vulnerabilities']}
High Vulnerabilities: {metrics['high_vulnerabilities']}
Mean Time to Patch: {metrics['mean_time_to_patch']:.2f} hours
Outdated Components: {metrics['outdated_components']}
End-of-Life Components: {metrics['eol_components']}
Patch Compliance Rate: {metrics['patch_compliance_rate']:.2f}%

Risk Assessment:
{self._generate_risk_assessment(metrics)}
        """

        return report
```

### 10.2 Compliance Reporting

- **MTTR (Mean Time To Remediation)**: Average time to fix vulnerabilities
- **Patch Coverage**: Percentage of systems with latest security patches
- **Component Freshness**: Age of components compared to latest versions
- **Vulnerability Exposure Time**: Time vulnerabilities remain unpatched
- **Risk Score**: Weighted score based on vulnerabilities and exposure
- **Compliance Rate**: Adherence to security policies and SLAs

## 11. Integration with DevSecOps

### 11.1 Security Gates in CI/CD

```yaml
# Example: Security gates in GitLab CI
stages:
  - build
  - security-scan
  - test
  - deploy

dependency-check:
  stage: security-scan
  script:
    - dependency-check.sh --project "MyApp" --scan .
    - python check_results.py dependency-check-report.xml
  artifacts:
    reports:
      junit: dependency-check-junit.xml
  allow_failure: false # Fail build on high/critical vulnerabilities

container-scan:
  stage: security-scan
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - trivy image --exit-code 1 --severity HIGH,CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  dependencies:
    - build

license-check:
  stage: security-scan
  script:
    - license-checker --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC'
  allow_failure: false
```

### 11.2 Automated Remediation

```python
# Example: Automated dependency update bot
import subprocess
import json
from github import Github

class AutoUpdateBot:
    def __init__(self, github_token, repo_name):
        self.github = Github(github_token)
        self.repo = self.github.get_repo(repo_name)

    def check_and_update_dependencies(self):
        """Check for dependency updates and create PRs"""
        vulnerabilities = self._scan_dependencies()

        for vuln in vulnerabilities:
            if self._should_auto_update(vuln):
                self._create_update_pr(vuln)

    def _should_auto_update(self, vulnerability):
        """Determine if vulnerability should be auto-updated"""
        criteria = [
            vulnerability.get('severity') in ['HIGH', 'CRITICAL'],
            vulnerability.get('fix_available', False),
            vulnerability.get('breaking_changes', True) == False,
            vulnerability.get('confidence', 0) > 0.8
        ]

        return all(criteria)

    def _create_update_pr(self, vulnerability):
        """Create pull request for dependency update"""
        branch_name = f"security-update-{vulnerability['component']}"

        # Create branch
        base_branch = self.repo.get_branch('main')
        self.repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=base_branch.commit.sha
        )

        # Update dependency file
        self._update_dependency_file(vulnerability, branch_name)

        # Create PR
        pr_title = f"Security update: {vulnerability['component']} to {vulnerability['fix_version']}"
        pr_body = self._generate_pr_body(vulnerability)

        self.repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base='main',
            maintainer_can_modify=True
        )
```

## 12. References and Further Reading

- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)
- [GitHub Security Advisories](https://github.com/advisories)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [NIST SSDF: Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [CWE-1035: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [End of Life Software Tracking](https://endoflife.date/)
