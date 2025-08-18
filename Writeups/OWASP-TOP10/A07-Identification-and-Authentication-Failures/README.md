# A07:2021 - Identification and Authentication Failures

## 1. What is the Vulnerability?

Identification and Authentication Failures occur when applications fail to properly verify the identity of users, or when authentication mechanisms are implemented incorrectly. This includes weak password policies, credential stuffing, brute force attacks, session management issues, and missing multi-factor authentication.

**Key Characteristics:**

- Weak password requirements and policies
- Credential stuffing and brute force attack vulnerabilities
- Missing or weak multi-factor authentication (MFA)
- Insecure session management
- Password recovery and reset vulnerabilities
- Missing account lockout mechanisms
- Credential exposure in URLs, logs, or code

## 2. Root Cause Analysis

**Primary Causes:**

- **Weak Password Policies**: Allowing simple, common, or easily guessable passwords
- **Missing Rate Limiting**: No protection against brute force attacks
- **Insecure Session Management**: Poor session token generation, storage, or validation
- **Credential Stuffing Vulnerability**: No protection against automated credential testing
- **Missing MFA**: Single-factor authentication for sensitive operations
- **Insecure Password Storage**: Plain text or weakly hashed passwords
- **Poor Account Recovery**: Insecure password reset mechanisms

**Technical Root Causes:**

- Inadequate understanding of authentication best practices
- Legacy authentication systems
- Performance concerns overriding security
- Insufficient threat modeling for authentication flows
- Lack of centralized authentication mechanisms
- Missing security monitoring for authentication events

## 3. Real World Cases

### Case Study 1: Twitter Bitcoin Hack (2020)

- **Impact**: High-profile accounts compromised, $100K+ in Bitcoin stolen
- **Cause**: Social engineering attack combined with weak internal authentication
- **Root Cause**: Insufficient authentication controls for administrative access
- **Lesson**: Internal systems need strong authentication controls

### Case Study 2: Yahoo Data Breaches (2013-2014)

- **Impact**: 3 billion user accounts compromised
- **Cause**: Weak password hashing (MD5) and security questions
- **Root Cause**: Outdated authentication mechanisms and weak cryptography
- **Lesson**: Strong password hashing and additional authentication factors are essential

### Case Study 3: Microsoft Exchange Server Attacks (2021)

- **Impact**: 250,000+ servers compromised worldwide
- **Cause**: Authentication bypass vulnerabilities in Exchange Server
- **Root Cause**: Flawed authentication validation in web applications
- **Lesson**: Authentication logic must be thoroughly tested and validated

## 4. Manual Testing Methodology

### 4.1 Password Policy Testing

```bash
# Test weak password acceptance
curl -X POST https://target.com/register \
  -d "username=test&password=123&email=test@example.com"

curl -X POST https://target.com/register \
  -d "username=test&password=password&email=test@example.com"

curl -X POST https://target.com/register \
  -d "username=test&password=qwerty&email=test@example.com"

# Test password length limits
curl -X POST https://target.com/register \
  -d "username=test&password=a&email=test@example.com"  # Too short

curl -X POST https://target.com/register \
  -d "username=test&password=$(python -c 'print("a"*1000)')&email=test@example.com"  # Too long
```

### 4.2 Brute Force Testing

```python
# Automated brute force testing
import requests
import time

def brute_force_login(target_url, username, password_list):
    session = requests.Session()

    for password in password_list:
        data = {
            'username': username,
            'password': password
        }

        response = session.post(target_url + '/login', data=data)

        # Check for rate limiting
        if response.status_code == 429:
            print("Rate limiting detected")
            time.sleep(60)
            continue

        # Check for successful login
        if 'dashboard' in response.text or response.status_code == 302:
            print(f"Success: {username}:{password}")
            return True

        # Check for account lockout
        if 'account locked' in response.text.lower():
            print("Account lockout detected")
            break

        time.sleep(1)  # Avoid overwhelming the server

    return False

# Common passwords list
common_passwords = [
    'password', '123456', 'password123', 'admin', 'qwerty',
    'letmein', 'welcome', '123456789', 'password1', 'abc123'
]

brute_force_login('https://target.com', 'admin', common_passwords)
```

### 4.3 Session Management Testing

```bash
# Test session fixation
# 1. Get session ID before login
curl -I https://target.com/login
# Note: JSESSIONID=ABC123

# 2. Login with fixed session
curl -X POST https://target.com/login \
  -H "Cookie: JSESSIONID=ABC123" \
  -d "username=admin&password=password"

# 3. Check if session ID changed after login
curl -I https://target.com/dashboard \
  -H "Cookie: JSESSIONID=ABC123"

# Test session timeout
curl -H "Cookie: JSESSIONID=VALID_SESSION" https://target.com/dashboard
# Wait 30+ minutes
curl -H "Cookie: JSESSIONID=VALID_SESSION" https://target.com/dashboard

# Test concurrent sessions
# Login from multiple locations with same credentials
curl -X POST https://target.com/login -d "username=user&password=pass"
# Login again from different IP/browser
curl -X POST https://target.com/login -d "username=user&password=pass" \
  -H "User-Agent: Different-Browser"
```

### 4.4 Multi-Factor Authentication Testing

```bash
# Test MFA bypass attempts
# 1. Normal login to trigger MFA
curl -X POST https://target.com/login \
  -d "username=user&password=validpass"

# 2. Try to access protected resources without MFA
curl -H "Cookie: session=partial_auth" https://target.com/dashboard

# 3. Test MFA token reuse
curl -X POST https://target.com/verify-mfa \
  -H "Cookie: session=partial_auth" \
  -d "mfa_token=123456"

# Use same token again
curl -X POST https://target.com/verify-mfa \
  -H "Cookie: session=partial_auth" \
  -d "mfa_token=123456"

# 4. Test MFA token timing
# Generate TOTP token and wait for it to expire
# Then try to use expired token
```

### 4.5 Password Recovery Testing

```bash
# Test password recovery enumeration
curl -X POST https://target.com/forgot-password \
  -d "email=existing@example.com"  # Should succeed

curl -X POST https://target.com/forgot-password \
  -d "email=nonexistent@example.com"  # Should not reveal if user exists

# Test reset token security
# 1. Request password reset
curl -X POST https://target.com/forgot-password \
  -d "email=user@example.com"

# 2. Check if reset token is predictable or in URL
# Look for patterns in reset tokens like:
# - Sequential numbers
# - Timestamps
# - Weak randomization

# 3. Test reset token expiration
# Try using old reset tokens

# 4. Test reset token reuse
# Use the same reset token multiple times
```

## 5. Remediation to Prevent and Fix

### 5.1 Secure Password Implementation

```python
# Example: Secure password handling with bcrypt
import bcrypt
import re
from datetime import datetime, timedelta

class SecurePasswordManager:
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
        self.complexity_patterns = [
            r'[a-z]',  # lowercase
            r'[A-Z]',  # uppercase
            r'\d',     # digits
            r'[!@#$%^&*(),.?\":{}|<>]'  # special chars
        ]
        self.common_passwords = self._load_common_passwords()

    def validate_password(self, password, username=None):
        """Comprehensive password validation"""
        errors = []

        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")

        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")

        # Complexity check
        patterns_met = 0
        for pattern in self.complexity_patterns:
            if re.search(pattern, password):
                patterns_met += 1

        if patterns_met < 3:
            errors.append("Password must contain at least 3 of: lowercase, uppercase, digits, special characters")

        # Common password check
        if password.lower() in self.common_passwords:
            errors.append("Password is too common")

        # Username similarity check
        if username and username.lower() in password.lower():
            errors.append("Password must not contain username")

        return len(errors) == 0, errors

    def hash_password(self, password):
        """Securely hash password with salt"""
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=12)  # Adjust rounds based on performance requirements
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password, hashed_password):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def _load_common_passwords(self):
        """Load common passwords list"""
        # Load from file or database
        return ['password', '123456', 'password123', 'admin', 'qwerty']
```

### 5.2 Multi-Factor Authentication Implementation

```python
# Example: TOTP-based MFA implementation
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta

class MFAManager:
    def __init__(self):
        self.issuer_name = "MySecureApp"
        self.token_validity_period = 30  # seconds
        self.backup_codes_count = 10

    def setup_totp(self, user_email):
        """Setup TOTP for user"""
        # Generate secret key
        secret = pyotp.random_base32()

        # Create TOTP object
        totp = pyotp.TOTP(secret)

        # Generate provisioning URI
        provisioning_uri = totp.provisioning_uri(
            user_email,
            issuer_name=self.issuer_name
        )

        # Generate QR code
        qr_code = self._generate_qr_code(provisioning_uri)

        # Generate backup codes
        backup_codes = self._generate_backup_codes()

        return {
            'secret': secret,
            'qr_code': qr_code,
            'backup_codes': backup_codes
        }

    def verify_totp(self, secret, token, user_id):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)

        # Verify current token
        if totp.verify(token, valid_window=1):  # Allow 1 time step variance
            # Check if token was already used (prevent replay)
            if not self._is_token_used(user_id, token):
                self._mark_token_used(user_id, token)
                return True

        return False

    def verify_backup_code(self, user_id, backup_code):
        """Verify and consume backup code"""
        user_backup_codes = self._get_user_backup_codes(user_id)

        if backup_code in user_backup_codes:
            # Remove used backup code
            self._remove_backup_code(user_id, backup_code)
            return True

        return False

    def _generate_qr_code(self, provisioning_uri):
        """Generate QR code for TOTP setup"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    def _generate_backup_codes(self):
        """Generate backup codes"""
        import secrets
        import string

        codes = []
        for _ in range(self.backup_codes_count):
            code = ''.join(secrets.choice(string.digits) for _ in range(8))
            codes.append(f"{code[:4]}-{code[4:]}")

        return codes
```

### 5.3 Secure Session Management

```python
# Example: Secure session management
import secrets
import hashlib
import time
from datetime import datetime, timedelta

class SecureSessionManager:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.session_timeout = 30 * 60  # 30 minutes
        self.absolute_timeout = 8 * 60 * 60  # 8 hours
        self.session_key_length = 32

    def create_session(self, user_id, ip_address, user_agent):
        """Create secure session"""
        # Generate cryptographically secure session ID
        session_id = secrets.token_urlsafe(self.session_key_length)

        # Create session data
        session_data = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip_address,
            'user_agent': hashlib.sha256(user_agent.encode()).hexdigest()[:16],
            'is_mfa_verified': False,
            'privilege_level': 'user'
        }

        # Store in Redis with expiration
        self.redis.setex(
            f"session:{session_id}",
            self.session_timeout,
            json.dumps(session_data)
        )

        # Track active sessions for user
        self._track_user_session(user_id, session_id)

        return session_id

    def validate_session(self, session_id, ip_address, user_agent):
        """Validate and refresh session"""
        session_key = f"session:{session_id}"
        session_data_str = self.redis.get(session_key)

        if not session_data_str:
            return None, "Session expired or invalid"

        session_data = json.loads(session_data_str)

        # Check absolute timeout
        if time.time() - session_data['created_at'] > self.absolute_timeout:
            self.destroy_session(session_id)
            return None, "Session exceeded maximum lifetime"

        # Check IP address (optional, can be disabled for mobile users)
        if session_data['ip_address'] != ip_address:
            self.destroy_session(session_id)
            return None, "IP address mismatch"

        # Check user agent fingerprint
        current_ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        if session_data['user_agent'] != current_ua_hash:
            self.destroy_session(session_id)
            return None, "User agent mismatch"

        # Update last activity
        session_data['last_activity'] = time.time()

        # Refresh session in Redis
        self.redis.setex(
            session_key,
            self.session_timeout,
            json.dumps(session_data)
        )

        return session_data, None

    def destroy_session(self, session_id):
        """Destroy session"""
        session_key = f"session:{session_id}"
        session_data_str = self.redis.get(session_key)

        if session_data_str:
            session_data = json.loads(session_data_str)
            # Remove from user's active sessions
            self._untrack_user_session(session_data['user_id'], session_id)

        self.redis.delete(session_key)

    def destroy_all_user_sessions(self, user_id):
        """Destroy all sessions for a user"""
        user_sessions = self._get_user_sessions(user_id)
        for session_id in user_sessions:
            self.destroy_session(session_id)
```

### 5.4 Rate Limiting and Account Lockout

```python
# Example: Rate limiting implementation
import time
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.max_attempts = 5
        self.lockout_duration = 15 * 60  # 15 minutes
        self.rate_limit_window = 60  # 1 minute
        self.progressive_delays = [1, 2, 5, 10, 15]  # seconds

    def check_rate_limit(self, identifier, action='login'):
        """Check if action is rate limited"""
        key = f"rate_limit:{action}:{identifier}"

        # Get current attempt count
        attempts = self.redis.get(key)
        if attempts is None:
            return True, 0

        attempts = int(attempts)

        # Check if account is locked
        if attempts >= self.max_attempts:
            lockout_key = f"lockout:{action}:{identifier}"
            if self.redis.exists(lockout_key):
                return False, attempts

        return True, attempts

    def record_attempt(self, identifier, action='login', success=False):
        """Record login attempt"""
        key = f"rate_limit:{action}:{identifier}"

        if success:
            # Clear attempts on successful login
            self.redis.delete(key)
            return

        # Increment failed attempts
        attempts = self.redis.incr(key)

        if attempts == 1:
            # Set expiration on first attempt
            self.redis.expire(key, self.rate_limit_window)

        # Apply progressive delay
        if attempts <= len(self.progressive_delays):
            delay = self.progressive_delays[attempts - 1]
            time.sleep(delay)

        # Lock account after max attempts
        if attempts >= self.max_attempts:
            lockout_key = f"lockout:{action}:{identifier}"
            self.redis.setex(lockout_key, self.lockout_duration, "locked")

    def is_locked(self, identifier, action='login'):
        """Check if account/IP is locked"""
        lockout_key = f"lockout:{action}:{identifier}"
        return self.redis.exists(lockout_key)

    def unlock_account(self, identifier, action='login'):
        """Manually unlock account"""
        key = f"rate_limit:{action}:{identifier}"
        lockout_key = f"lockout:{action}:{identifier}"

        self.redis.delete(key)
        self.redis.delete(lockout_key)
```

### 5.5 Secure Password Recovery

```python
# Example: Secure password recovery implementation
import secrets
import hashlib
from datetime import datetime, timedelta

class PasswordRecoveryManager:
    def __init__(self, email_service, db_connection):
        self.email_service = email_service
        self.db = db_connection
        self.token_expiry = 15 * 60  # 15 minutes
        self.max_attempts = 3

    def initiate_recovery(self, email, ip_address):
        """Initiate password recovery process"""
        # Rate limit recovery requests
        if self._is_recovery_rate_limited(email, ip_address):
            return False, "Too many recovery requests. Please try again later."

        # Always return success to prevent email enumeration
        response_message = "If the email address exists, a recovery link has been sent."

        # Check if user exists (internal check only)
        user = self._get_user_by_email(email)
        if not user:
            # Log the attempt but don't reveal user doesn't exist
            self._log_recovery_attempt(email, ip_address, success=False, reason="user_not_found")
            return True, response_message

        # Generate secure recovery token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Store recovery token in database
        expiry_time = datetime.utcnow() + timedelta(seconds=self.token_expiry)
        self._store_recovery_token(user['id'], token_hash, expiry_time, ip_address)

        # Send recovery email
        recovery_url = f"https://example.com/reset-password?token={token}"
        self.email_service.send_recovery_email(email, recovery_url)

        # Log successful recovery initiation
        self._log_recovery_attempt(email, ip_address, success=True)

        return True, response_message

    def validate_recovery_token(self, token):
        """Validate recovery token"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Get token from database
        token_data = self._get_recovery_token(token_hash)

        if not token_data:
            return False, "Invalid or expired recovery token"

        # Check expiration
        if datetime.utcnow() > token_data['expiry_time']:
            self._delete_recovery_token(token_hash)
            return False, "Recovery token has expired"

        # Check if token was already used
        if token_data['used']:
            return False, "Recovery token has already been used"

        return True, token_data['user_id']

    def reset_password(self, token, new_password, ip_address):
        """Reset password using recovery token"""
        # Validate token
        valid, result = self.validate_recovery_token(token)
        if not valid:
            return False, result

        user_id = result
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Validate new password
        password_manager = SecurePasswordManager()
        valid_password, errors = password_manager.validate_password(new_password)
        if not valid_password:
            return False, "; ".join(errors)

        # Hash new password
        password_hash = password_manager.hash_password(new_password)

        # Update password in database
        self._update_user_password(user_id, password_hash)

        # Mark token as used
        self._mark_token_used(token_hash)

        # Invalidate all existing sessions for the user
        self._invalidate_user_sessions(user_id)

        # Log password reset
        self._log_password_reset(user_id, ip_address)

        return True, "Password has been reset successfully"

    def _is_recovery_rate_limited(self, email, ip_address):
        """Check if recovery requests are rate limited"""
        email_key = f"recovery_rate_limit:email:{email}"
        ip_key = f"recovery_rate_limit:ip:{ip_address}"

        # Check email-based rate limit
        email_attempts = self.redis.get(email_key) or 0
        if int(email_attempts) >= self.max_attempts:
            return True

        # Check IP-based rate limit
        ip_attempts = self.redis.get(ip_key) or 0
        if int(ip_attempts) >= self.max_attempts * 3:  # Higher limit for IP
            return True

        # Increment counters
        self.redis.incr(email_key)
        self.redis.expire(email_key, 3600)  # 1 hour
        self.redis.incr(ip_key)
        self.redis.expire(ip_key, 3600)  # 1 hour

        return False
```

## 6. Prevention Best Practices

### 6.1 Authentication Security Principles

- **Multi-Factor Authentication**: Require MFA for all accounts, especially privileged ones
- **Strong Password Policies**: Enforce length, complexity, and uniqueness requirements
- **Rate Limiting**: Implement progressive delays and account lockouts
- **Session Security**: Secure token generation, storage, and validation
- **Principle of Least Privilege**: Grant minimum necessary access
- **Defense in Depth**: Multiple layers of authentication controls

### 6.2 Implementation Guidelines

- Use proven authentication libraries and frameworks
- Implement proper error handling without information disclosure
- Use secure password storage (bcrypt, scrypt, or Argon2)
- Implement proper session lifecycle management
- Log all authentication events for monitoring
- Regular security testing and penetration testing

### 6.3 Password Security Standards

```python
# Example: Password policy configuration
PASSWORD_POLICY = {
    'minimum_length': 12,
    'maximum_length': 128,
    'require_lowercase': True,
    'require_uppercase': True,
    'require_digits': True,
    'require_special_chars': True,
    'min_character_classes': 3,
    'prevent_username_in_password': True,
    'prevent_common_passwords': True,
    'prevent_password_reuse': 12,  # Last 12 passwords
    'password_expiry_days': 90,
    'password_history_count': 12
}

# MFA Requirements
MFA_POLICY = {
    'required_for_admin': True,
    'required_for_all_users': True,
    'allowed_methods': ['totp', 'sms', 'email', 'hardware_token'],
    'backup_codes_count': 10,
    'token_validity_window': 30  # seconds
}
```

## 7. Testing Tools and Techniques

### 7.1 Authentication Testing Tools

```bash
# Hydra for brute force testing
hydra -L users.txt -P passwords.txt https-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Medusa for credential testing
medusa -H hosts.txt -U users.txt -P passwords.txt -M http -m DIR:/login

# Burp Suite Intruder for custom attacks
# Configure payload positions and attack types

# OWASP ZAP authentication testing
# Configure authentication contexts and forced user modes

# Custom Python scripts for specific testing
python auth_tester.py --target https://example.com --userlist users.txt --passlist passwords.txt
```

### 7.2 Session Management Testing

```python
# Session security testing script
import requests
import time

def test_session_security(base_url, valid_credentials):
    session = requests.Session()

    # Test 1: Session fixation
    print("Testing session fixation...")
    pre_login_cookies = session.cookies.get_dict()

    # Login
    login_response = session.post(f"{base_url}/login", data=valid_credentials)
    post_login_cookies = session.cookies.get_dict()

    if pre_login_cookies == post_login_cookies:
        print("⚠️ Session fixation vulnerability detected")

    # Test 2: Session timeout
    print("Testing session timeout...")
    dashboard_response = session.get(f"{base_url}/dashboard")

    # Wait for expected timeout
    time.sleep(1800)  # 30 minutes

    timeout_response = session.get(f"{base_url}/dashboard")
    if timeout_response.status_code == 200:
        print("⚠️ Session does not timeout properly")

    # Test 3: Concurrent sessions
    print("Testing concurrent sessions...")
    session2 = requests.Session()
    login2_response = session2.post(f"{base_url}/login", data=valid_credentials)

    # Check if first session is still valid
    concurrent_response = session.get(f"{base_url}/dashboard")
    if concurrent_response.status_code == 200:
        print("ℹ️ Multiple concurrent sessions allowed")

    # Test 4: Session token predictability
    print("Testing session token randomness...")
    tokens = []
    for i in range(5):
        temp_session = requests.Session()
        temp_session.post(f"{base_url}/login", data=valid_credentials)
        token = temp_session.cookies.get('sessionid')
        if token:
            tokens.append(token)

    # Basic entropy check
    unique_chars = set(''.join(tokens))
    if len(unique_chars) < 20:  # Basic check
        print("⚠️ Session tokens may have low entropy")
```

### 7.3 Manual Testing Checklist

- [ ] Test weak password acceptance
- [ ] Test brute force protection
- [ ] Test account lockout mechanisms
- [ ] Test password recovery process
- [ ] Test session management security
- [ ] Test multi-factor authentication
- [ ] Test credential enumeration vulnerabilities
- [ ] Test authentication bypass attempts
- [ ] Test privilege escalation
- [ ] Test logout functionality

## 8. Monitoring and Detection

### 8.1 Authentication Event Monitoring

```python
# Example: Authentication event monitoring
import json
import time
from datetime import datetime
from collections import defaultdict

class AuthenticationMonitor:
    def __init__(self, alert_service):
        self.alert_service = alert_service
        self.failed_attempts = defaultdict(list)
        self.suspicious_patterns = {
            'brute_force_threshold': 10,
            'credential_stuffing_threshold': 50,
            'time_window': 300  # 5 minutes
        }

    def log_authentication_event(self, event):
        """Log and analyze authentication event"""
        # Store event
        self._store_event(event)

        # Analyze for suspicious patterns
        if not event['success']:
            self._analyze_failed_login(event)
        else:
            self._analyze_successful_login(event)

        # Generate alerts if needed
        self._check_alert_conditions(event)

    def _analyze_failed_login(self, event):
        """Analyze failed login attempts"""
        key = f"{event['ip_address']}:{event['username']}"
        current_time = time.time()

        # Add to failed attempts
        self.failed_attempts[key].append(current_time)

        # Remove old attempts outside time window
        window_start = current_time - self.suspicious_patterns['time_window']
        self.failed_attempts[key] = [
            t for t in self.failed_attempts[key] if t > window_start
        ]

        # Check for brute force
        if len(self.failed_attempts[key]) >= self.suspicious_patterns['brute_force_threshold']:
            self._alert_brute_force(event, len(self.failed_attempts[key]))

    def _analyze_successful_login(self, event):
        """Analyze successful login for anomalies"""
        user_id = event['user_id']

        # Check for unusual login times
        if self._is_unusual_time(event['timestamp']):
            self._alert_unusual_time_login(event)

        # Check for new location
        if self._is_new_location(user_id, event['ip_address']):
            self._alert_new_location_login(event)

        # Check for multiple concurrent sessions
        if self._has_multiple_sessions(user_id):
            self._alert_concurrent_sessions(event)

    def _alert_brute_force(self, event, attempt_count):
        """Alert on brute force attempt"""
        alert = {
            'type': 'brute_force_attack',
            'severity': 'high',
            'ip_address': event['ip_address'],
            'username': event['username'],
            'attempt_count': attempt_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.alert_service.send_alert(alert)

    def _alert_unusual_time_login(self, event):
        """Alert on unusual time login"""
        alert = {
            'type': 'unusual_time_login',
            'severity': 'medium',
            'user_id': event['user_id'],
            'ip_address': event['ip_address'],
            'timestamp': event['timestamp']
        }
        self.alert_service.send_alert(alert)
```

### 8.2 Security Metrics and KPIs

- **Failed Login Rate**: Percentage of failed authentication attempts
- **Account Lockout Rate**: Frequency of account lockouts
- **MFA Adoption Rate**: Percentage of users with MFA enabled
- **Password Reset Frequency**: Rate of password reset requests
- **Session Duration**: Average and maximum session durations
- **Concurrent Session Count**: Number of simultaneous user sessions
- **Authentication Response Time**: Performance metrics for auth operations

## 9. Compliance and Standards

### 9.1 Regulatory Requirements

- **PCI DSS**: Requirement 8 - Identify and authenticate access to system components
- **HIPAA**: Administrative safeguards for unique user identification
- **SOX**: Access controls and authentication for financial systems
- **GDPR**: Technical and organizational measures for access control
- **NIST SP 800-63**: Digital identity guidelines for authentication

### 9.2 Industry Standards

- **OWASP ASVS**: Authentication verification requirements
- **ISO 27001**: Access control management standards
- **FIDO Alliance**: Standards for strong authentication
- **NIST Cybersecurity Framework**: Identity and access management

## 10. References and Further Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST SP 800-63B: Authentication and Lifecycle Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [RFC 6238: TOTP Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [FIDO2 WebAuthn Standard](https://webauthn.guide/)
