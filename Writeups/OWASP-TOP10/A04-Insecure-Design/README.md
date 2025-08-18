# A04:2021 - Insecure Design

## 1. What is the Vulnerability?

Insecure Design represents a broad category of weaknesses described as "missing or ineffective control design." It focuses on risks related to design and architectural flaws that cannot be fixed by perfect implementation, as they represent fundamental flaws in the design itself.

**Key Characteristics:**

- Missing security controls in the design phase
- Business logic flaws that allow abuse of legitimate functionality
- Insufficient threat modeling during design
- Lack of security requirements gathering
- Poor architectural decisions that introduce security risks
- Missing defense-in-depth strategies

**Difference from Implementation Issues:**

- Insecure Design: "We didn't design proper access controls"
- Implementation Issue: "We designed proper access controls but implemented them wrong"

## 2. Root Cause Analysis

**Primary Causes:**

- **Missing Threat Modeling**: Not identifying threats during design phase
- **Insufficient Security Requirements**: Security not considered in requirements gathering
- **Business Logic Flaws**: Legitimate functionality can be abused
- **Missing Security Controls**: No design for essential security controls
- **Poor Architecture Decisions**: Architectural choices that inherently introduce risks
- **Inadequate Risk Assessment**: Not understanding the risk landscape
- **Lack of Security Expertise**: Design teams without security knowledge

**Technical Root Causes:**

- Over-reliance on implementation security rather than design security
- Assuming "secure by default" without proper design
- Not considering edge cases and abuse scenarios
- Insufficient consideration of the complete attack surface
- Missing security patterns and anti-patterns knowledge

## 3. Real World Cases

### Case Study 1: Business Logic Flaw in E-commerce

- **Impact**: Customers could purchase items for negative prices
- **Cause**: The system allowed negative quantity values, which when multiplied by price resulted in credits
- **Root Cause**: Design didn't consider input validation for business logic
- **Lesson**: Business logic must be thoroughly analyzed for edge cases

### Case Study 2: Authentication Bypass in Mobile Banking

- **Impact**: Users could access other accounts by manipulating account numbers
- **Cause**: The system relied only on session validation but didn't verify account ownership
- **Root Cause**: Missing authorization design for account-specific operations
- **Lesson**: Authentication and authorization must be designed separately and thoroughly

### Case Study 3: Race Condition in Financial Transfer

- **Impact**: Users could transfer more money than they had by making simultaneous requests
- **Cause**: No proper locking mechanism designed for concurrent operations
- **Root Cause**: Concurrency not considered during the design phase
- **Lesson**: Concurrent operations must be part of the security design

## 4. Manual Testing Methodology

### 4.1 Business Logic Testing

```bash
# Test for business logic flaws
# Example: E-commerce price manipulation
POST /cart/add
{
  "product_id": 123,
  "quantity": -1,
  "price": 100
}
# Total should be -100, potentially giving credit

# Test workflow bypass
# Step 1: Start checkout process
GET /checkout/step1
# Step 3: Skip to step 3 directly
POST /checkout/step3
# Check if validation steps were bypassed
```

### 4.2 Privilege Escalation Testing

```bash
# Test for design flaws in role management
# Create low-privilege user
POST /register
{
  "username": "testuser",
  "role": "admin"  # Try to set admin role during registration
}

# Test role modification
PUT /user/profile
{
  "user_id": 123,
  "role": "admin"  # Try to modify own role
}
```

### 4.3 Race Condition Testing

```python
# Test for concurrent operation flaws
import threading
import requests

def transfer_money():
    response = requests.post('/api/transfer', json={
        'from_account': '12345',
        'to_account': '67890',
        'amount': 1000
    })
    return response

# Execute multiple transfers simultaneously
threads = []
for i in range(10):
    thread = threading.Thread(target=transfer_money)
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()
```

### 4.4 Workflow and State Testing

```bash
# Test for workflow bypass
# Normal flow: register -> verify email -> access features
# Test: register -> access features (bypass email verification)

# Test state manipulation
# Example: Order processing
POST /order/create  # Creates order in "pending" state
PUT /order/123/status
{
  "status": "completed"  # Try to directly change to completed
}
```

### 4.5 Resource Limits Testing

```bash
# Test for missing resource limits
# Upload large file
curl -X POST -F "file=@large_file.zip" http://target.com/upload

# Create excessive resources
for i in {1..1000}; do
  curl -X POST -d "name=account$i" http://target.com/create-account
done
```

## 5. Remediation to Prevent and Fix

### 5.1 Implement Secure Design Principles
```python
# Example: Secure business logic design
class TransferService:
    def __init__(self, account_service, audit_service):
        self.account_service = account_service
        self.audit_service = audit_service
        self.transfer_lock = threading.Lock()
    
    def transfer_money(self, from_account, to_account, amount, user_id):
        # Design principle: Fail securely
        if amount <= 0:
            raise ValueError("Transfer amount must be positive")
        
        # Design principle: Complete mediation
        if not self.account_service.user_owns_account(user_id, from_account):
            raise PermissionError("User doesn't own source account")
        
        # Design principle: Atomicity and consistency
        with self.transfer_lock:
            from_balance = self.account_service.get_balance(from_account)
            if from_balance < amount:
                raise InsufficientFundsError("Insufficient balance")
            
            # Atomic transaction
            with database.transaction():
                self.account_service.debit(from_account, amount)
                self.account_service.credit(to_account, amount)
                self.audit_service.log_transfer(from_account, to_account, amount, user_id)
```

### 5.2 Design Security Controls
```java
// Example: Proper authorization design
@Component
public class SecurityService {
    
    // Design: Centralized authorization
    public boolean canPerformAction(User user, Resource resource, Action action) {
        // Check user permissions
        Set<Permission> userPermissions = getUserPermissions(user);
        
        // Check resource-specific permissions
        Permission requiredPermission = getRequiredPermission(resource, action);
        
        // Apply business rules
        if (action == Action.DELETE && resource.getOwner().equals(user)) {
            return true; // Owner can always delete
        }
        
        return userPermissions.contains(requiredPermission);
    }
    
    // Design: Rate limiting
    @RateLimited(requests = 10, window = "1m")
    public void performSensitiveAction(User user, Action action) {
        if (!canPerformAction(user, action.getResource(), action)) {
            throw new UnauthorizedException("Access denied");
        }
        // Perform action
    }
}
```

### 5.3 Implement Defense in Depth
```python
# Example: Multi-layer security design
class SecureController:
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.validator = InputValidator()
        self.auth_service = AuthenticationService()
        self.authz_service = AuthorizationService()
        self.audit_service = AuditService()
    
    def handle_request(self, request):
        try:
            # Layer 1: Rate limiting
            if not self.rate_limiter.allow_request(request.client_ip):
                raise RateLimitExceeded("Too many requests")
            
            # Layer 2: Input validation
            validated_input = self.validator.validate(request.data)
            
            # Layer 3: Authentication
            user = self.auth_service.authenticate(request.token)
            
            # Layer 4: Authorization
            if not self.authz_service.is_authorized(user, request.action, request.resource):
                raise UnauthorizedException("Access denied")
            
            # Layer 5: Business logic
            result = self.execute_business_logic(validated_input, user)
            
            # Layer 6: Audit logging
            self.audit_service.log_action(user, request.action, request.resource, "SUCCESS")
            
            return result
            
        except Exception as e:
            self.audit_service.log_action(user, request.action, request.resource, f"FAILURE: {str(e)}")
            raise
```

### 5.4 Secure Workflow Design
```javascript
// Example: Secure state machine design
class OrderStateMachine {
    constructor() {
        this.validTransitions = {
            'draft': ['submitted'],
            'submitted': ['approved', 'rejected'],
            'approved': ['shipped'],
            'shipped': ['delivered'],
            'delivered': [],
            'rejected': ['draft']
        };
    }
    
    transitionState(order, newState, user) {
        // Validate state transition
        if (!this.validTransitions[order.status].includes(newState)) {
            throw new Error(`Invalid state transition from ${order.status} to ${newState}`);
        }
        
        // Check authorization for state change
        if (!this.canChangeState(user, order, newState)) {
            throw new Error("Unauthorized state change");
        }
        
        // Apply business rules
        this.applyBusinessRules(order, newState);
        
        // Update state atomically
        return this.updateOrderState(order.id, newState, user.id);
    }
    
    canChangeState(user, order, newState) {
        const rules = {
            'approved': user => user.role === 'admin' || user.role === 'approver',
            'shipped': user => user.role === 'admin' || user.role === 'shipper',
            'delivered': user => user.role === 'admin' || user.role === 'delivery'
        };
        
        return rules[newState] ? rules[newState](user) : false;
    }
}
```

## 6. Prevention Best Practices

### 6.1 Secure Design Process
- **Security by Design**: Integrate security from the earliest design phase
- **Threat Modeling**: Systematic identification of threats and mitigations
- **Security Requirements**: Define explicit security requirements
- **Architecture Reviews**: Regular security architecture assessments
- **Secure Design Patterns**: Use proven secure design patterns
- **Risk Assessment**: Understand and document security risks

### 6.2 Design Principles
- **Fail Securely**: Default to denial of access
- **Complete Mediation**: Check every access
- **Least Privilege**: Grant minimum necessary permissions
- **Defense in Depth**: Multiple layers of security
- **Economy of Mechanism**: Keep security mechanisms simple
- **Psychological Acceptability**: Security should be easy to use correctly

### 6.3 Business Logic Security
- **Input Validation**: Validate all inputs according to business rules
- **State Management**: Proper state transitions and validation
- **Concurrency Control**: Handle concurrent operations safely
- **Resource Limits**: Implement appropriate limits and quotas
- **Audit and Logging**: Comprehensive logging for security events

## 7. Testing Tools and Techniques

### 7.1 Design Review Tools
- **Microsoft Threat Modeling Tool**: Structured threat modeling
- **OWASP Threat Dragon**: Open-source threat modeling
- **IriusRisk**: Automated threat modeling platform
- **Architecture Review Checklists**: Systematic review processes

### 7.2 Business Logic Testing Tools
- **Burp Suite**: Manual testing with custom logic
- **OWASP ZAP**: Automated and manual testing
- **Custom Scripts**: Tailored testing for specific business logic
- **Fuzzing Tools**: Input validation and edge case testing

### 7.3 Static Analysis for Design Issues
- **SonarQube**: Code quality and architectural analysis
- **NDepend**: Architecture and design analysis
- **Structure101**: Architectural complexity analysis

## 8. Secure Design Patterns

### 8.1 Authentication Patterns
```python
# Secure authentication design pattern
class SecureAuthenticator:
    def __init__(self):
        self.max_attempts = 3
        self.lockout_duration = 300  # 5 minutes
        self.failed_attempts = {}
    
    def authenticate(self, username, password):
        # Check if account is locked
        if self.is_locked(username):
            raise AccountLockedException("Account temporarily locked")
        
        # Validate credentials
        user = self.validate_credentials(username, password)
        
        if user:
            # Reset failed attempts on success
            self.failed_attempts.pop(username, None)
            return user
        else:
            # Track failed attempts
            self.record_failed_attempt(username)
            raise AuthenticationFailedException("Invalid credentials")
```

### 8.2 Authorization Patterns
```java
// Role-Based Access Control (RBAC) pattern
public class RBACAuthorizationService {
    
    public boolean hasPermission(User user, String resource, String action) {
        Set<Role> userRoles = user.getRoles();
        
        for (Role role : userRoles) {
            Set<Permission> rolePermissions = role.getPermissions();
            
            for (Permission permission : rolePermissions) {
                if (permission.getResource().equals(resource) && 
                    permission.getAction().equals(action)) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
```

### 8.3 Secure Communication Patterns
```python
# Secure API communication pattern
class SecureAPIClient:
    def __init__(self, api_key, secret_key):
        self.api_key = api_key
        self.secret_key = secret_key
    
    def make_request(self, endpoint, data):
        # Create request with security headers
        headers = {
            'X-API-Key': self.api_key,
            'X-Timestamp': str(int(time.time())),
            'Content-Type': 'application/json'
        }
        
        # Create signature for request integrity
        signature_data = f"{headers['X-Timestamp']}{json.dumps(data)}"
        headers['X-Signature'] = self.create_signature(signature_data)
        
        # Make HTTPS request with certificate validation
        response = requests.post(
            endpoint,
            json=data,
            headers=headers,
            verify=True,  # Verify SSL certificates
            timeout=30    # Reasonable timeout
        )
        
        return self.validate_response(response)
```

## 9. Compliance and Standards

### 9.1 Regulatory Requirements
- **PCI DSS**: Requirement 6.5 - Address common vulnerabilities in software development
- **ISO 27001**: A.14.2 - Security in development and support processes
- **NIST SP 800-64**: Security considerations in the system development life cycle
- **GDPR**: Privacy by design requirements

### 9.2 Design Standards
- **OWASP SAMM**: Software Assurance Maturity Model
- **BSIMM**: Building Security In Maturity Model
- **NIST SSDF**: Secure Software Development Framework
- **ISO/IEC 27034**: Application security guidelines
